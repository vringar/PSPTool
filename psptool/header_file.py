# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2021 Christian Werling, Robert Buhren, Hans Niklas Jacob
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import string
import struct
from binascii import hexlify
from hashlib import md5, sha256, sha384
from enum import Enum

from . import errors
from .utils import NestedBuffer, zlib_decompress, decrypt, shannon
from .file import File

class SignatureType(Enum):
    NONE = (None, 0x0)
    SHA256 = (0, 0x100)
    SHA384 = (2, 0x200)

    def __init__(self, type: int, len: int):
        self.type = type
        self.len = len

    @property
    def is_signed(self) -> bool:
        return self is not SignatureType.NONE

    @classmethod
    def from_header(cls, signed: NestedBuffer, type: int) -> "SignatureType":
        signed = int.from_bytes(signed.get_bytes(), 'little')
        if signed not in {0, 1, 0xffff0000}:
            raise File.ParseError(f'Did not expect signed to be 0x{signed:x}')
        if signed == 0:
            return SignatureType.NONE
        for st in cls:
            if st.type == type:
                return st
        return File.ParseError(f"Unknown signature type 0x{type:x}")

class Signature(NestedBuffer):
    def __init__(self, file: 'HeaderFile', type: SignatureType):
        self.type = type
        super().__init__(file, type.len, file.rom_size - type.len)

    @property
    def len(self) -> int:
        return self.type.len


class HeaderFile(File):

    HEADER_LEN = 0x100

    def _parse(self):
        if self.buffer_size < 0x100:  # give those with a entry size of 0 (!?) a chance to get their header parsed
            self.buffer_size = 0x100
        self.header = NestedBuffer(self, HeaderFile.HEADER_LEN)

        # Will be set by the CertificateTree created after the blob
        self.signed_entity = None

        # Will be set by blob._find_inline_pubkeys
        self.inline_keys = set()

        # todo: use NestedBuffers instead of saving by value
        self.magic = self.header[0x10:0x14]
        self.size_signed = struct.unpack('<I', self.header[0x14:0x18])[0]
        self.encrypted = struct.unpack('<I', self.header[0x18:0x1c])[0] == 1
        self._sha256_checksum = NestedBuffer(self, 0x20, 0xd0)
        self._sha384_checksum = NestedBuffer(self, 0x30, 0xd0)
        # signed, signature_type = struct.unpack('<II', self.header[0x30:0x38])
        signed = NestedBuffer(self, 4, 0x30)
        signature_type = struct.unpack('<I', self.header[0x34:0x38])[0]
        self.signature_fingerprint = hexlify(self.header[0x38:0x48])
        self.compressed = struct.unpack('<I', self.header[0x48:0x4c])[0] == 1
        self.unknown_field_2 = struct.unpack('<I', self.header[0x4c:0x50])[0]
        self.size_uncompressed = struct.unpack('<I', self.header[0x50:0x54])[0]
        self.zlib_size = struct.unpack('<I', self.header[0x54:0x58])[0]
        self.bitfield = struct.unpack('>I', self.header[0x58:0x5c])[0]
        self.version = self.header[0x63:0x5f:-1]
        # Raw header field 0x68. NOTE: this is the entry/body offset relative to
        # the image's link base (0x100 for off-chip BLs, i.e. just past the
        # header), NOT the runtime SRAM address the on-chip BL copies the stage
        # to. Downstream must not treat load_addr as a load address; the real
        # base comes from the image's vector table or dynamic observation.
        self.load_addr = struct.unpack('<I', self.header[0x68:0x6c])[0]
        self.rom_size = struct.unpack('<I', self.header[0x6c:0x70])[0]
        self.unknown_field_3 = struct.unpack('<I', self.header[0x7c:0x80])[0]

        self.has_sha256_checksum = self.bitfield & 0b01
        self.has_sha384_checksum = self.bitfield & 0b10

        if self.has_sha256_checksum and self.has_sha384_checksum:
            raise File.ParseError('File should not have both sha256 and sha384 checksum bits set!')

        if self.buffer_offset + self.rom_size > self.parent_buffer.buffer_size:
            raise File.ParseError(f'Header size 0x{self.rom_size:x} overflows the parent buffer, '
                                  f'likely not a PSP header')

        if self.rom_size == 0:
            self.rom_size = self.buffer_size
        elif self.rom_size > self.buffer_size:
            self.buffer_size = self.rom_size

        # self.iv = hexlify(self.header[0x20:0x30])
        # self.wrapped_key = hexlify(self.header[0x80:0x90])

        # TODO: Take care of headers with only 0xfff...
        # TODO if zlib_size == 0 try size_signed

        self.signature = Signature(self, SignatureType.from_header(signed, signature_type))

        self._parse_hdr()

        return

    def _parse_hdr(self):
        # Get IV and wrapped KEY from file header
        if self.encrypted:
            self.iv = self.header[0x20:0x30]
            self.key = self.header[0x80:0x90]
            assert(self.iv != (b'\x00' * 16))
            assert(self.key != (b'\x00' * 16))

        assert 0 < self.rom_size <= self.buffer_size
        self.buffer_size = self.rom_size
        self.body = NestedBuffer(self, len(self) - len(self.header) - self.signature.len, len(self.header))
        self.is_legacy = False

    def get_checksummed_bytes(self):
        return self.get_decrypted_decompressed_body()

    def verify_sha256(self, print_warning=True) -> bool:
        if self._sha256_checksum.get_bytes() == sha256(self.get_checksummed_bytes()).digest():
            return True
        if print_warning:
            self.psptool.ph.print_warning(f"Could not verify sha256 checksum for {self}")
        return False

    def update_sha256(self):
        self._sha256_checksum[:] = sha256(self.get_checksummed_bytes()).digest()
        self.verify_sha256()

    def verify_sha384(self, print_warning=True) -> bool:
        if self._sha384_checksum.get_bytes() == sha384(self.get_checksummed_bytes()).digest():
            return True
        if print_warning:
            self.psptool.ph.print_warning(f"Could not verify sha384 checksum for {self}")
        return False

    @property
    def is_signed(self) -> bool:
        return self.signature.type.is_signed

    def get_readable_version(self):
        return '.'.join([hex(b)[2:].upper() for b in self.version])

    def get_ikek_md5sum(self) -> bytes:
        ikek = self.parent_buffer.get_files_by_type(0x21)[0]
        m = md5()
        m.update(ikek.get_bytes())
        return m.digest()

    def get_readable_magic(self):
        # if self.magic == b'\x01\x00\x00\x00':
            # actually twice as long, but SMURULESMURULES is kinda redundant
            # readable_magic= self[0x0:0x4]
        if self.magic == b'\x05\x00\x00\x00':
            readable_magic = b'0x05'
        else:
            readable_magic = self.magic

        try:
            # Try to encode the id as ascii
            readable_magic = str(readable_magic, encoding='ascii')
            # and remove unprintable chars
            readable_magic = ''.join(s for s in readable_magic if s in string.printable)
        except UnicodeDecodeError:
            return ''

        return readable_magic

    def get_readable_signed_by(self):
        return self.signed_entity.certifying_id.magic

    def get_signed_bytes(self) -> bytes:
        file_bytes = self.header.get_bytes() + self.get_decrypted_decompressed_body()
        return file_bytes[:len(self.header) + self.size_signed]

    def _decrypted_decompressed_body(self, print_warning=True) -> tuple:
        """Returns (body, decompress_ok). When the entry is flagged compressed but
        its declared zlib stream fails to decompress, the still-compressed (but
        decrypted) bytes are returned and decompress_ok is False, so callers can
        tell a genuine plaintext body from a silently-failed decode."""
        output = self.get_decrypted_body()

        if self.compressed:
            try:
                return zlib_decompress(output[:self.zlib_size]), True
            except Exception:
                if print_warning:
                    self.psptool.ph.print_warning(f"ZLIB decompression failed on file {self.get_readable_type()}")
                return output, False
        return output, True

    def get_decrypted_decompressed_body(self) -> bytes:
        return self._decrypted_decompressed_body()[0]

    def decode_verification(self, print_warning=False) -> tuple:
        """Returns (verified, basis) in a single pass - use this when you want
        both the bool and the basis (e.g. logging why a body was rejected)
        without verifying twice. See decode_verified() and
        decode_verification_method() for the individual accessors."""
        return self._verify_decode(print_warning=print_warning)

    def _verify_decode(self, print_warning=False) -> tuple:
        """Returns (verified, basis). See decode_verified()."""
        body, decompress_ok = self._decrypted_decompressed_body(print_warning=print_warning)
        if not decompress_ok:
            return False, 'decompress-failed'
        if self.signed_entity is not None:
            try:
                verified = self.signed_entity.is_verified()
            except errors.NoCertifyingKey:
                # Expected: the cert tree has no pubkey for this entry's certifying
                # id, so the body can't be confirmed. Distinct from a real fault.
                return False, 'signature-unresolved'
            except Exception:
                # An unexpected failure in verification - surface it rather than
                # silently folding it into the "no key" bucket, where a crypto-lib
                # regression would hide.
                if print_warning:
                    self.psptool.ph.print_warning(
                        f"Unexpected error verifying signature of {self.get_readable_type()}")
                return False, 'signature-error'
            if not verified:
                return False, 'signature-failed'
            # A valid signature only covers header + body[:size_signed] (see
            # get_signed_bytes). It authenticates the WHOLE decoded body only if
            # size_signed spans it, or if the header - which is always inside the
            # signed region - carries a checksum that matches the body. Otherwise
            # the tail past size_signed is unsigned and must not be called plain.
            if self.size_signed >= len(body):
                return True, 'signature'
            if self.has_sha256_checksum and self.verify_sha256(print_warning=print_warning):
                return True, 'signature+sha256'
            if self.has_sha384_checksum and self.verify_sha384(print_warning=print_warning):
                return True, 'signature+sha384'
            return False, 'signature-partial'
        # Unsigned: a stored content checksum over the decoded body is the
        # next-best integrity proof.
        if self.has_sha256_checksum:
            return (True, 'sha256') if self.verify_sha256(print_warning=print_warning) else (False, 'sha256-failed')
        if self.has_sha384_checksum:
            return (True, 'sha384') if self.verify_sha384(print_warning=print_warning) else (False, 'sha384-failed')
        # No integrity data: trustworthy only if nothing was transformed AND the
        # entry does not even claim to be signed (a signed file whose signed_entity
        # the cert tree has not attached must not pass as plaintext).
        if not self.encrypted and not self.compressed and not self.is_signed:
            return True, 'plain'
        return False, 'unverifiable'

    def decode_verified(self, print_warning=False) -> bool:
        """Whether get_decrypted_decompressed_body() can be positively confirmed
        to return the authentic plaintext body.

        This is the signal downstream tooling should key on before trusting a
        decoded body (e.g. as a sha256_plain identity). It is True only when the
        FULL body is cryptographically or structurally confirmed (a signature
        spanning the whole body, a signature plus a matching header checksum, a
        standalone stored checksum, or an untransformed and unsigned body), and
        False when it cannot be confirmed - a wrong or unknown IKEK, a failed
        decompression, an unresolved certifying key, a signature that covers only
        part of the body, or tampering."""
        return self._verify_decode(print_warning=print_warning)[0]

    def decode_verification_method(self) -> str:
        """The basis for decode_verified(): one of 'signature', 'signature+sha256',
        'signature+sha384', 'sha256', 'sha384' or 'plain' when verified;
        'signature-failed', 'signature-unresolved', 'signature-error',
        'signature-partial', 'sha256-failed', 'sha384-failed', 'decompress-failed'
        or 'unverifiable' when not."""
        return self._verify_decode()[1]

    def plaintext_identity_ok(self) -> bool:
        """Whether get_decrypted_decompressed_body() yields the true plaintext
        body, so its sha256 is a valid content identity (what downstream tools
        key sha256_plain on). This is WEAKER than decode_verified(): for an
        unencrypted entry the body is the plaintext verbatim regardless of
        signature provenance, so a failed/absent signature does not invalidate
        the identity. Only an unconfirmable decryption (wrong/unknown IKEK) or a
        failed decompression makes the bytes untrustworthy as plaintext."""
        verified, method = self.decode_verification()
        return (not self.encrypted or verified) and method != 'decompress-failed'

    def to_decrypted_file_bytes(self) -> bytes:
        """Returns the bytes of the same file, just with the encryption removed"""
        header = bytearray(self.header.get_bytes())
        header[0x18:0x1c] = bytes(4)
        header[0x20:0x30] = bytes(0x10)
        signature = self.signature.get_bytes() if self.is_signed else b''
        return bytes(header) + self.get_decrypted_body() + signature

    def get_decrypted_body(self) -> bytes:
        if not self.encrypted:
            return self.body.get_bytes()
        else:
            unwrapped_ikek = self.get_unwrapped_ikek()
            assert(unwrapped_ikek != None)
            return decrypt(self.body.get_bytes(), self.key, unwrapped_ikek, self.iv)

    def get_unwrapped_ikek(self) -> bytes:
        # The Zen+ IKEK decrypts every encrypted entry across the Zen1-Zen3 test
        # corpus (verified: the RSA signature, which covers the decrypted body,
        # validates under it and fails under the Zen IKEK). We therefore default
        # to it rather than trying to pick a key per entry.
        #
        # Picking the IKEK by the ROM's wrapped-IKEK (type 0x21) entry does not
        # work: a single BIOS ships several 0x21 entries (Zen and Zen+, plus
        # newer-gen ones whose unwrapped key we don't have), so the ROM alone
        # does not identify the key for a given entry. When this default is the
        # wrong key (a newer generation), the decoded body is garbage - but
        # decode_verified() returns False for it (the signature won't validate),
        # so callers can detect and reject it instead of trusting garbage.
        return self.UNWRAPPED_IKEK_ZEN_PLUS

    def shannon_entropy(self):
        return shannon(self.body[:])

    def md5(self):
        m = md5()
        try:
            m.update(self.body.get_bytes())
        except:
            self.psptool.ph.print_warning(f"Get bytes failed at file: 0x{self.get_address():x} type: {self.get_readable_type()} size: 0x{self.buffer_size:x}")
        return m.hexdigest()
