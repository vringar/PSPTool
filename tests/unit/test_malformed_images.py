"""Malformed or hostile images must not abort parsing: the bad part is skipped (with a warning) and every valid
sibling is still returned. Images are synthesised in memory."""
import contextlib
import io
import struct
import unittest
import zlib
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from psptool import PSPTool
from psptool.header_file import HeaderFile
from psptool.utils import NestedBuffer, fletcher32

MB = 1024 * 1024
FET, DIR, GOOD, BAD = 0x20000, 0x30000, 0x40000, 0x50000
X86 = 0xFF000000


def blank(size=16 * MB):
    return bytearray(b'\xff' * size)


def put_fet(img, offset, pointers):
    img[offset:offset + 4] = b'\xAA\x55\xAA\x55'
    for i, pointer in enumerate(pointers):
        img[offset + 4 + 4 * i:offset + 8 + 4 * i] = struct.pack('<I', pointer)
    end = offset + 4 + 4 * len(pointers)
    img[end:end + 16] = b'\xff' * 16


def entry(type_, size, offset):
    return struct.pack('<BBHIII', type_, 0, 0, size, offset, 0)


def put_dir(img, offset, entries, magic=b'$PSP', info=0):
    body = b''.join(entries)
    img[offset:offset + 16] = magic + b'\0' * 4 + struct.pack('<II', len(entries), info)
    img[offset + 16:offset + 16 + len(body)] = body
    img[offset + 4:offset + 8] = fletcher32(bytes(img[offset + 8:offset + 16 + len(body)]))


def put_combo(img, offset, targets, psp_id=0xbc0c0100):
    img[offset:offset + 0x20 + 16 * len(targets)] = b'\0' * (0x20 + 16 * len(targets))
    img[offset:offset + 4] = b'2PSP'
    img[offset + 8:offset + 12] = struct.pack('<I', len(targets))
    for i, target in enumerate(targets):
        img[offset + 0x20 + 16 * i:offset + 0x30 + 16 * i] = struct.pack('<IIII', 0, psp_id, target, 0)


def header(size_signed=0, encrypted=0, iv=b'\0' * 16, key=b'\0' * 16, signed=0, sig_type=0, key_id=b'\x11' * 16,
           compressed=0, zlib_size=0, rom_size=0, magic=b'$TST'):
    h = bytearray(0x100)
    h[0x10:0x14] = magic
    h[0x14:0x1c] = struct.pack('<II', size_signed, encrypted)
    h[0x20:0x30] = iv
    h[0x30:0x38] = struct.pack('<II', signed, sig_type)
    h[0x38:0x48] = key_id
    h[0x48:0x4c] = struct.pack('<I', compressed)
    h[0x54:0x58] = struct.pack('<I', zlib_size)
    h[0x6c:0x70] = struct.pack('<I', rom_size)
    h[0x80:0x90] = key
    return h


def pubkey(key_id, modulus=0, bits=2048, version=1):
    pk = bytearray(0x40 + 2 * bits // 8)
    pk[0:4] = struct.pack('<I', version)
    pk[4:0x14] = pk[0x14:0x24] = key_id
    pk[0x38:0x40] = struct.pack('<II', bits, bits)
    pk[0x40:0x40 + bits // 8] = (65537).to_bytes(bits // 8, 'little')
    pk[0x40 + bits // 8:] = modulus.to_bytes(bits // 8, 'little')
    return pk


def key_store(key_bits):
    key = bytearray(0x50 + key_bits // 8)
    key[0:0x10] = struct.pack('<IIII', len(key), 1, 0, 0x10001)
    key[0x10:0x20] = b'\x22' * 16
    key[0x20:0x24] = struct.pack('<I', key_bits)
    store = bytearray(0x50) + key
    store[0:0xc] = struct.pack('<II', len(store), 1) + b'$KDB'
    h = header(signed=1, sig_type=2, size_signed=len(store), rom_size=0x100 + len(store) + 0x200, magic=b'$PS1')
    h[0x7c:0x80] = struct.pack('<I', 0x50)
    return h + store + b'\0' * 0x200


def image(*extra_entries, size=16 * MB, pointers=(X86 + DIR,)):
    """An image with one valid file (type 0x01 at GOOD) plus the given extra directory entries."""
    img = blank(size)
    put_fet(img, FET, pointers)
    img[GOOD:GOOD + 0x200] = header() + b'A' * 0x100
    put_dir(img, DIR, [entry(0x01, 0x200, X86 + GOOD)] + list(extra_entries))
    return img


def parse(img):
    with contextlib.redirect_stderr(io.StringIO()) as stderr:
        return PSPTool(img), stderr.getvalue()


def files(pt):
    return [file for rom in pt.blob.roms for directory in rom.directories for file in directory.files]


class TestMalformedImages(unittest.TestCase):

    def assertGoodSiblingParsed(self, pt):
        self.assertIn((0x01, GOOD), [(file.type, file.get_address()) for file in files(pt)])

    def assertSkipped(self, img, address=BAD):
        pt, stderr = parse(img)
        self.assertGoodSiblingParsed(pt)
        self.assertNotIn(address, [file.get_address() for file in files(pt)])
        self.assertIn('Warning', stderr)
        return pt

    def test_malformed_entry_is_skipped(self):
        mismatched_pubkey = pubkey(b'\x44' * 16)
        mismatched_pubkey[0x3c:0x40] = struct.pack('<I', 4096)
        cases = {
            'unknown signature type': (header(signed=1, sig_type=1, rom_size=0x300) + b'B' * 0x200, 0x02),
            'encrypted with zero IV': (header(encrypted=1) + b'B' * 0x100, 0x02),
            'encrypted body not AES aligned': (header(encrypted=1, iv=b'\1' * 16, key=b'\2' * 16, rom_size=0x208)
                                               + b'B' * 0x108, 0x02),
            'unknown pubkey version': (b'\x07' * 0x240, 0x00),
            'pubkey bit sizes differ': (mismatched_pubkey, 0x00),
            'key store with bad magic': (header(signed=1, sig_type=2, magic=b'XXXX') + b'\0' * 0x300, 0x50),
            'key store key of unsupported size': (key_store(1024), 0x50),
        }
        for name, (blob, type_) in cases.items():
            with self.subTest(name):
                img = image(entry(type_, len(blob), X86 + BAD))
                img[BAD:BAD + len(blob)] = blob
                self.assertSkipped(img)

        with self.subTest('flash offset past the end of the ROM'):
            img = blank()
            put_fet(img, FET, [X86 + DIR])
            img[GOOD:GOOD + 0x200] = header() + b'A' * 0x100
            put_dir(img, DIR, [entry(0x01, 0x200, GOOD), entry(0x02, 0x100, 0x1800000)], info=1 << 29)
            self.assertGoodSiblingParsed(parse(img)[0])

        with self.subTest('inline pubkey candidate'):
            img = image(entry(0x02, 0x300, X86 + BAD))
            img[BAD:BAD + 0x300] = header(signed=1, rom_size=0x300) + b'B' * 0x200
            # candidate version and size, read at the key ID's file-relative offset in the image
            img[0x34:0x38] = struct.pack('<I', 1)
            img[0x6c:0x70] = struct.pack('<I', 2048)
            self.assertGoodSiblingParsed(parse(img)[0])

    def test_header_file_exceeding_its_rom_is_skipped(self):
        for name, blob in {
            'rom_size past the ROM end': header(rom_size=0x2000000) + b'B' * 0x100,
            'signed, rom_size past the ROM end': header(signed=1, rom_size=0x2000000) + b'B' * 0x200,
        }.items():
            with self.subTest(name):
                img = image(entry(0x02, len(blob), X86 + BAD))
                img[BAD:BAD + len(blob)] = blob
                self.assertSkipped(img)
        with self.subTest('header grown past the ROM end'):
            self.assertSkipped(image(entry(0x02, 0x10, X86 + 16 * MB - 0x10)), address=16 * MB - 0x10)

    def test_negative_buffer_sizes_are_rejected(self):
        parent = NestedBuffer(bytearray(0x100), 0x100)
        for size, offset in ((-0x10, 0x80), (0x10, -0x10), (0x90, 0x80)):
            with self.subTest(size=size, offset=offset), self.assertRaises(AssertionError):
                NestedBuffer(parent, size, offset)
        with self.subTest('signed file whose body size would be negative'):
            img = image(entry(0x02, 0x200, X86 + BAD))
            img[BAD:BAD + 0x200] = header(signed=1, rom_size=0x180) + b'Y' * 0x100
            self.assertSkipped(img)

    def test_each_rom_of_a_multi_rom_image_is_parsed(self):
        img = blank(32 * MB)
        for base, fill in ((0, b'A'), (16 * MB, b'Z')):
            put_fet(img, base + FET, [X86 + DIR])
            img[base + GOOD:base + GOOD + 0x200] = header() + fill * 0x100
            put_dir(img, base + DIR, [entry(0x01, 0x200, X86 + GOOD)])
        pt, _ = parse(img)
        self.assertGoodSiblingParsed(pt)
        self.assertEqual(len(pt.blob.roms), 2)
        second = pt.blob.roms[1].directories[0]
        self.assertEqual(second.get_address(), 16 * MB + DIR)
        self.assertEqual(second.files[0].get_address(), 16 * MB + GOOD)
        self.assertEqual(second.files[0].get_decrypted_decompressed_body()[:1], b'Z')

    def test_decompression_is_capped_at_the_rom_size(self):
        bomb = zlib.compress(b'\0' * 20 * MB, 9)
        bomb += b'\0' * (-len(bomb) % 16)
        img = image(entry(0x02, 0x100 + len(bomb), X86 + BAD))
        img[BAD:BAD + 0x100 + len(bomb)] = header(compressed=1, zlib_size=len(bomb)) + bomb
        pt, _ = parse(img)
        self.assertGoodSiblingParsed(pt)
        bomb_file = next(file for file in files(pt) if file.get_address() == BAD)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(bomb_file.get_decrypted_decompressed_body(), bomb)
        self.assertEqual(bomb_file.decode_verification(), (False, 'decompress-failed'))

    def test_compressed_body_must_actually_decompress(self):
        plain = b'PLAINTEXT' * 100
        stream = zlib.compress(plain)
        stream += b'\0' * (-len(stream) % 16)
        for name, (body, zlib_size, decompressed) in {
            'no zlib stream': (b'\0\1' * 0x80, 0x100, False),
            'zlib_size larger than the body': (stream, len(stream) + 0x10, False),
            'zlib_size 0 (stream length unrecorded)': (stream, 0, True),
        }.items():
            with self.subTest(name):
                img = image(entry(0x02, 0x100 + len(body), X86 + BAD))
                img[BAD:BAD + 0x100 + len(body)] = header(compressed=1, zlib_size=zlib_size) + body
                pt, _ = parse(img)
                self.assertGoodSiblingParsed(pt)
                file = next(file for file in files(pt) if file.get_address() == BAD)
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(file.plaintext_identity_ok(), decompressed)
                    self.assertEqual(file.get_decrypted_decompressed_body() == plain, decompressed)
                if not decompressed:
                    self.assertEqual(file.decode_verification(), (False, 'decompress-failed'))

    def test_listing_survives_unusable_certifying_key(self):
        key_id = b'\xCD' * 16
        img = image(entry(0x00, 0x240, X86 + BAD), entry(0x02, 0x300, X86 + BAD + 0x1000))
        img[BAD:BAD + 0x240] = pubkey(key_id, modulus=0)
        img[BAD + 0x1000:BAD + 0x1300] = header(signed=1, size_signed=0x100, rom_size=0x300, key_id=key_id) \
            + b'X' * 0x200
        pt, _ = parse(img)
        self.assertGoodSiblingParsed(pt)
        signed = next(file for file in files(pt) if file.type == 0x02)
        self.assertEqual(signed.decode_verification(), (False, 'signature-error'))
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            pt.ls()
            pt.ls_json()
            pt.cert_tree.print_key_tree()
        with mock.patch.object(HeaderFile, 'get_decrypted_body', side_effect=ValueError('boom')):
            self.assertEqual(signed.decode_verification(), (False, 'decode-error'))

    def test_malformed_directory_graph_is_contained(self):
        with self.subTest('long chain of secondary directories'):
            img = image(entry(0x40, 0x20, X86 + 0x100000))
            for i in range(1500):
                offset = 0x100000 + 0x40 * i
                put_dir(img, offset, [entry(0x40, 0x20, X86 + offset + 0x40)])
            pt, _ = parse(img)
            self.assertGoodSiblingParsed(pt)
            self.assertEqual(len(pt.blob.roms[0].directories), 1501)

        with self.subTest('directory reached from the FET and again from a combo directory'):
            img = image(pointers=(X86 + DIR, X86 + 0x60000))
            put_combo(img, 0x60000, [DIR])
            pt, _ = parse(img)
            self.assertGoodSiblingParsed(pt)
            self.assertEqual(pt.blob.roms[0].directories[0].zen_generation, 'Zen 3 (PSP ID 0xbc0c0100)')

        with self.subTest('two combo directories, secondary pointer to an empty slot'):
            img = image(entry(0x40, 0x400, X86 + 0xA0000), pointers=(X86 + 0x60000, X86 + 0x70000))
            put_combo(img, 0x60000, [DIR], psp_id=0xbc0c0100)
            put_combo(img, 0x70000, [DIR], psp_id=0xbc0b0500)
            pt, _ = parse(img)
            self.assertGoodSiblingParsed(pt)
            self.assertIn('Zen 2', pt.blob.roms[0].directories[0].zen_generation)

        with self.subTest('secondary directory pointer to garbage'):
            img = image(entry(0x40, 0x400, X86 + BAD))
            img[BAD:BAD + 16] = b'GARBAGEGARBAGE!!'
            self.assertGoodSiblingParsed(parse(img)[0])

        with self.subTest('combo directory entry pointing to garbage'):
            img = image(pointers=(X86 + DIR, X86 + 0x60000))
            put_combo(img, 0x60000, [BAD])
            img[BAD:BAD + 16] = b'GARBAGEGARBAGE!!'
            self.assertGoodSiblingParsed(parse(img)[0])

        with self.subTest('directory with a huge entry count'):
            img = image(pointers=(X86 + DIR, X86 + BAD))
            img[BAD:BAD + 16] = b'$PSP\0\0\0\0' + struct.pack('<II', 0xffffff, 0)
            self.assertGoodSiblingParsed(parse(img)[0])

    def test_malformed_rom_and_fet_candidates_are_skipped(self):
        with self.subTest('20 MiB input with a FET-like pattern past 16 MiB'):
            img = image(size=20 * MB)
            put_fet(img, 0x1100004, [0xFFFFFFFF])
            self.assertGoodSiblingParsed(parse(img)[0])

        with self.subTest('input smaller than any ROM size'):
            self.assertEqual(parse(blank(4 * MB))[0].blob.roms, [])

        with self.subTest('FET without end marker'):
            img = image()
            img[0xfa0000 - 4:] = b'\0' * 4 + b'\xAA\x55\xAA\x55' + b'\0' * (16 * MB - 0xfa0000 - 4)
            self.assertGoodSiblingParsed(parse(img)[0])

        for name, combo in {
            'combo header with non-zero reserved bytes': b'2PSP' + b'\0' * 4 + struct.pack('<I', 1) + b'\0' * 4
                                                        + b'\1' * 16,
            'combo directory with a huge count': b'2PSP' + b'\0' * 4 + struct.pack('<I', 0x10000000) + b'\0' * 0x24,
        }.items():
            with self.subTest(name):
                img = image(pointers=(X86 + DIR, X86 + 0x60000))
                img[0x60000:0x60000 + len(combo)] = combo
                self.assertGoodSiblingParsed(parse(img)[0])

        with self.subTest('non-ASCII AGESA version'):
            img = image()
            img[0x90000:0x9000c] = b'AGESA!V9\0\xe9\xe9\0'
            pt, _ = parse(img)
            self.assertGoodSiblingParsed(pt)
            self.assertIn('�', pt.blob.roms[0].agesa_version)

    def test_x86_address_0xff000000_maps_to_the_start_of_a_32mb_rom(self):
        img = blank(32 * MB)
        put_fet(img, FET, [X86])
        img[GOOD:GOOD + 0x200] = header() + b'A' * 0x100
        put_dir(img, 0, [entry(0x01, 0x200, X86 + GOOD)])
        self.assertGoodSiblingParsed(parse(img)[0])

    def test_verified_form_reflects_the_latest_verification(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_id = b'\xAB' * 16
        payload = b'SIGNED' * 0x40
        signed_header = header(signed=1, size_signed=len(payload), rom_size=0x100 + len(payload) + 0x100,
                               key_id=key_id)
        signature = private_key.sign(bytes(signed_header) + payload,
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        signed_file = signed_header + payload + signature
        img = image(entry(0x00, 0x240, X86 + BAD), entry(0x02, len(signed_file), X86 + BAD + 0x1000))
        img[BAD:BAD + 0x240] = pubkey(key_id, modulus=private_key.public_key().public_numbers().n)
        img[BAD + 0x1000:BAD + 0x1000 + len(signed_file)] = signed_file
        pt, _ = parse(img)
        self.assertGoodSiblingParsed(pt)
        entity = next(file for file in files(pt) if file.type == 0x02).signed_entity
        self.assertTrue(entity.is_verified())
        self.assertEqual(entity.verified_form, 'decoded')
        entity.signature.set_bytes(0, 4, b'\0' * 4)
        self.assertFalse(entity.is_verified())
        self.assertIsNone(entity.verified_form)

    def test_inline_pubkey_match_near_the_end_of_a_file_is_ignored(self):
        key_id = b'\xAB' * 16
        img = image(entry(0x04, 16 * MB, X86 + 0), entry(0x02, 0x300, X86 + BAD))
        img[BAD:BAD + 0x300] = header(signed=1, rom_size=0x300, key_id=key_id) + b'B' * 0x200
        img[16 * MB - 0x24:16 * MB - 0x20] = struct.pack('<I', 1)
        img[16 * MB - 0x20:16 * MB - 0x10] = key_id
        self.assertGoodSiblingParsed(parse(img)[0])

    def test_unterminated_fet_is_rejected_quickly(self):
        img = bytearray(b'\0' * 32 * MB)
        for i in range(7):
            m = 16 * MB + 0x1000 + 8 * i
            img[m:m + 4] = b'\xAA\x55\xAA\x55'
        pt, stderr = parse(img)
        self.assertEqual(pt.blob.roms, [])
        self.assertIn('Warning', stderr)

    def test_compressed_microcode_header_does_not_retain_the_body(self):
        bomb = zlib.compress(b'\x01\x02\x03\x04\x05\x06\x07\x08' + b'\0' * (4 * MB), 9)
        bomb += b'\0' * (-len(bomb) % 16)
        size = 0x100 + len(bomb)
        img = blank()
        put_fet(img, FET, [X86 + DIR])
        img[0x100000:0x100000 + size] = header(compressed=1, zlib_size=len(bomb)) + bomb
        put_dir(img, DIR, [struct.pack('<BBHIIIQ', 0x66, 0, 0, size, X86 + 0x100000, 0, 0)], magic=b'$BHD')
        pt, _ = parse(img)
        microcode = next(file for file in files(pt) if file.type == 0x66)
        self.assertEqual((microcode.date, microcode.patch_level), (0x04030201, 0x08070605))
        self.assertFalse(hasattr(microcode, 'body'))

    def test_aliased_and_oversized_directory_references_are_contained(self):
        with self.subTest('secondary pointers aliasing one directory'):
            img = blank()
            put_fet(img, FET, [X86 + DIR])
            img[GOOD:GOOD + 0x200] = header() + b'A' * 0x100
            ents = [entry(0x01, 0x200, GOOD)] + [entry(0x40, 0x100, DIR + k * 16 * MB) for k in range(1, 256)]
            put_dir(img, DIR, ents, info=1 << 29)
            pt, _ = parse(img)
            self.assertEqual([d.get_address() for d in pt.blob.roms[0].directories], [DIR])
        with self.subTest('combo directory with too many entries'):
            img = image(pointers=(X86 + 0x100000,))
            put_combo(img, 0x100000, [DIR] * 1000)
            pt, stderr = parse(img)
            self.assertIn('Warning', stderr)
        with self.subTest('overlapping directories exhaust the entry budget'):
            img = blank()
            rec = b'$PSP' + b'\0' * 4 + struct.pack('<II', 3000, 0)
            for k in range(3100):
                img[0x100000 + 16 * k:0x100000 + 16 * k + 16] = rec
            img[3000:3000 + 0x200] = header() + b'A' * 0x100
            put_fet(img, FET, [X86 + 0x100000 + 16 * k for k in range(40)])
            pt, _ = parse(img)
            self.assertLess(sum(len(d.entries) for d in pt.blob.roms[0].directories), 100000)

    def test_unsupported_key_sizes_are_skipped(self):
        for t, blob in ((0x00, pubkey(b'\x44' * 16, bits=1024)), (0x50, key_store(1024))):
            img = image(entry(t, len(blob), X86 + BAD))
            img[BAD:BAD + len(blob)] = blob
            pt, _ = parse(img)
            self.assertGoodSiblingParsed(pt)

    def test_resign_only_signs_the_form_that_was_verified(self):
        from psptool.crypto import RsaPrivateKey
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_id = b'\xAB' * 16
        stream = zlib.compress(b'PLAINTEXT' * 300)
        stream += b'\0' * (-len(stream) % 16)
        signed_header = header(signed=1, compressed=1, zlib_size=len(stream), size_signed=len(stream),
                               rom_size=0x100 + len(stream) + 0x100, key_id=key_id)
        signature = private_key.sign(bytes(signed_header) + stream,
                                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        signed_file = signed_header + stream + signature
        img = image(entry(0x00, 0x240, X86 + BAD), entry(0x02, len(signed_file), X86 + BAD + 0x1000))
        img[BAD:BAD + 0x240] = pubkey(key_id, modulus=private_key.public_key().public_numbers().n)
        img[BAD + 0x1000:BAD + 0x1000 + len(signed_file)] = signed_file
        pt, _ = parse(img)
        entity = next(file for file in files(pt) if file.type == 0x02).signed_entity
        self.assertTrue(entity.is_verified())
        self.assertEqual(entity.verified_form, 'stored')
        new_key = next(c for c in RsaPrivateKey.__subclasses__() if c.key_bits == 2048).generate_new()
        with contextlib.redirect_stdout(io.StringIO()):
            entity.resign_only(new_key)
        self.assertEqual(entity.resigned_form, 'stored')
        self.assertTrue(entity.verify_with_pubkey(new_key.get_public_key()))
        self.assertEqual(entity.verified_form, 'stored')


if __name__ == '__main__':
    unittest.main()
