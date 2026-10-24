import io
import os
import contextlib
import unittest
from unittest import mock

import psptool
from psptool.header_file import HeaderFile

dirname = os.path.dirname(__file__)
fixtures_path = os.path.join(dirname, 'fixtures/test_files')

VERIFIED_METHODS = {'signature', 'signature+sha256', 'signature+sha384', 'sha256', 'sha384', 'plain'}
UNVERIFIED_METHODS = {'signature-failed', 'signature-unresolved', 'signature-error',
                      'signature-partial', 'sha256-failed', 'sha384-failed',
                      'decompress-failed', 'unverifiable'}


@unittest.skipUnless(os.path.isdir(fixtures_path), "firmware fixtures submodule not checked out")
class TestDecodeVerified(unittest.TestCase):
    """Exercises HeaderFile.decode_verified() - the signal downstream tools key on
    to tell an authentic decoded body from a silently mis-decoded one."""

    _pts = {}

    @classmethod
    def fixtures(cls):
        for subdir, _dirs, files in os.walk(fixtures_path):
            for f in files:
                if not f.startswith('.'):
                    yield os.path.join(subdir, f)

    @classmethod
    def pt(cls, filename):
        if filename not in cls._pts:
            with io.StringIO() as buf, contextlib.redirect_stderr(buf):
                cls._pts[filename] = psptool.PSPTool.from_file(filename)
        return cls._pts[filename]

    def header_files(self):
        for filename in self.fixtures():
            pt = self.pt(filename)
            for rom in pt.blob.roms:
                for directory in rom.directories:
                    for entry in directory.files:
                        if isinstance(entry, HeaderFile):
                            yield filename, entry

    def test_signal_is_total_and_consistent(self):
        """decode_verified() never raises, returns a bool, and its basis string
        agrees with the verdict for every HeaderFile in every fixture."""
        seen_methods = set()
        verified = encrypted_verified = 0
        for filename, entry in self.header_files():
            with self.subTest(f"{os.path.basename(filename)} type=0x{entry.type:x}"):
                with io.StringIO() as buf, contextlib.redirect_stderr(buf):
                    ok = entry.decode_verified()
                    method = entry.decode_verification_method()
                    combined = entry.decode_verification()
                self.assertIsInstance(ok, bool)
                self.assertEqual(combined, (ok, method))  # single-pass accessor agrees
                self.assertIn(method, VERIFIED_METHODS | UNVERIFIED_METHODS)
                if ok:
                    self.assertIn(method, VERIFIED_METHODS)
                else:
                    self.assertIn(method, UNVERIFIED_METHODS)
                seen_methods.add(method)
                verified += ok
                encrypted_verified += ok and entry.encrypted
        # The corpus must actually exercise the authoritative (signature) oracle,
        # including on real encrypted bodies - otherwise the signal proves nothing.
        self.assertIn('signature', seen_methods)
        self.assertGreater(verified, 0)
        self.assertGreater(encrypted_verified, 0)

    def test_signature_basis_covers_whole_body(self):
        """A bare 'signature' verdict must mean the signature spans the ENTIRE
        decoded body (size_signed >= len(body)). A signature only covers
        header + body[:size_signed]; if size_signed is short, the tail is
        unsigned and the body must NOT be reported verified on signature alone."""
        for filename, entry in self.header_files():
            with io.StringIO() as buf, contextlib.redirect_stderr(buf):
                method = entry.decode_verification_method()
                if method != 'signature':
                    continue
                body_len = len(entry.get_decrypted_decompressed_body())
                if entry.signed_entity.verified_form == 'stored':
                    body_len = entry.zlib_size
            with self.subTest(f"{os.path.basename(filename)} type=0x{entry.type:x}"):
                self.assertGreaterEqual(
                    entry.size_signed, body_len,
                    "'signature' basis but signature does not span the whole body")

    def test_signature_over_stored_zlib_stream(self):
        """Zen4/5 sign the stored (compressed) bytes of a compressed entry, older
        generations the decompressed ones; verification must accept either."""
        stored = 0
        for filename, entry in self.header_files():
            if not (entry.compressed and entry.signed_entity is not None):
                continue
            with io.StringIO() as buf, contextlib.redirect_stderr(buf):
                try:
                    verified = entry.signed_entity.is_verified()
                except Exception:
                    continue
            if verified and entry.signed_entity.verified_form == 'stored':
                stored += 1
                with self.subTest(f"{os.path.basename(filename)} type=0x{entry.type:x}"):
                    forms = dict(entry.get_signed_bytes_forms())
                    self.assertNotEqual(forms['stored'], forms['decoded'])
        if not stored:
            self.skipTest("no stored-form compressed signature in fixtures")

    def test_deterministic(self):
        for _filename, entry in self.header_files():
            with io.StringIO() as buf, contextlib.redirect_stderr(buf):
                first = entry.decode_verified()
                self.assertEqual(first, entry.decode_verified())

    def test_plaintext_identity_is_superset_of_verified(self):
        """plaintext_identity_ok() never raises, returns a bool, is True whenever
        decode_verified() is, and is False for any encrypted entry that is not
        verified (an unconfirmable decryption is never a plaintext identity)."""
        for filename, entry in self.header_files():
            with self.subTest(f"{os.path.basename(filename)} type=0x{entry.type:x}"):
                with io.StringIO() as buf, contextlib.redirect_stderr(buf):
                    ok = entry.decode_verified()
                    identity = entry.plaintext_identity_ok()
                self.assertIsInstance(identity, bool)
                if ok:
                    self.assertTrue(identity)
                if entry.encrypted and not ok:
                    self.assertFalse(identity)

    def test_failed_decompression_is_not_verified(self):
        """A compressed entry whose zlib stream fails to decompress must report
        decode_verified() == False (basis 'decompress-failed'), not silently pass
        the still-compressed bytes off as plaintext."""
        target = None
        for _filename, entry in self.header_files():
            if entry.compressed:
                target = entry
                break
        if target is None:
            self.skipTest("no compressed HeaderFile in fixtures")
        with mock.patch('psptool.header_file.zlib_decompress', side_effect=Exception('boom')):
            with io.StringIO() as buf, contextlib.redirect_stderr(buf):
                self.assertFalse(target.decode_verified())
                self.assertEqual(target.decode_verification_method(), 'decompress-failed')


if __name__ == '__main__':
    unittest.main()
