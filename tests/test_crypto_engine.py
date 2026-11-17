import os
import tempfile
import unittest
from pathlib import Path
from crypto_engine import encrypt_file, decrypt_file
from legacy_v1 import encrypt_file as legacy_encrypt
from archive_utils import archive_folder

class CryptoTests(unittest.TestCase):
    def test_round_trip_and_tamper(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t); src = p/'source'; enc = p/'encrypted.cvlt'; out = p/'output'
            src.write_bytes(os.urandom(2_500_000))
            encrypt_file(src, enc, 'correct horse battery staple')
            with self.assertRaises(ValueError): decrypt_file(enc, out, 'wrong')
            self.assertFalse(out.exists())
            decrypt_file(enc, out, 'correct horse battery staple')
            self.assertEqual(src.read_bytes(), out.read_bytes())
            with self.assertRaises(FileExistsError): decrypt_file(enc, out, 'correct horse battery staple')
            out.unlink()
            content = bytearray(enc.read_bytes()); content[60] ^= 1; enc.write_bytes(content)
            with self.assertRaises(ValueError): decrypt_file(enc, out, 'correct horse battery staple')
            self.assertFalse(out.exists())
    def test_empty_and_legacy(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t); src=p/'empty'; enc=p/'empty.cvlt'; dst=p/'restored'
            src.write_bytes(b'')
            encrypt_file(src, enc, 'pass'); decrypt_file(enc, dst, 'pass')
            self.assertEqual(dst.read_bytes(), b'')
            dst.unlink(); enc.unlink()
            src.write_bytes(b'old format')
            legacy_encrypt(str(src), str(enc), 'pass')
            decrypt_file(enc, dst, 'pass')
            self.assertEqual(dst.read_bytes(), b'old format')
    def test_folder_archive(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t); folder=p/'data'; folder.mkdir(); (folder/'a.txt').write_text('abc')
            archive_folder(folder, p/'data.zip')
            from zipfile import ZipFile
            with ZipFile(p/'data.zip') as z: self.assertEqual(z.read('data/a.txt'), b'abc')
if __name__ == '__main__': unittest.main()
