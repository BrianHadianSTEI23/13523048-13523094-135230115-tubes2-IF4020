import unittest
import os
import tempfile
from src.modes import (
    pkcs7_pad,
    pkcs7_unpad,
    encrypt_ecb,
    decrypt_ecb,
    encrypt_cbc,
    decrypt_cbc,
    encrypt_cfb,
    decrypt_cfb,
    encrypt_ofb,
    decrypt_ofb,
    encrypt_ctr,
    decrypt_ctr,
    encrypt_file,
    decrypt_file,
)


class TestModule5(unittest.TestCase):
    def setUp(self):
        self.master_key = 0xDEADBEEF12345678
        self.iv = b"12345678"  # 8 bytes = 64 bits
        self.sample_text = b"This is a test message for Module 5 block cipher modes!"

    def test_pkcs7_padding_roundtrip(self):
        data = b"Hello, World!"
        padded = pkcs7_pad(data, 8)
        self.assertEqual(len(padded) % 8, 0)
        unpadded = pkcs7_unpad(padded, 8)
        self.assertEqual(data, unpadded)

    def test_ecb_mode(self):
        ciphertext = encrypt_ecb(self.sample_text, self.master_key, block_bits=64)
        decrypted = decrypt_ecb(ciphertext, self.master_key, block_bits=64)
        self.assertEqual(self.sample_text, decrypted)

    def test_cbc_mode(self):
        ciphertext = encrypt_cbc(self.sample_text, self.master_key, self.iv, block_bits=64)
        decrypted = decrypt_cbc(ciphertext, self.master_key, self.iv, block_bits=64)
        self.assertEqual(self.sample_text, decrypted)

    def test_cfb_mode(self):
        ciphertext = encrypt_cfb(self.sample_text, self.master_key, self.iv, block_bits=64)
        decrypted = decrypt_cfb(ciphertext, self.master_key, self.iv, block_bits=64)
        self.assertEqual(self.sample_text, decrypted)

    def test_ofb_mode(self):
        ciphertext = encrypt_ofb(self.sample_text, self.master_key, self.iv, block_bits=64)
        decrypted = decrypt_ofb(ciphertext, self.master_key, self.iv, block_bits=64)
        self.assertEqual(self.sample_text, decrypted)

    def test_ctr_mode(self):
        ciphertext = encrypt_ctr(self.sample_text, self.master_key, self.iv, block_bits=64)
        decrypted = decrypt_ctr(ciphertext, self.master_key, self.iv, block_bits=64)
        self.assertEqual(self.sample_text, decrypted)

    def test_file_encryption_decryption(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_file = os.path.join(tmp_dir, "plain.txt")
            enc_file = os.path.join(tmp_dir, "enc.bin")
            dec_file = os.path.join(tmp_dir, "dec.txt")

            with open(input_file, "wb") as f:
                f.write(self.sample_text)

            # Encrypt file
            encrypt_file(
                input_file, enc_file, self.master_key, mode="CBC", block_bits=64, iv=self.iv
            )
            self.assertTrue(os.path.exists(enc_file))

            # Decrypt file
            decrypt_file(
                enc_file, dec_file, self.master_key, mode="CBC", block_bits=64, iv=self.iv
            )
            
            with open(dec_file, "rb") as f:
                decrypted_data = f.read()

            self.assertEqual(self.sample_text, decrypted_data)


if __name__ == "__main__":
    unittest.main()