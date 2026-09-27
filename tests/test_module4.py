import unittest
from src.cipher_core import encrypt_block, decrypt_block

class TestModule4(unittest.TestCase):

    def test_single_block_encryption_decryption_64bit(self):
        block_bits = 64
        plaintext = 0x123456789ABCDEF0
        master_key = 0x0F0E0D0C0B0A0908
        iv = 0xA1B2C3D4E5F60718
        
        ciphertext = encrypt_block(plaintext, master_key, iv, block_bits, num_rounds=20)
        self.assertNotEqual(plaintext, ciphertext)
        
        decrypted = decrypt_block(ciphertext, master_key, iv, block_bits, num_rounds=20)
        self.assertEqual(plaintext, decrypted)

    def test_variable_block_sizes_roundtrip(self):
        for b_bits in [64, 96, 128, 192]:
            plaintext = (1 << b_bits) - 0xCAFEBABE
            master_key = (1 << b_bits) - 0x123456789
            iv = (1 << b_bits) - 0x987654321
            
            ciphertext = encrypt_block(plaintext, master_key, iv, b_bits, num_rounds=2)
            decrypted = decrypt_block(ciphertext, master_key, iv, b_bits, num_rounds=2)
            
            self.assertEqual(plaintext, decrypted, f"Roundtrip failed for block size {b_bits}")

if __name__ == '__main__':
    unittest.main()