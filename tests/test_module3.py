import unittest
from config.params import BLOCK_CONFIGS
from src.keygen import generate_keys, derive_round_subkeys

class TestModule3(unittest.TestCase):

    def test_key_generation_bounds_and_count(self):
        for b_bits in [64, 96, 128, 192]:
            master_key = (1 << b_bits) - 0xDEADBEEF
            count = 20
            keys = generate_keys(master_key, count, b_bits)
            
            self.assertEqual(len(keys), count)
            mask = (1 << b_bits) - 1
            for k in keys:
                self.assertLessEqual(k, mask)
                self.assertGreaterEqual(k, 0)

    def test_key_generation_determinism(self):
        master_key = 0x123456789ABCDEF0
        keys1 = generate_keys(master_key, 10, 64)
        keys2 = generate_keys(master_key, 10, 64)
        self.assertEqual(keys1, keys2)

    def test_round_subkeys_derivation(self):
        master_key = 0x0123456789ABCDEF0123456789ABCDEF
        round_subkeys = derive_round_subkeys(master_key, num_rounds=20, block_bits=128)
        
        self.assertEqual(len(round_subkeys), 20)
        for r in range(20):
            sub = round_subkeys[r]
            self.assertIn('Key1', sub)
            self.assertIn('Key2', sub)
            self.assertIn('Key3', sub)
            self.assertIn('Key4', sub)
            self.assertIn('Key5', sub)

    def test_key_avalanche_sensitivity(self):
        master_key_a = 0x123456789ABCDEF0
        master_key_b = 0x123456789ABCDEF1  # 1 bit difference
        
        keys_a = generate_keys(master_key_a, 5, 64)
        keys_b = generate_keys(master_key_b, 5, 64)
        
        for ka, kb in zip(keys_a, keys_b):
            self.assertNotEqual(ka, kb)

if __name__ == '__main__':
    unittest.main()