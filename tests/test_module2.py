import unittest
from config.params import BLOCK_CONFIGS
from src.sbox_spn import (
    sub_bytes,
    add_round_key,
    sbox_compress,
    custom_sha256,
)

class TestModule2(unittest.TestCase):

    def test_sub_bytes_invertibility(self):
        val = 0xA5B4C3D2
        subbed = sub_bytes(val, 32, inverse=False)
        restored = sub_bytes(subbed, 32, inverse=True)
        self.assertEqual(val, restored)

    def test_sbox_compress_bounds(self):
        for b_bits, cfg in BLOCK_CONFIGS.items():
            in_bits, out_bits = cfg.merged_l_bits, cfg.outer_bits
            val = (1 << in_bits) - 1
            compressed = sbox_compress(val, in_bits, out_bits)
            self.assertLess(compressed, 1 << out_bits)

    def test_custom_sha256_key_dependency(self):
        data_val = 0x1234  # 16-bit value (fits in data_bits = 16)
        data_bits = 16
        key1 = 0xAAAAAAAA
        key2 = 0xAAAAAAAB
        
        out1 = custom_sha256(data_val, data_bits, key1, 32)
        out2 = custom_sha256(data_val, data_bits, key2, 32)
        
        self.assertLess(out1, 1 << data_bits)
        self.assertLess(out2, 1 << data_bits)
        self.assertNotEqual(out1, out2)

if __name__ == '__main__':
    unittest.main()
