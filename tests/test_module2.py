import unittest
from config.params import BLOCK_CONFIGS
from src.sbox_spn import (
    sub_bytes,
    shift_rows,
    mix_columns,
    add_round_key,
    sbox_compress,
    sbox_expand,
    custom_sha256,
)

class TestModule2(unittest.TestCase):

    def test_sub_bytes_invertibility(self):
        val = 0xA5B4C3D2
        subbed = sub_bytes(val, 32, inverse=False)
        restored = sub_bytes(subbed, 32, inverse=True)
        self.assertEqual(val, restored)

    def test_shift_rows_invertibility(self):
        for b_bits in [64, 96, 128, 192]:
            val = (1 << b_bits) - 0x123456789
            shifted = shift_rows(val, b_bits, inverse=False)
            restored = shift_rows(shifted, b_bits, inverse=True)
            self.assertEqual(val, restored)

    def test_sbox_compress_and_expand_bounds(self):
        for b_bits, cfg in BLOCK_CONFIGS.items():
            # Test S1/S2 Compression
            in_bits, out_bits = cfg.round_s_compress
            val = (1 << in_bits) - 1
            compressed = sbox_compress(val, in_bits, out_bits)
            self.assertLess(compressed, 1 << out_bits)

            # Test S3/S4 Expansion
            in_bits, out_bits = cfg.round_s_expand
            val = (1 << in_bits) - 1
            expanded = sbox_expand(val, in_bits, out_bits)
            self.assertLess(expanded, 1 << out_bits)

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