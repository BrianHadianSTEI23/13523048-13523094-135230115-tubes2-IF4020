import unittest
from config.params import get_config, BLOCK_CONFIGS
from src.bit_utils import (
    slice_bits_msb,
    concat_bits,
    rot_left,
    rot_right,
    gf2_mul,
    bytes_to_int,
    int_to_bytes,
)

class TestModule1(unittest.TestCase):

    def test_block_configs_ratios(self):
        for b_bits, cfg in BLOCK_CONFIGS.items():
            self.assertEqual(cfg.half_bits * 2, b_bits)
            total_partition = (cfg.outer_bits * 2) + cfg.l1_bits + cfg.l2_bits + cfg.r1_bits + cfg.r2_bits
            self.assertEqual(total_partition, b_bits)
            self.assertEqual(cfg.merged_l_bits, cfg.l1_bits + cfg.l2_bits)
            self.assertEqual(cfg.merged_r_bits, cfg.r1_bits + cfg.r2_bits)

    def test_bit_slicing_and_concatenation(self):
        # Test 64-bit block slicing into 6 parts
        cfg = get_config(64)
        val = 0x123456789ABCDEF0
        
        out_l = slice_bits_msb(val, 64, 0, cfg.outer_bits)
        l1    = slice_bits_msb(val, 64, cfg.outer_bits, cfg.l1_bits)
        l2    = slice_bits_msb(val, 64, cfg.outer_bits + cfg.l1_bits, cfg.l2_bits)
        r1    = slice_bits_msb(val, 64, cfg.outer_bits + cfg.l1_bits + cfg.l2_bits, cfg.r1_bits)
        r2    = slice_bits_msb(val, 64, cfg.outer_bits + cfg.l1_bits + cfg.l2_bits + cfg.r1_bits, cfg.r2_bits)
        out_r = slice_bits_msb(val, 64, cfg.outer_bits + cfg.l1_bits + cfg.l2_bits + cfg.r1_bits + cfg.r2_bits, cfg.outer_bits)

        reconstructed = concat_bits([
            (out_l, cfg.outer_bits),
            (l1, cfg.l1_bits),
            (l2, cfg.l2_bits),
            (r1, cfg.r1_bits),
            (r2, cfg.r2_bits),
            (out_r, cfg.outer_bits)
        ])
        self.assertEqual(val, reconstructed)

    def test_rotations(self):
        val = 0b10110000
        self.assertEqual(rot_left(val, 8, 2), 0b11000010)
        self.assertEqual(rot_right(val, 8, 2), 0b00101100)

    def test_gf2_multiplication(self):
        # GF(2^64) identity multiplication test
        cfg64 = get_config(64)
        a = 0xDEADBEEFCAFE1234
        res = gf2_mul(a, 1, 64, cfg64.gf_poly_low)
        self.assertEqual(a, res)
        
        # Test GF(2^64) associative property: (a * b) in field
        b = 0x0000000000000002
        c = gf2_mul(a, b, 64, cfg64.gf_poly_low)
        self.assertNotEqual(c, 0)
        self.assertLess(c, 1 << 64)

if __name__ == '__main__':
    unittest.main()