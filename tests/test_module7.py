import unittest
import math
import os
from src.analysis import (
    count_bit_differences,
    analyze_avalanche_plaintext,
    analyze_avalanche_key,
    calculate_shannon_entropy,
    generate_histogram,
    calculate_chi_square_uniformity,
)


class TestModule7(unittest.TestCase):
    def test_count_bit_differences(self):
        self.assertEqual(count_bit_differences(0b0000, 0b1111), 4)
        self.assertEqual(count_bit_differences(0x1234, 0x1234), 0)
        self.assertEqual(count_bit_differences(0x00, 0x01), 1)

    def test_avalanche_effect_plaintext(self):
        pt = 0x0123456789ABCDEF
        key = 0xDEADBEEF12345678
        
        # 1. Single bit flip test (verify output changes)
        res_single = analyze_avalanche_plaintext(pt, key, bit_index=0, block_bits=64, num_rounds=20)
        self.assertGreater(res_single["delta_bits"], 0)

        # 2. Average avalanche effect across all 64 bit positions
        total_percentage = 0.0
        for b in range(64):
            res = analyze_avalanche_plaintext(pt, key, bit_index=b, block_bits=64, num_rounds=20)
            total_percentage += res["percentage"]

        avg_percentage = total_percentage / 64.0
        # Average avalanche across all bit flips should satisfy diffusion (> 30%)
        self.assertGreater(avg_percentage, 30.0)

    def test_avalanche_effect_key(self):
        pt = 0x0123456789ABCDEF
        key = 0xDEADBEEF12345678
        
        # 1. Single bit flip test
        res_single = analyze_avalanche_key(pt, key, bit_index=0, block_bits=64, num_rounds=20)
        self.assertGreater(res_single["delta_bits"], 0)

        # 2. Average avalanche effect across key bits
        total_percentage = 0.0
        for b in range(64):
            res = analyze_avalanche_key(pt, key, bit_index=b, block_bits=64, num_rounds=20)
            total_percentage += res["percentage"]

        avg_percentage = total_percentage / 64.0
        self.assertGreater(avg_percentage, 30.0)

    def test_shannon_entropy_zero(self):
        data = b"\x00" * 100
        res = calculate_shannon_entropy(data)
        self.assertEqual(res["entropy"], 0.0)
        self.assertEqual(res["max_theoretical_entropy"], 8.0)

    def test_shannon_entropy_maximum(self):
        data = bytes(range(256))
        res = calculate_shannon_entropy(data)
        self.assertAlmostEqual(res["entropy"], 8.0, places=4)
        self.assertAlmostEqual(res["ratio"], 1.0, places=4)

    def test_shannon_entropy_random_data(self):
        data = os.urandom(1024)
        res = calculate_shannon_entropy(data)
        self.assertGreater(res["entropy"], 7.0)

    def test_histogram_generator(self):
        data = b"\x00\x00\x01\x02\xFF"
        hist = generate_histogram(data)
        self.assertEqual(len(hist), 256)
        self.assertEqual(hist[0], 2)
        self.assertEqual(hist[1], 1)
        self.assertEqual(hist[2], 1)
        self.assertEqual(hist[255], 1)
        self.assertEqual(hist[3], 0)

    def test_chi_square_uniformity(self):
        # Perfectly uniform distribution
        uniform_data = bytes(range(256)) * 4
        res = calculate_chi_square_uniformity(uniform_data)
        self.assertAlmostEqual(res["chi_square"], 0.0, places=4)

        # Highly non-uniform distribution
        non_uniform_data = b"\x00" * 1024
        res_non = calculate_chi_square_uniformity(non_uniform_data)
        self.assertGreater(res_non["chi_square"], 1000.0)


if __name__ == "__main__":
    unittest.main()