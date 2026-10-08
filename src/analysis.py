import math
from collections import Counter
from typing import Dict, Any
from src.cipher_core import encrypt_block


def count_bit_differences(val1: int, val2: int) -> int:
    """Calculates the Hamming distance (number of differing bits) between two integers."""
    return bin(val1 ^ val2).count("1")


def analyze_avalanche_plaintext(
    plaintext: int,
    key: int,
    iv: int = 0,
    bit_index: int = 0,
    block_bits: int = 64,
    num_rounds: int = 16,
) -> Dict[str, Any]:
    """Flips 1 bit in plaintext and measures the bit changes in ciphertext.

    Calculates percentage using: (delta_bits / block_bits) * 100%
    """
    flipped_plaintext = plaintext ^ (1 << bit_index)

    c1 = encrypt_block(
        plaintext,
        master_key=key,
        iv=iv,
        block_bits=block_bits,
        num_rounds=num_rounds,
    )
    c2 = encrypt_block(
        flipped_plaintext,
        master_key=key,
        iv=iv,
        block_bits=block_bits,
        num_rounds=num_rounds,
    )

    delta_bits = count_bit_differences(c1, c2)
    percentage = (delta_bits / block_bits) * 100.0

    return {
        "block_bits": block_bits,
        "delta_bits": delta_bits,
        "percentage": percentage,
        "ciphertext_original": c1,
        "ciphertext_flipped": c2,
    }


def analyze_avalanche_key(
    plaintext: int,
    key: int,
    iv: int = 0,
    bit_index: int = 0,
    block_bits: int = 64,
    num_rounds: int = 16,
) -> Dict[str, Any]:
    """Flips 1 bit in key and measures the bit changes in ciphertext.

    Calculates percentage using: (delta_bits / block_bits) * 100%
    """
    flipped_key = key ^ (1 << bit_index)

    c1 = encrypt_block(
        plaintext,
        master_key=key,
        iv=iv,
        block_bits=block_bits,
        num_rounds=num_rounds,
    )
    c2 = encrypt_block(
        plaintext,
        master_key=flipped_key,
        iv=iv,
        block_bits=block_bits,
        num_rounds=num_rounds,
    )

    delta_bits = count_bit_differences(c1, c2)
    percentage = (delta_bits / block_bits) * 100.0

    return {
        "block_bits": block_bits,
        "delta_bits": delta_bits,
        "percentage": percentage,
        "ciphertext_original": c1,
        "ciphertext_flipped": c2,
    }


def calculate_shannon_entropy(data: bytes) -> Dict[str, float]:
    """Calculates byte-level Shannon entropy: H(X) = -sum(P(x) * log2(P(x))).

    Validates against the maximum theoretical upper bound of 8.0 bits/byte.
    """
    if not data:
        return {"entropy": 0.0, "max_theoretical_entropy": 8.0, "ratio": 0.0}

    length = len(data)
    counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    max_entropy = 8.0
    ratio = entropy / max_entropy

    return {
        "entropy": entropy,
        "max_theoretical_entropy": max_entropy,
        "ratio": ratio,
    }


def generate_histogram(data: bytes) -> Dict[int, int]:
    """Generates a byte frequency distribution (histogram) across all values 0-255."""
    counts = Counter(data)
    return {b: counts.get(b, 0) for b in range(256)}


def calculate_chi_square_uniformity(data: bytes) -> Dict[str, float]:
    """Calculates Chi-Square statistic to test byte distribution uniformity.

    Expected frequency per byte value: E = len(data) / 256
    Chi-Square = sum((O_i - E)^2 / E)
    """
    n = len(data)
    if n == 0:
        return {"chi_square": 0.0, "degrees_of_freedom": 255, "expected_frequency": 0.0}

    expected = n / 256.0
    histogram = generate_histogram(data)

    chi_square = sum(
        ((observed - expected) ** 2) / expected for observed in histogram.values()
    )

    return {
        "chi_square": chi_square,
        "degrees_of_freedom": 255,
        "expected_frequency": expected,
    }
