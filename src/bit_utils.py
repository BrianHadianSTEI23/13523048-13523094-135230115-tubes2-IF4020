from typing import List, Tuple

def slice_bits_msb(val: int, total_bits: int, start_bit: int, length: int) -> int:
    """
    Extracts a bit field of length `length` starting from `start_bit` (0 = MSB).
    """
    if start_bit + length > total_bits:
        raise ValueError(f"Slice range [{start_bit}:{start_bit+length}] exceeds total bits ({total_bits})")
    shift = total_bits - (start_bit + length)
    mask = (1 << length) - 1
    return (val >> shift) & mask

def concat_bits(parts: List[Tuple[int, int]]) -> int:
    """
    Concatenates a sequence of (value, bit_length) tuples from MSB to LSB.
    """
    res = 0
    for val, length in parts:
        mask = (1 << length) - 1
        res = (res << length) | (val & mask)
    return res

def rot_left(val: int, bit_length: int, shift: int) -> int:
    """
    Performs circular left shift on an arbitrary-length integer bit string.
    """
    mask = (1 << bit_length) - 1
    shift %= bit_length
    val &= mask
    return ((val << shift) | (val >> (bit_length - shift))) & mask

def rot_right(val: int, bit_length: int, shift: int) -> int:
    """
    Performs circular right shift on an arbitrary-length integer bit string.
    """
    mask = (1 << bit_length) - 1
    shift %= bit_length
    val &= mask
    return ((val >> shift) | (val << (bit_length - shift))) & mask

def gf2_mul(a: int, b: int, n: int, poly_low: int) -> int:
    """
    Performs multiplication in GF(2^n) modulo (x^n + poly_low).
    Uses peasant multiplication with bitwise XOR addition.
    """
    mask_n = (1 << n) - 1
    a &= mask_n
    b &= mask_n
    res = 0

    while b > 0:
        if b & 1:
            res ^= a
        b >>= 1
        a <<= 1
        if a & (1 << n):
            a ^= ((1 << n) | poly_low)

    return res & mask_n

def bytes_to_int(data: bytes) -> int:
    """Converts big-endian bytes to integer."""
    return int.from_bytes(data, byteorder='big')

def int_to_bytes(val: int, num_bytes: int) -> bytes:
    """Converts integer to big-endian bytes padded to num_bytes."""
    return val.to_bytes(num_bytes, byteorder='big')