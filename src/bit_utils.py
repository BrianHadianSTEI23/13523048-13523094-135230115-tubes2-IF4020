from math import gcd
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
    """Performs circular left shift on an arbitrary-length integer bit string."""
    if bit_length == 0:
        return val
    mask = (1 << bit_length) - 1
    shift %= bit_length
    val &= mask
    return ((val << shift) | (val >> (bit_length - shift))) & mask


def rot_right(val: int, bit_length: int, shift: int) -> int:
    """Performs circular right shift on an arbitrary-length integer bit string."""
    if bit_length == 0:
        return val
    mask = (1 << bit_length) - 1
    shift %= bit_length
    val &= mask
    return ((val >> shift) | (val << (bit_length - shift))) & mask


def permute_state_bits(val: int, bit_length: int, inverse: bool = False) -> int:
    if bit_length <= 0 or gcd(5, bit_length) != 1:
        raise ValueError("bit_length must be positive and coprime to 5")
    if not isinstance(val, int) or val < 0 or val >= (1 << bit_length):
        raise ValueError("value must fit within bit_length bits")

    result = 0
    for source in range(bit_length):
        target = (5 * source + 7) % bit_length
        if inverse:
            result |= ((val >> target) & 1) << source
        else:
            result |= ((val >> source) & 1) << target
    return result


def _undo_xor_shift_left(value: int, bit_length: int, shift: int) -> int:
    mask = (1 << bit_length) - 1
    step = shift
    while step < bit_length:
        value ^= (value << step) & mask
        step *= 2
    return value & mask


def _undo_xor_shift_right(value: int, bit_length: int, shift: int) -> int:
    step = shift
    while step < bit_length:
        value ^= value >> step
        step *= 2
    return value


def diffuse_state_bits(val: int, bit_length: int, inverse: bool = False) -> int:
    mask = (1 << bit_length) - 1
    if inverse:
        val = permute_state_bits(val, bit_length, inverse=True)
        val = _undo_xor_shift_left(val, bit_length, 17)
        val = _undo_xor_shift_right(val, bit_length, 11)
        return _undo_xor_shift_left(val, bit_length, 7)
    if not isinstance(val, int) or val < 0 or val > mask:
        raise ValueError("value must fit within bit_length bits")
    val ^= (val << 7) & mask
    val ^= val >> 11
    val ^= (val << 17) & mask
    return permute_state_bits(val & mask, bit_length)

def gf2_mul(a: int, b: int, n: int, poly_low: int) -> int:
    """
    Carryless polynomial multiplication modulo x^n + poly_low.

    The quotient is a field only when the modulus is irreducible; that is not
    assumed for every configured block width.
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