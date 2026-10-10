import ctypes
import os
import struct
import sys
from functools import lru_cache
from pathlib import Path
from typing import List, Tuple
from src.bit_utils import concat_bits, rot_left, rot_right, gf2_mul, bytes_to_int, int_to_bytes

def _gf8_inverse(value: int) -> int:
    if value == 0:
        return 0
    result = 1
    factor = value
    exponent = 254
    while exponent:
        if exponent & 1:
            result = gf2_mul(result, factor, 8, 0x1D)
        factor = gf2_mul(factor, factor, 8, 0x1D)
        exponent >>= 1
    return result


def _generate_sbox() -> Tuple[List[int], List[int]]:
    sbox = []
    for value in range(256):
        inverse = _gf8_inverse(value)
        if value != 0 and gf2_mul(value, inverse, 8, 0x1D) != 1:
            raise AssertionError("the selected 8-bit polynomial is not a field")
        sbox.append(inverse ^ rot_left(inverse, 8, 2) ^ rot_left(inverse, 8, 5) ^ 0xA7)
    if len(set(sbox)) != 256:
        raise AssertionError("the S-box must be a permutation")
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox

S_BOX, INV_S_BOX = _generate_sbox()

def sub_bytes(val: int, num_bits: int, inverse: bool = False) -> int:
    """Byte-wise table lookup using the oatside S-box or its inverse."""
    table = INV_S_BOX if inverse else S_BOX
    
    full_bytes = num_bits // 8
    rem_bits = num_bits % 8
    
    full_mask = (1 << (full_bytes * 8)) - 1
    lower_val = val & full_mask
    rem_val = val >> (full_bytes * 8)
    
    if full_bytes > 0:
        val_bytes = int_to_bytes(lower_val, full_bytes)
        substituted = bytes(table[b] for b in val_bytes)
        lower_res = bytes_to_int(substituted)
    else:
        lower_res = 0
        
    return (rem_val << (full_bytes * 8)) | lower_res


def add_round_key(val: int, key: int) -> int:
    """Bitwise XOR with round key."""
    return val ^ key

def sbox_compress(val: int, in_bits: int, out_bits: int) -> int:
    """
    S-box compression transforming in_bits into out_bits (in_bits > out_bits).
    Uses non-linear byte folding and bit extraction.
    """
    sub_val = sub_bytes(val, in_bits)
    mask_out = (1 << out_bits) - 1
    res = 0
    shift = 0
    curr_in = in_bits
    while curr_in > 0:
        chunk_bits = min(curr_in, out_bits)
        chunk = (sub_val >> (curr_in - chunk_bits)) & ((1 << chunk_bits) - 1)
        res ^= (chunk << shift)
        shift = (shift + 3) % out_bits
        curr_in -= chunk_bits
    return res & mask_out

@lru_cache(maxsize=4096)
def _sha_key_words(round_key: int, key_bits: int) -> Tuple[int, ...]:
    key_bytes = int_to_bytes(round_key, (key_bits + 7) // 8)
    words = []
    for i in range(64):
        w = 0
        for b in key_bytes + i.to_bytes(2, byteorder='big'):
            w = (w * 31 + S_BOX[(b + i) % 256]) & 0xFFFFFFFF
        words.append(w)
    return tuple(words)


def _load_native():
    if os.environ.get("OATSIDE_NO_NATIVE"):
        return None
    name = (
        "oatside_sha.dll" if sys.platform.startswith("win")
        else "liboatside_sha.dylib" if sys.platform == "darwin"
        else "liboatside_sha.so"
    )
    path = Path(__file__).resolve().parent / "native" / name
    try:
        lib = ctypes.CDLL(str(path))
        lib.oatside_compress.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_char_p]
        lib.oatside_compress.restype = None
        return lib.oatside_compress
    except (OSError, AttributeError):
        return None


_NATIVE_COMPRESS = _load_native()


@lru_cache(maxsize=4096)
def _native_key_words(round_key: int, key_bits: int):
    return (ctypes.c_uint32 * 64)(*_sha_key_words(round_key, key_bits))


def custom_sha256(
    data_val: int,
    data_bits: int,
    round_key: int,
    key_bits: int,
    output_bits: int | None = None,
) -> int:

    if output_bits is None:
        output_bits = data_bits
    if not 1 <= output_bits <= 256:
        raise ValueError("output_bits must be between 1 and 256")

    # Mask inputs to fit within their specified bit bounds
    data_val &= (1 << data_bits) - 1
    round_key &= (1 << key_bits) - 1

    # 1. K_t words derived from round_key (cached: the same keys serve every block)
    k_custom = _sha_key_words(round_key, key_bits)

    # 2. Convert data_val into 512-bit message block (padded)
    msg_bytes = int_to_bytes(data_val, (data_bits + 7) // 8)
    block = bytearray(64)
    for i in range(min(len(msg_bytes), 56)):
        block[i] = msg_bytes[i]
    block[56:64] = (data_bits).to_bytes(8, byteorder='big')

    if _NATIVE_COMPRESS is not None:
        out = ctypes.create_string_buffer(32)
        _NATIVE_COMPRESS(bytes(block), _native_key_words(round_key, key_bits), out)
        return (int.from_bytes(out.raw, "big") >> (256 - output_bits)) & ((1 << output_bits) - 1)

    # 3. Message schedule W_0 ... W_15 expanded to W_63
    # Rotations are written inline; this function dominates the cipher's runtime.
    m = 0xFFFFFFFF
    w_sched = list(struct.unpack(">16I", block)) + [0] * 48
    for t in range(16, 64):
        x = w_sched[t-15]
        y = w_sched[t-2]
        s0 = (((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3)) & m
        s1 = (((y >> 17) | (y << 15)) ^ ((y >> 19) | (y << 13)) ^ (y >> 10)) & m
        w_sched[t] = (w_sched[t-16] + s0 + w_sched[t-7] + s1) & m

    # 4. Initial Hash Values
    a, b, c, d, e, f, g, h = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    )

    # 5. 64-Round Compression Loop with swapped K_custom constants
    for t in range(64):
        S1 = (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) & m
        ch = ((e & f) ^ ((~e) & g)) & m
        temp1 = (h + S1 + ch + k_custom[t] + w_sched[t]) & m
        S0 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) & m
        maj = ((a & b) ^ (a & c) ^ (b & c)) & m
        temp2 = (S0 + maj) & m

        h = g
        g = f
        f = e
        e = (d + temp1) & m
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & m

    out_hash = concat_bits([
        (a, 32), (b, 32), (c, 32), (d, 32),
        (e, 32), (f, 32), (g, 32), (h, 32)
    ])
    
    mask = (1 << output_bits) - 1
    return (out_hash >> (256 - output_bits)) & mask
