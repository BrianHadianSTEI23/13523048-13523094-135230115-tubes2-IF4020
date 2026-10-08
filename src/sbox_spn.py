import struct
from typing import List, Tuple
from src.bit_utils import concat_bits, rot_left, rot_right, gf2_mul, bytes_to_int, int_to_bytes

# Oatside's fixed 8-bit table is generated once, then used by table lookup.
# The field polynomial is x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
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

def custom_sha256(
    data_val: int,
    data_bits: int,
    round_key: int,
    key_bits: int,
    output_bits: int | None = None,
) -> int:
    """
    Customized SHA-256 compression function.
    Key scheduling constants K_t are dynamically replaced with key schedule
    words derived directly from round_key for each cycle/part.
    """

    if output_bits is None:
        output_bits = data_bits
    if not 1 <= output_bits <= 256:
        raise ValueError("output_bits must be between 1 and 256")

    # Mask inputs to fit within their specified bit bounds
    data_val &= (1 << data_bits) - 1
    round_key &= (1 << key_bits) - 1

    # 1. Derive 64 32-bit K_t round keys from round_key for this specific cycle/part
    k_custom = []
    key_bytes = int_to_bytes(round_key, (key_bits + 7) // 8)
    for i in range(64):
        seed = key_bytes + i.to_bytes(2, byteorder='big')
        w = 0
        for b in seed:
            w = (w * 31 + S_BOX[(b + i) % 256]) & 0xFFFFFFFF
        k_custom.append(w)

    # 2. Convert data_val into 512-bit message block (padded)
    msg_bytes = int_to_bytes(data_val, (data_bits + 7) // 8)
    block = bytearray(64)
    for i in range(min(len(msg_bytes), 56)):
        block[i] = msg_bytes[i]
    block[56:64] = (data_bits).to_bytes(8, byteorder='big')

    # 3. Message schedule W_0 ... W_15 expanded to W_63
    w_sched = [0] * 64
    for t in range(16):
        w_sched[t] = struct.unpack(">I", block[t*4:(t+1)*4])[0]
    
    for t in range(16, 64):
        s0 = (rot_right(w_sched[t-15], 32, 7) ^ rot_right(w_sched[t-15], 32, 18) ^ (w_sched[t-15] >> 3)) & 0xFFFFFFFF
        s1 = (rot_right(w_sched[t-2], 32, 17) ^ rot_right(w_sched[t-2], 32, 19) ^ (w_sched[t-2] >> 10)) & 0xFFFFFFFF
        w_sched[t] = (w_sched[t-16] + s0 + w_sched[t-7] + s1) & 0xFFFFFFFF

    # 4. Initial Hash Values
    a, b, c, d, e, f, g, h = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    )

    # 5. 64-Round Compression Loop with swapped K_custom constants
    for t in range(64):
        S1 = (rot_right(e, 32, 6) ^ rot_right(e, 32, 11) ^ rot_right(e, 32, 25)) & 0xFFFFFFFF
        ch = ((e & f) ^ ((~e) & g)) & 0xFFFFFFFF
        temp1 = (h + S1 + ch + k_custom[t] + w_sched[t]) & 0xFFFFFFFF
        S0 = (rot_right(a, 32, 2) ^ rot_right(a, 32, 13) ^ rot_right(a, 32, 22)) & 0xFFFFFFFF
        maj = ((a & b) ^ (a & c) ^ (b & c)) & 0xFFFFFFFF
        temp2 = (S0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    out_hash = concat_bits([
        (a, 32), (b, 32), (c, 32), (d, 32),
        (e, 32), (f, 32), (g, 32), (h, 32)
    ])
    
    mask = (1 << output_bits) - 1
    return (out_hash >> (256 - output_bits)) & mask
