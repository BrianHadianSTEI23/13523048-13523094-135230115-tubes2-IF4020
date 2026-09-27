from typing import Tuple, List, Dict
from config.params import BlockConfig, get_config
from src.bit_utils import (
    slice_bits_msb,
    concat_bits,
)
from src.sbox_spn import (
    sub_bytes,
    shift_rows,
    mix_columns,
    add_round_key,
    sbox_compress,
    sbox_expand,
    custom_sha256,
)
from src.keygen import derive_round_subkeys

def split_block_6_parts(block_val: int, cfg: BlockConfig) -> Tuple[int, int, int, int, int, int]:
    """Slices input block into 6 proportional parts according to the block scheme[cite: 2]."""
    b = cfg.block_bits
    out_l = slice_bits_msb(block_val, b, 0, cfg.outer_bits)
    offset = cfg.outer_bits
    
    l1 = slice_bits_msb(block_val, b, offset, cfg.l1_bits)
    offset += cfg.l1_bits
    
    l2 = slice_bits_msb(block_val, b, offset, cfg.l2_bits)
    offset += cfg.l2_bits
    
    r1 = slice_bits_msb(block_val, b, offset, cfg.r1_bits)
    offset += cfg.r1_bits
    
    r2 = slice_bits_msb(block_val, b, offset, cfg.r2_bits)
    offset += cfg.r2_bits
    
    out_r = slice_bits_msb(block_val, b, offset, cfg.outer_bits)
    return out_l, l1, l2, r1, r2, out_r

def feistel_left(l1: int, l2: int, cfg: BlockConfig, key2: int, key3: int) -> Tuple[int, int]:
    """Left Feistel network step with Custom SHA-256 blocks[cite: 2]."""
    # Top custom SHA-256 with Key 3
    sha_out3 = custom_sha256(l2, cfg.l2_bits, key3, cfg.block_bits)
    l1_prime = (l1 + sha_out3) & ((1 << cfg.l1_bits) - 1)
    
    # Bottom custom SHA-256 with Key 2
    sha_out2 = custom_sha256(l1_prime, cfg.l1_bits, key2, cfg.block_bits)
    l2_prime = l2 ^ sha_out2
    
    return l1_prime, l2_prime

def inv_feistel_left(l1_prime: int, l2_prime: int, cfg: BlockConfig, key2: int, key3: int) -> Tuple[int, int]:
    """Inverse of Left Feistel network step."""
    sha_out2 = custom_sha256(l1_prime, cfg.l1_bits, key2, cfg.block_bits)
    l2 = l2_prime ^ sha_out2
    
    sha_out3 = custom_sha256(l2, cfg.l2_bits, key3, cfg.block_bits)
    l1 = (l1_prime - sha_out3) & ((1 << cfg.l1_bits) - 1)
    return l1, l2

def feistel_right(r1: int, r2: int, cfg: BlockConfig, key4: int, key5: int) -> Tuple[int, int]:
    """Right Feistel network step with Custom SHA-256 blocks[cite: 2]."""
    # Top custom SHA-256 with Key 4
    sha_out4 = custom_sha256(r1, cfg.r1_bits, key4, cfg.block_bits)
    r2_prime = (r2 + sha_out4) & ((1 << cfg.r2_bits) - 1)
    
    # Bottom custom SHA-256 with Key 5
    sha_out5 = custom_sha256(r2_prime, cfg.r2_bits, key5, cfg.block_bits)
    r1_prime = r1 ^ sha_out5
    
    return r1_prime, r2_prime

def inv_feistel_right(r1_prime: int, r2_prime: int, cfg: BlockConfig, key4: int, key5: int) -> Tuple[int, int]:
    """Inverse of Right Feistel network step."""
    sha_out5 = custom_sha256(r2_prime, cfg.r2_bits, key5, cfg.block_bits)
    r1 = r1_prime ^ sha_out5
    
    sha_out4 = custom_sha256(r1, cfg.r1_bits, key4, cfg.block_bits)
    r2 = (r2_prime - sha_out4) & ((1 << cfg.r2_bits) - 1)
    return r1, r2

# def encrypt_round(
#     out_l: int, l1: int, l2: int, r1: int, r2: int, out_r: int,
#     subkeys: Dict[str, int], cfg: BlockConfig
# ) -> Tuple[int, int, int, int, int, int]:
#     """Executes single round iteration of Function F[cite: 2]."""
#     k1, k2, k3, k4, k5 = subkeys['Key1'], subkeys['Key2'], subkeys['Key3'], subkeys['Key4'], subkeys['Key5']
    
#     # 1. Feistel round 1
#     l1_p, l2_p = feistel_left(l1, l2, cfg, k2, k3)
#     r1_p, r2_p = feistel_right(r1, r2, cfg, k4, k5)
    
#     l_merged = concat_bits([(l1_p, cfg.l1_bits), (l2_p, cfg.l2_bits)])
#     r_merged = concat_bits([(r1_p, cfg.r1_bits), (r2_p, cfg.r2_bits)])
    
#     # 2. Outer SPN & Compress S1/S2
#     out_l_spn = shift_rows(sub_bytes(out_l, cfg.outer_bits), cfg.outer_bits)
#     out_r_spn = shift_rows(sub_bytes(out_r, cfg.outer_bits), cfg.outer_bits)
    
#     s1_comp = sbox_compress(l_merged, cfg.merged_l_bits, cfg.outer_bits)
#     s2_comp = sbox_compress(r_merged, cfg.merged_r_bits, cfg.outer_bits)
    
#     out_l_xor = out_l_spn ^ s1_comp
#     out_r_xor = out_r_spn ^ s2_comp
    
#     # 3. Outer MixColumns & S3/S4 Expand
#     out_l_mix = mix_columns(out_l_xor, cfg.outer_bits)
#     out_r_mix = mix_columns(out_r_xor, cfg.outer_bits)
    
#     l_exp = sbox_expand(l_merged, cfg.merged_l_bits, cfg.merged_l_bits)
#     r_exp = sbox_expand(r_merged, cfg.merged_r_bits, cfg.merged_r_bits)
    
#     l1_next = slice_bits_msb(l_exp, cfg.merged_l_bits, 0, cfg.l1_bits)
#     l2_next = slice_bits_msb(l_exp, cfg.merged_l_bits, cfg.l1_bits, cfg.l2_bits)
#     r1_next = slice_bits_msb(r_exp, cfg.merged_r_bits, 0, cfg.r1_bits)
#     r2_next = slice_bits_msb(r_exp, cfg.merged_r_bits, cfg.r1_bits, cfg.r2_bits)
    
#     # 4. Feistel round 2
#     l1_p2, l2_p2 = feistel_left(l1_next, l2_next, cfg, k2, k3)
#     r1_p2, r2_p2 = feistel_right(r1_next, r2_next, cfg, k4, k5)
    
#     l_merged2 = concat_bits([(l1_p2, cfg.l1_bits), (l2_p2, cfg.l2_bits)])
#     r_merged2 = concat_bits([(r1_p2, cfg.r1_bits), (r2_p2, cfg.r2_bits)])
    
#     # 5. AddRoundKey & Final Compress/Expand
#     out_l_key = add_round_key(out_l_mix, slice_bits_msb(k1, cfg.block_bits, 0, cfg.outer_bits))
#     out_r_key = add_round_key(out_r_mix, slice_bits_msb(k1, cfg.block_bits, cfg.block_bits - cfg.outer_bits, cfg.outer_bits))
    
#     s1_comp2 = sbox_compress(l_merged2, cfg.merged_l_bits, cfg.outer_bits)
#     s2_comp2 = sbox_compress(r_merged2, cfg.merged_r_bits, cfg.outer_bits)
    
#     out_l_final = out_l_key ^ s1_comp2
#     out_r_final = out_r_key ^ s2_comp2
    
#     l_final_exp = sbox_expand(s1_comp2, cfg.outer_bits, cfg.merged_l_bits)
#     r_final_exp = sbox_expand(s2_comp2, cfg.outer_bits, cfg.merged_r_bits)
    
#     l1_out = slice_bits_msb(l_final_exp, cfg.merged_l_bits, 0, cfg.l1_bits)
#     l2_out = slice_bits_msb(l_final_exp, cfg.merged_l_bits, cfg.l1_bits, cfg.l2_bits)
#     r1_out = slice_bits_msb(r_final_exp, cfg.merged_r_bits, 0, cfg.r1_bits)
#     r2_out = slice_bits_msb(r_final_exp, cfg.merged_r_bits, cfg.r1_bits, cfg.r2_bits)
    
#     return out_l_final, l1_out, l2_out, r1_out, r2_out, out_r_final

def encrypt_round(
    out_l: int, l1: int, l2: int, r1: int, r2: int, out_r: int,
    subkeys: Dict[str, int], cfg: BlockConfig
) -> Tuple[int, int, int, int, int, int]:
    """Executes single round iteration of Function F."""
    k1, k2, k3, k4, k5 = subkeys['Key1'], subkeys['Key2'], subkeys['Key3'], subkeys['Key4'], subkeys['Key5']
    
    # 1. Feistel round 1
    l1_p, l2_p = feistel_left(l1, l2, cfg, k2, k3)
    r1_p, r2_p = feistel_right(r1, r2, cfg, k4, k5)
    
    l_merged = concat_bits([(l1_p, cfg.l1_bits), (l2_p, cfg.l2_bits)])
    r_merged = concat_bits([(r1_p, cfg.r1_bits), (r2_p, cfg.r2_bits)])
    
    # 2. Outer SPN & Compress S1/S2
    out_l_spn = shift_rows(sub_bytes(out_l, cfg.outer_bits), cfg.outer_bits)
    out_r_spn = shift_rows(sub_bytes(out_r, cfg.outer_bits), cfg.outer_bits)
    
    s1_comp = sbox_compress(l_merged, cfg.merged_l_bits, cfg.outer_bits)
    s2_comp = sbox_compress(r_merged, cfg.merged_r_bits, cfg.outer_bits)
    
    out_l_xor = out_l_spn ^ s1_comp
    out_r_xor = out_r_spn ^ s2_comp
    
    # 3. Outer MixColumns
    out_l_mix = mix_columns(out_l_xor, cfg.outer_bits)
    out_r_mix = mix_columns(out_r_xor, cfg.outer_bits)
    
    # 4. Feistel round 2
    l1_p2, l2_p2 = feistel_left(l1_p, l2_p, cfg, k2, k3)
    r1_p2, r2_p2 = feistel_right(r1_p, r2_p, cfg, k4, k5)
    
    l_merged2 = concat_bits([(l1_p2, cfg.l1_bits), (l2_p2, cfg.l2_bits)])
    r_merged2 = concat_bits([(r1_p2, cfg.r1_bits), (r2_p2, cfg.r2_bits)])
    
    # 5. AddRoundKey & Final Compress
    out_l_key = add_round_key(out_l_mix, slice_bits_msb(k1, cfg.block_bits, 0, cfg.outer_bits))
    out_r_key = add_round_key(out_r_mix, slice_bits_msb(k1, cfg.block_bits, cfg.block_bits - cfg.outer_bits, cfg.outer_bits))
    
    s1_comp2 = sbox_compress(l_merged2, cfg.merged_l_bits, cfg.outer_bits)
    s2_comp2 = sbox_compress(r_merged2, cfg.merged_r_bits, cfg.outer_bits)
    
    out_l_final = out_l_key ^ s1_comp2
    out_r_final = out_r_key ^ s2_comp2
    
    return out_l_final, l1_p2, l2_p2, r1_p2, r2_p2, out_r_final

def encrypt_block(plaintext: int, master_key: int, iv: int, block_bits: int, num_rounds: int = 20) -> int:
    """Encrypts a single block of size block_bits[cite: 2]."""
    cfg = get_config(block_bits)
    round_subkeys = derive_round_subkeys(master_key, num_rounds, block_bits)
    
    # Initial IV XOR whitening across sub-blocks[cite: 2]
    initial_val = plaintext ^ iv
    out_l, l1, l2, r1, r2, out_r = split_block_6_parts(initial_val, cfg)
    
    for r in range(num_rounds):
        out_l, l1, l2, r1, r2, out_r = encrypt_round(
            out_l, l1, l2, r1, r2, out_r, round_subkeys[r], cfg
        )
        
    return concat_bits([
        (out_l, cfg.outer_bits),
        (l1, cfg.l1_bits),
        (l2, cfg.l2_bits),
        (r1, cfg.r1_bits),
        (r2, cfg.r2_bits),
        (out_r, cfg.outer_bits),
    ])

# def decrypt_block(ciphertext: int, master_key: int, iv: int, block_bits: int, num_rounds: int = 20) -> int:
#     """Decrypts a single block of size block_bits."""
#     cfg = get_config(block_bits)
#     round_subkeys = derive_round_subkeys(master_key, num_rounds, block_bits)
    
#     out_l, l1, l2, r1, r2, out_r = split_block_6_parts(ciphertext, cfg)
    
#     # Reverse round execution from num_rounds-1 down to 0
#     for r in range(num_rounds - 1, -1, -1):
#         # Feistel rounds run symmetrically using inverse Feistel functions
#         k = round_subkeys[r]
#         k1, k2, k3, k4, k5 = k['Key1'], k['Key2'], k['Key3'], k['Key4'], k['Key5']
        
#         # Reverse Step 5 & 4
#         l_merged2 = concat_bits([(l1, cfg.l1_bits), (l2, cfg.l2_bits)])
#         r_merged2 = concat_bits([(r1, cfg.r1_bits), (r2, cfg.r2_bits)])
        
#         s1_comp2 = sbox_compress(l_merged2, cfg.merged_l_bits, cfg.outer_bits)
#         s2_comp2 = sbox_compress(r_merged2, cfg.merged_r_bits, cfg.outer_bits)
        
#         out_l_key = out_l ^ s1_comp2
#         out_r_key = out_r ^ s2_comp2
        
#         out_l_mix = add_round_key(out_l_key, slice_bits_msb(k1, cfg.block_bits, 0, cfg.outer_bits))
#         out_r_mix = add_round_key(out_r_key, slice_bits_msb(k1, cfg.block_bits, cfg.block_bits - cfg.outer_bits, cfg.outer_bits))
        
#         # Reverse Feistel round 2
#         l1_next, l2_next = inv_feistel_left(l1, l2, cfg, k2, k3)
#         r1_next, r2_next = inv_feistel_right(r1, r2, cfg, k4, k5)
        
#         l_exp = concat_bits([(l1_next, cfg.l1_bits), (l2_next, cfg.l2_bits)])
#         r_exp = concat_bits([(r1_next, cfg.r1_bits), (r2_next, cfg.r2_bits)])
        
#         l_merged = sbox_compress(l_exp, cfg.merged_l_bits, cfg.merged_l_bits)
#         r_merged = sbox_compress(r_exp, cfg.merged_r_bits, cfg.merged_r_bits)
        
#         # Reverse Step 3 & 2
#         out_l_xor = mix_columns(out_l_mix, cfg.outer_bits)
#         out_r_xor = mix_columns(out_r_mix, cfg.outer_bits)
        
#         s1_comp = sbox_compress(l_merged, cfg.merged_l_bits, cfg.outer_bits)
#         s2_comp = sbox_compress(r_merged, cfg.merged_r_bits, cfg.outer_bits)
        
#         out_l_spn = out_l_xor ^ s1_comp
#         out_r_spn = out_r_xor ^ s2_comp
        
#         out_l = sub_bytes(shift_rows(out_l_spn, cfg.outer_bits, inverse=True), cfg.outer_bits, inverse=True)
#         out_r = sub_bytes(shift_rows(out_r_spn, cfg.outer_bits, inverse=True), cfg.outer_bits, inverse=True)
        
#         # Reverse Feistel round 1
#         l1_m = slice_bits_msb(l_merged, cfg.merged_l_bits, 0, cfg.l1_bits)
#         l2_m = slice_bits_msb(l_merged, cfg.merged_l_bits, cfg.l1_bits, cfg.l2_bits)
#         r1_m = slice_bits_msb(r_merged, cfg.merged_r_bits, 0, cfg.r1_bits)
#         r2_m = slice_bits_msb(r_merged, cfg.merged_r_bits, cfg.r1_bits, cfg.r2_bits)
        
#         l1, l2 = inv_feistel_left(l1_m, l2_m, cfg, k2, k3)
#         r1, r2 = inv_feistel_right(r1_m, r2_m, cfg, k4, k5)

#     reconstructed = concat_bits([
#         (out_l, cfg.outer_bits),
#         (l1, cfg.l1_bits),
#         (l2, cfg.l2_bits),
#         (r1, cfg.r1_bits),
#         (r2, cfg.r2_bits),
#         (out_r, cfg.outer_bits),
#     ])
    
#     return reconstructed ^ iv

def decrypt_block(ciphertext: int, master_key: int, iv: int, block_bits: int, num_rounds: int = 20) -> int:
    """Decrypts a single block of size block_bits."""
    cfg = get_config(block_bits)
    round_subkeys = derive_round_subkeys(master_key, num_rounds, block_bits)
    
    out_l, l1, l2, r1, r2, out_r = split_block_6_parts(ciphertext, cfg)
    
    for r in range(num_rounds - 1, -1, -1):
        k = round_subkeys[r]
        k1, k2, k3, k4, k5 = k['Key1'], k['Key2'], k['Key3'], k['Key4'], k['Key5']
        
        # Reverse Step 5
        l_merged2 = concat_bits([(l1, cfg.l1_bits), (l2, cfg.l2_bits)])
        r_merged2 = concat_bits([(r1, cfg.r1_bits), (r2, cfg.r2_bits)])
        
        s1_comp2 = sbox_compress(l_merged2, cfg.merged_l_bits, cfg.outer_bits)
        s2_comp2 = sbox_compress(r_merged2, cfg.merged_r_bits, cfg.outer_bits)
        
        out_l_key = out_l ^ s1_comp2
        out_r_key = out_r ^ s2_comp2
        
        out_l_mix = add_round_key(out_l_key, slice_bits_msb(k1, cfg.block_bits, 0, cfg.outer_bits))
        out_r_mix = add_round_key(out_r_key, slice_bits_msb(k1, cfg.block_bits, cfg.block_bits - cfg.outer_bits, cfg.outer_bits))
        
        # Reverse Step 4 (Feistel round 2)
        l1_p, l2_p = inv_feistel_left(l1, l2, cfg, k2, k3)
        r1_p, r2_p = inv_feistel_right(r1, r2, cfg, k4, k5)
        
        # Reverse Step 3 & 2
        out_l_xor = mix_columns(out_l_mix, cfg.outer_bits, inverse=True)
        out_r_xor = mix_columns(out_r_mix, cfg.outer_bits, inverse=True)
        
        l_merged = concat_bits([(l1_p, cfg.l1_bits), (l2_p, cfg.l2_bits)])
        r_merged = concat_bits([(r1_p, cfg.r1_bits), (r2_p, cfg.r2_bits)])
        
        s1_comp = sbox_compress(l_merged, cfg.merged_l_bits, cfg.outer_bits)
        s2_comp = sbox_compress(r_merged, cfg.merged_r_bits, cfg.outer_bits)
        
        out_l_spn = out_l_xor ^ s1_comp
        out_r_spn = out_r_xor ^ s2_comp
        
        out_l = sub_bytes(shift_rows(out_l_spn, cfg.outer_bits, inverse=True), cfg.outer_bits, inverse=True)
        out_r = sub_bytes(shift_rows(out_r_spn, cfg.outer_bits, inverse=True), cfg.outer_bits, inverse=True)
        
        # Reverse Step 1 (Feistel round 1)
        l1, l2 = inv_feistel_left(l1_p, l2_p, cfg, k2, k3)
        r1, r2 = inv_feistel_right(r1_p, r2_p, cfg, k4, k5)

    reconstructed = concat_bits([
        (out_l, cfg.outer_bits),
        (l1, cfg.l1_bits),
        (l2, cfg.l2_bits),
        (r1, cfg.r1_bits),
        (r2, cfg.r2_bits),
        (out_r, cfg.outer_bits),
    ])
    
    return reconstructed ^ iv