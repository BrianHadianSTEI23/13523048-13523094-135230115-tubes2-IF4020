from typing import Tuple, Dict
from config.params import BlockConfig, get_config
from src.bit_utils import (
    slice_bits_msb,
    concat_bits,
    diffuse_state_bits,
)
from src.sbox_spn import (
    sub_bytes,
    add_round_key,
    sbox_compress,
    custom_sha256,
)
from src.keygen import derive_round_subkeys

def split_block_6_parts(block_val: int, cfg: BlockConfig) -> Tuple[int, int, int, int, int, int]:
    """Slice a B-bit block into the six configured branches."""
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


def join_block_6_parts(
    out_l: int, l1: int, l2: int, r1: int, r2: int, out_r: int, cfg: BlockConfig
) -> int:
    return concat_bits([
        (out_l, cfg.outer_bits),
        (l1, cfg.l1_bits),
        (l2, cfg.l2_bits),
        (r1, cfg.r1_bits),
        (r2, cfg.r2_bits),
        (out_r, cfg.outer_bits),
    ])


def _validate_block_inputs(value: int, master_key: int, iv: int, cfg: BlockConfig, num_rounds: int) -> None:
    limit = 1 << cfg.block_bits
    for label, item in (("block", value), ("master_key", master_key), ("iv", iv)):
        if not isinstance(item, int) or isinstance(item, bool) or not 0 <= item < limit:
            raise ValueError(f"{label} must be a {cfg.block_bits}-bit unsigned integer")
    if not isinstance(num_rounds, int) or isinstance(num_rounds, bool) or num_rounds < 1:
        raise ValueError("num_rounds must be a positive integer")

def feistel_left(l1: int, l2: int, cfg: BlockConfig, key2: int, key3: int) -> Tuple[int, int]:
    """Invertible left-branch update using the keyed SHA-like function."""
    # Top custom SHA-256 with Key 3
    sha_out3 = custom_sha256(l2, cfg.l2_bits, key3, cfg.block_bits, cfg.l1_bits)
    l1_prime = (l1 + sha_out3) & ((1 << cfg.l1_bits) - 1)
    
    # Bottom custom SHA-256 with Key 2
    sha_out2 = custom_sha256(l1_prime, cfg.l1_bits, key2, cfg.block_bits, cfg.l2_bits)
    l2_prime = l2 ^ sha_out2
    
    return l1_prime, l2_prime

def inv_feistel_left(l1_prime: int, l2_prime: int, cfg: BlockConfig, key2: int, key3: int) -> Tuple[int, int]:
    """Inverse of Left Feistel network step."""
    sha_out2 = custom_sha256(l1_prime, cfg.l1_bits, key2, cfg.block_bits, cfg.l2_bits)
    l2 = l2_prime ^ sha_out2
    
    sha_out3 = custom_sha256(l2, cfg.l2_bits, key3, cfg.block_bits, cfg.l1_bits)
    l1 = (l1_prime - sha_out3) & ((1 << cfg.l1_bits) - 1)
    return l1, l2

def feistel_right(r1: int, r2: int, cfg: BlockConfig, key4: int, key5: int) -> Tuple[int, int]:
    """Invertible right-branch update using the keyed SHA-like function."""
    # Top custom SHA-256 with Key 4
    sha_out4 = custom_sha256(r1, cfg.r1_bits, key4, cfg.block_bits, cfg.r2_bits)
    r2_prime = (r2 + sha_out4) & ((1 << cfg.r2_bits) - 1)
    
    # Bottom custom SHA-256 with Key 5
    sha_out5 = custom_sha256(r2_prime, cfg.r2_bits, key5, cfg.block_bits, cfg.r1_bits)
    r1_prime = r1 ^ sha_out5
    
    return r1_prime, r2_prime

def inv_feistel_right(r1_prime: int, r2_prime: int, cfg: BlockConfig, key4: int, key5: int) -> Tuple[int, int]:
    """Inverse of Right Feistel network step."""
    sha_out5 = custom_sha256(r2_prime, cfg.r2_bits, key5, cfg.block_bits, cfg.r1_bits)
    r1 = r1_prime ^ sha_out5
    
    sha_out4 = custom_sha256(r1, cfg.r1_bits, key4, cfg.block_bits, cfg.r2_bits)
    r2 = (r2_prime - sha_out4) & ((1 << cfg.r2_bits) - 1)
    return r1, r2

def encrypt_round(
    out_l: int, l1: int, l2: int, r1: int, r2: int, out_r: int,
    subkeys: Dict[str, int], cfg: BlockConfig
) -> Tuple[int, int, int, int, int, int]:
    """One Feistel stage, one non-destructive compression, then outer S-box/key XOR."""
    k1, k2, k3, k4, k5 = subkeys['Key1'], subkeys['Key2'], subkeys['Key3'], subkeys['Key4'], subkeys['Key5']

    l1_p, l2_p = feistel_left(l1, l2, cfg, k2, k3)
    r1_p, r2_p = feistel_right(r1, r2, cfg, k4, k5)
    l_merged = concat_bits([(l1_p, cfg.l1_bits), (l2_p, cfg.l2_bits)])
    r_merged = concat_bits([(r1_p, cfg.r1_bits), (r2_p, cfg.r2_bits)])


    out_l_next = sub_bytes(out_l, cfg.outer_bits) ^ sbox_compress(
        l_merged, cfg.merged_l_bits, cfg.outer_bits
    )
    out_r_next = sub_bytes(out_r, cfg.outer_bits) ^ sbox_compress(
        r_merged, cfg.merged_r_bits, cfg.outer_bits
    )
    out_l_next = add_round_key(out_l_next, slice_bits_msb(k1, cfg.block_bits, 0, cfg.outer_bits))
    out_r_next = add_round_key(
        out_r_next,
        slice_bits_msb(k1, cfg.block_bits, cfg.block_bits - cfg.outer_bits, cfg.outer_bits),
    )
    return out_l_next, l1_p, l2_p, r1_p, r2_p, out_r_next


def decrypt_round(
    out_l: int, l1: int, l2: int, r1: int, r2: int, out_r: int,
    subkeys: Dict[str, int], cfg: BlockConfig
) -> Tuple[int, int, int, int, int, int]:
    """Invert ``encrypt_round`` before undoing the global diffusion layer."""
    k1, k2, k3, k4, k5 = (
        subkeys['Key1'], subkeys['Key2'], subkeys['Key3'],
        subkeys['Key4'], subkeys['Key5'],
    )
    l_merged = concat_bits([(l1, cfg.l1_bits), (l2, cfg.l2_bits)])
    r_merged = concat_bits([(r1, cfg.r1_bits), (r2, cfg.r2_bits)])
    out_l_prev = sub_bytes(
        out_l ^ sbox_compress(l_merged, cfg.merged_l_bits, cfg.outer_bits)
        ^ slice_bits_msb(k1, cfg.block_bits, 0, cfg.outer_bits),
        cfg.outer_bits, inverse=True,
    )
    out_r_prev = sub_bytes(
        out_r ^ sbox_compress(r_merged, cfg.merged_r_bits, cfg.outer_bits)
        ^ slice_bits_msb(k1, cfg.block_bits, cfg.block_bits - cfg.outer_bits, cfg.outer_bits),
        cfg.outer_bits, inverse=True,
    )
    l1_prev, l2_prev = inv_feistel_left(l1, l2, cfg, k2, k3)
    r1_prev, r2_prev = inv_feistel_right(r1, r2, cfg, k4, k5)
    return out_l_prev, l1_prev, l2_prev, r1_prev, r2_prev, out_r_prev

def encrypt_block(plaintext: int, master_key: int, iv: int, block_bits: int, num_rounds: int = 16) -> int:
    """Encrypt one fixed-width block with the oatside round function."""
    cfg = get_config(block_bits)
    _validate_block_inputs(plaintext, master_key, iv, cfg, num_rounds)
    round_subkeys = derive_round_subkeys(master_key, num_rounds, block_bits)
    
    # Legacy core argument iv acts as input whitening; modes pass zero here.
    initial_val = plaintext ^ iv
    out_l, l1, l2, r1, r2, out_r = split_block_6_parts(initial_val, cfg)
    
    for r in range(num_rounds):
        out_l, l1, l2, r1, r2, out_r = encrypt_round(
            out_l, l1, l2, r1, r2, out_r, round_subkeys[r], cfg
        )
        state = join_block_6_parts(out_l, l1, l2, r1, r2, out_r, cfg)
        state = diffuse_state_bits(state, cfg.block_bits)
        out_l, l1, l2, r1, r2, out_r = split_block_6_parts(state, cfg)
        
    return join_block_6_parts(out_l, l1, l2, r1, r2, out_r, cfg)

def decrypt_block(ciphertext: int, master_key: int, iv: int, block_bits: int, num_rounds: int = 16) -> int:
    """Decrypt a block by reversing global diffusion and each local round."""
    cfg = get_config(block_bits)
    _validate_block_inputs(ciphertext, master_key, iv, cfg, num_rounds)
    round_subkeys = derive_round_subkeys(master_key, num_rounds, block_bits)
    out_l, l1, l2, r1, r2, out_r = split_block_6_parts(ciphertext, cfg)

    for r in range(num_rounds - 1, -1, -1):
        state = join_block_6_parts(out_l, l1, l2, r1, r2, out_r, cfg)
        state = diffuse_state_bits(state, cfg.block_bits, inverse=True)
        out_l, l1, l2, r1, r2, out_r = split_block_6_parts(state, cfg)
        out_l, l1, l2, r1, r2, out_r = decrypt_round(
            out_l, l1, l2, r1, r2, out_r, round_subkeys[r], cfg
        )

    reconstructed = join_block_6_parts(out_l, l1, l2, r1, r2, out_r, cfg)
    return reconstructed ^ iv
