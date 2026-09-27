from typing import List, Dict
from config.params import BlockConfig, get_config
from src.bit_utils import (
    slice_bits_msb,
    gf2_mul,
)
from src.sbox_spn import (
    sbox_expand,
    sbox_compress,
)

def generate_key_step_phase_a(state: int, cfg: BlockConfig) -> int:
    """
    Phase A of KeyGen cycle[cite: 1]:
    Left branch (L) -> S1-box (expand to 0.75*B)[cite: 1].
    Right branch (R) -> S2-box (shrink to 0.25*B)[cite: 1].
    Combine via GF(2^B) multiplication[cite: 1].
    """
    b_bits = cfg.block_bits
    half_bits = cfg.half_bits
    
    # Split state into L (MSB) and R (LSB)
    l_val = slice_bits_msb(state, b_bits, 0, half_bits)
    r_val = slice_bits_msb(state, b_bits, half_bits, half_bits)
    
    # S1-box expansion and S2-box compression[cite: 1]
    s1_out = sbox_expand(l_val, half_bits, cfg.s1_expand_bits)
    s2_out = sbox_compress(r_val, half_bits, cfg.s2_shrink_bits)
    
    # GF Multiplication Modulo 2^B[cite: 1]
    return gf2_mul(s1_out, s2_out, b_bits, cfg.gf_poly_low)

def generate_key_step_phase_b(state: int, cfg: BlockConfig) -> int:
    """
    Phase B of KeyGen cycle[cite: 1]:
    Left branch (L) -> S2-box (shrink to 0.25*B)[cite: 1].
    Right branch (R) -> S1-box (expand to 0.75*B)[cite: 1].
    Combine via GF(2^B) multiplication[cite: 1].
    """
    b_bits = cfg.block_bits
    half_bits = cfg.half_bits
    
    # Split state into L (MSB) and R (LSB)
    l_val = slice_bits_msb(state, b_bits, 0, half_bits)
    r_val = slice_bits_msb(state, b_bits, half_bits, half_bits)
    
    # S2-box compression and S1-box expansion[cite: 1]
    s2_out = sbox_compress(l_val, half_bits, cfg.s2_shrink_bits)
    s1_out = sbox_expand(r_val, half_bits, cfg.s1_expand_bits)
    
    # GF Multiplication Modulo 2^B[cite: 1]
    return gf2_mul(s2_out, s1_out, b_bits, cfg.gf_poly_low)

def generate_keys(master_key: int, count: int, block_bits: int) -> List[int]:
    """
    Generates `count` B-bit round keys (Key_1, Key_2, ..., Key_count)[cite: 1]
    from a master key using the alternating KeyGen pipeline[cite: 1].
    """
    cfg = get_config(block_bits)
    mask = (1 << block_bits) - 1
    state = master_key & mask
    keys: List[int] = []
    
    for _ in range(count):
        # Two alternating cycles per output key[cite: 1]
        state = generate_key_step_phase_a(state, cfg)
        state = generate_key_step_phase_b(state, cfg)
        keys.append(state)
        
    return keys

def derive_round_subkeys(master_key: int, num_rounds: int, block_bits: int) -> List[Dict[str, int]]:
    """
    Generates subkey sets for 20 cipher rounds.
    Each round requires subkeys corresponding to Key1..Key5 in the Cipher specification[cite: 2].
    Total generated key blocks = num_rounds * 5.
    """
    cfg = get_config(block_bits)
    total_keys_needed = num_rounds * 5
    raw_keys = generate_keys(master_key, total_keys_needed, block_bits)
    
    round_subkeys = []
    for r in range(num_rounds):
        idx = r * 5
        subkeys = {
            'Key1': raw_keys[idx],
            'Key2': raw_keys[idx + 1],
            'Key3': raw_keys[idx + 2],
            'Key4': raw_keys[idx + 3],
            'Key5': raw_keys[idx + 4],
        }
        round_subkeys.append(subkeys)
        
    return round_subkeys