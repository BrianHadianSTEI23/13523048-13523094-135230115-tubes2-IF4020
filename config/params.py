from dataclasses import dataclass
from typing import Dict, Tuple

@dataclass(frozen=True)
class BlockConfig:
    block_bits: int
    half_bits: int          # L, R half block (0.5 * B)
    outer_bits: int         # Outer left/right branches (3/16 * B)
    l1_bits: int            # Sub-block L1 (1/16 * B)
    l2_bits: int            # Sub-block L2 (4/16 * B)
    r1_bits: int            # Sub-block R1 (3/16 * B)
    r2_bits: int            # Sub-block R2 (2/16 * B)
    merged_l_bits: int      # Merged L = L1 + L2 (5/16 * B)
    merged_r_bits: int      # Merged R = R1 + R2 (5/16 * B)
    s1_expand_bits: int     # KeyGen S1 expand (0.75 * B)
    s2_shrink_bits: int     # KeyGen S2 shrink (0.25 * B)
    round_s_compress: Tuple[int, int]  # (5/16 * B, 3/16 * B)
    round_s_expand: Tuple[int, int]    # (3/16 * B, 5/16 * B)
    gf_poly_low: int        # Low terms of irreducible polynomial for GF(2^B)

BLOCK_CONFIGS: Dict[int, BlockConfig] = {
    64: BlockConfig(
        block_bits=64,
        half_bits=32,
        outer_bits=12,
        l1_bits=4,
        l2_bits=16,
        r1_bits=12,
        r2_bits=8,
        merged_l_bits=20,
        merged_r_bits=20,
        s1_expand_bits=48,
        s2_shrink_bits=16,
        round_s_compress=(20, 12),
        round_s_expand=(12, 20),
        gf_poly_low=0x1B,  # x^4 + x^3 + x + 1
    ),
    96: BlockConfig(
        block_bits=96,
        half_bits=48,
        outer_bits=18,
        l1_bits=6,
        l2_bits=24,
        r1_bits=18,
        r2_bits=12,
        merged_l_bits=30,
        merged_r_bits=30,
        s1_expand_bits=72,
        s2_shrink_bits=24,
        round_s_compress=(30, 18),
        round_s_expand=(18, 30),
        gf_poly_low=0x641,  # x^10 + x^9 + x^6 + 1
    ),
    128: BlockConfig(
        block_bits=128,
        half_bits=64,
        outer_bits=24,
        l1_bits=8,
        l2_bits=32,
        r1_bits=24,
        r2_bits=16,
        merged_l_bits=40,
        merged_r_bits=40,
        s1_expand_bits=96,
        s2_shrink_bits=32,
        round_s_compress=(40, 24),
        round_s_expand=(24, 40),
        gf_poly_low=0x87,  # x^7 + x^2 + x + 1
    ),
    192: BlockConfig(
        block_bits=192,
        half_bits=96,
        outer_bits=36,
        l1_bits=12,
        l2_bits=48,
        r1_bits=36,
        r2_bits=24,
        merged_l_bits=60,
        merged_r_bits=60,
        s1_expand_bits=144,
        s2_shrink_bits=48,
        round_s_compress=(60, 36),
        round_s_expand=(36, 60),
        gf_poly_low=0x87,  # x^7 + x^2 + x + 1
    ),
}

def get_config(block_bits: int) -> BlockConfig:
    if block_bits not in BLOCK_CONFIGS:
        raise ValueError(f"Unsupported block size: {block_bits}. Supported sizes: {list(BLOCK_CONFIGS.keys())}")
    return BLOCK_CONFIGS[block_bits]