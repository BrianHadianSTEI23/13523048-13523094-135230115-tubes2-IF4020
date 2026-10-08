from dataclasses import dataclass
from typing import Dict

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
    ),
}

def get_config(block_bits: int) -> BlockConfig:
    if not isinstance(block_bits, int) or isinstance(block_bits, bool) or block_bits not in BLOCK_CONFIGS:
        raise ValueError(f"Unsupported block size: {block_bits}. Supported sizes: {list(BLOCK_CONFIGS.keys())}")
    return BLOCK_CONFIGS[block_bits]
