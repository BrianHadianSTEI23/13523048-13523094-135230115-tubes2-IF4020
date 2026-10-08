from typing import List, Dict
from config.params import BlockConfig, get_config
from src.bit_utils import diffuse_state_bits, rot_left
from src.sbox_spn import sub_bytes


def _round_constant(index: int, cfg: BlockConfig) -> int:
    """Public B-bit constant, distinct over the supported first 20 rounds."""
    byte_count = cfg.block_bits // 8
    return int.from_bytes(
        bytes((0x9D + index + 0x3D * position) & 0xFF for position in range(byte_count)),
        "big",
    )


def _domain_subkey(round_key: int, cfg: BlockConfig, domain: int) -> int:
    """Derive one working key for a Feistel call from the primary round key."""
    if domain not in (2, 3, 4, 5):
        raise ValueError("domain must be 2, 3, 4, or 5")
    byte_count = cfg.block_bits // 8
    domain_word = int.from_bytes(bytes([(0x35 * domain) & 0xFF]) * byte_count, "big")
    return sub_bytes(rot_left(round_key, cfg.block_bits, 7 * domain) ^ domain_word, cfg.block_bits)

def generate_keys(master_key: int, count: int, block_bits: int) -> List[int]:
    """Generate ``count`` sequential primary B-bit round keys."""
    cfg = get_config(block_bits)
    limit = 1 << block_bits
    if not isinstance(master_key, int) or isinstance(master_key, bool) or not 0 <= master_key < limit:
        raise ValueError(f"master_key must be a {block_bits}-bit unsigned integer")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise ValueError("count must be a non-negative integer")
    state = master_key
    keys: List[int] = []
    for index in range(count):
        state = rot_left(state, block_bits, 11) ^ _round_constant(index, cfg)
        state = sub_bytes(state, block_bits)
        state = diffuse_state_bits(state, block_bits)
        keys.append(state)
    return keys

def derive_round_subkeys(master_key: int, num_rounds: int, block_bits: int) -> List[Dict[str, int]]:
    """Expose one primary round key and four domain-separated working keys."""
    if not isinstance(num_rounds, int) or isinstance(num_rounds, bool) or num_rounds < 1:
        raise ValueError("num_rounds must be a positive integer")
    cfg = get_config(block_bits)
    round_keys = generate_keys(master_key, num_rounds, block_bits)
    result: List[Dict[str, int]] = []
    for round_key in round_keys:
        result.append({
            "RoundKey": round_key,
            "Key1": round_key,
            "Key2": _domain_subkey(round_key, cfg, 2),
            "Key3": _domain_subkey(round_key, cfg, 3),
            "Key4": _domain_subkey(round_key, cfg, 4),
            "Key5": _domain_subkey(round_key, cfg, 5),
        })
    return result
