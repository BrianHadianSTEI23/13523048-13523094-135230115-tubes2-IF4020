import argparse
import csv
import json
from pathlib import Path
import random
import statistics

from config.params import get_config
from src.analysis import calculate_shannon_entropy, generate_histogram
from src.modes import (
    encrypt_ecb,
    encrypt_cbc,
    encrypt_cfb,
    encrypt_ofb,
    encrypt_ctr,
)


MODES = ("ECB", "CBC", "CFB", "OFB", "CTR")


def _random_bytes(rng, count):
    return bytes(rng.getrandbits(8) for _ in range(count))


def _flip_bit(data, bit_index):
    changed = bytearray(data)
    changed[bit_index // 8] ^= 1 << (bit_index % 8)
    return bytes(changed)


def _encrypt(mode, plaintext, key, iv, block_bits, rounds):
    master_key = int.from_bytes(key, "big")
    if mode == "ECB":
        return encrypt_ecb(plaintext, master_key, block_bits, rounds)
    if mode == "CBC":
        return encrypt_cbc(plaintext, master_key, iv, block_bits, rounds)
    if mode == "CFB":
        return encrypt_cfb(plaintext, master_key, iv, block_bits, rounds)
    if mode == "OFB":
        return encrypt_ofb(plaintext, master_key, iv, block_bits, rounds)
    if mode == "CTR":
        return encrypt_ctr(plaintext, master_key, iv, block_bits, rounds)
    raise ValueError(f"Unsupported mode: {mode}")


def _summarize(bit_counts, ciphertext_bits):
    percentages = [100 * count / ciphertext_bits for count in bit_counts]
    return {
        "trials": len(bit_counts),
        "ciphertext_bits": ciphertext_bits,
        "mean_changed_bits": statistics.mean(bit_counts),
        "min_changed_bits": min(bit_counts),
        "max_changed_bits": max(bit_counts),
        "mean_percent": statistics.mean(percentages),
        "min_percent": min(percentages),
        "max_percent": max(percentages),
        "stddev_percent": statistics.pstdev(percentages),
    }


def run_experiments(block_bits=64, rounds=16, trials=16, sample_bytes=512, seed=4020):
    get_config(block_bits)
    if rounds < 1 or trials < 2 or sample_bytes < 1:
        raise ValueError("rounds must be >= 1, trials >= 2, and sample_bytes >= 1")

    block_bytes = block_bits // 8
    rng = random.Random(seed)
    histogram_key = _random_bytes(rng, block_bytes)
    histogram_iv = _random_bytes(rng, block_bytes)
    plaintext_sample = (bytes(range(block_bytes)) * ((sample_bytes + block_bytes - 1) // block_bytes))[:sample_bytes]
    plaintext_hist = generate_histogram(plaintext_sample)

    cases = []
    for _ in range(trials):
        cases.append((
            _random_bytes(rng, block_bytes),
            _random_bytes(rng, block_bytes),
            _random_bytes(rng, block_bytes),
            rng.randrange(block_bits),
            rng.randrange(block_bits),
        ))

    results = {
        "method": {
            "block_bits": block_bits,
            "rounds": rounds,
            "trials_per_mode": trials,
            "seed": seed,
            "sample_bytes": sample_bytes,
            "sample_description": f"bytes 00..{block_bytes - 1:02x} repeated, truncated to sample_bytes",
            "histogram_key_hex": histogram_key.hex(),
            "histogram_iv_or_counter_hex": histogram_iv.hex(),
            "plaintext_entropy_bits_per_byte": calculate_shannon_entropy(plaintext_sample)["entropy"],
            "avalanche_description": "One block of plaintext per trial; flip one plaintext bit or one master-key bit while holding all other inputs and IV fixed. Compare the entire ciphertext, including PKCS#7 padding blocks in ECB/CBC.",
            "interpretation": "Avalanche and entropy are measurements, not security proofs. A one-bit plaintext change in CFB/OFB/CTR changes one ciphertext bit for this one-block experiment by mode construction.",
        },
        "modes": {},
    }
    avalanche_rows = []
    histogram_rows = []

    for mode in MODES:
        plaintext_distances = []
        key_distances = []
        ciphertext_bits = None
        for trial_index, (plaintext, key, iv, plaintext_bit, key_bit) in enumerate(cases):
            baseline = _encrypt(mode, plaintext, key, iv, block_bits, rounds)
            changed_plaintext = _encrypt(mode, _flip_bit(plaintext, plaintext_bit), key, iv, block_bits, rounds)
            changed_key = _encrypt(mode, plaintext, _flip_bit(key, key_bit), iv, block_bits, rounds)
            if len(baseline) != len(changed_plaintext) or len(baseline) != len(changed_key):
                raise AssertionError("avalanche ciphertext lengths differ")
            ciphertext_bits = len(baseline) * 8
            for change, bit_index, changed, distances in (
                ("plaintext", plaintext_bit, changed_plaintext, plaintext_distances),
                ("key", key_bit, changed_key, key_distances),
            ):
                distance = sum((left ^ right).bit_count() for left, right in zip(baseline, changed))
                distances.append(distance)
                avalanche_rows.append({
                    "mode": mode,
                    "trial": trial_index,
                    "change": change,
                    "flipped_bit_index": bit_index,
                    "changed_bits": distance,
                    "ciphertext_bits": ciphertext_bits,
                    "percent": 100 * distance / ciphertext_bits,
                })

        ciphertext_sample = _encrypt(mode, plaintext_sample, histogram_key, histogram_iv, block_bits, rounds)
        ciphertext_hist = generate_histogram(ciphertext_sample)
        for byte_value in range(256):
            histogram_rows.append({
                "mode": mode,
                "byte_value": byte_value,
                "plaintext_count": plaintext_hist[byte_value],
                "ciphertext_count": ciphertext_hist[byte_value],
            })
        results["modes"][mode] = {
            "plaintext_flip": _summarize(plaintext_distances, ciphertext_bits),
            "key_flip": _summarize(key_distances, ciphertext_bits),
            "ciphertext_entropy_bits_per_byte": calculate_shannon_entropy(ciphertext_sample)["entropy"],
            "ciphertext_bytes": len(ciphertext_sample),
        }

    return results, avalanche_rows, histogram_rows


def write_results(output_dir, results, avalanche_rows, histogram_rows, plots=False):
    """Save numeric evidence, and optionally render histogram PNGs."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    for filename, rows, columns in (
        ("avalanche_trials.csv", avalanche_rows, ("mode", "trial", "change", "flipped_bit_index", "changed_bits", "ciphertext_bits", "percent")),
        ("histograms.csv", histogram_rows, ("mode", "byte_value", "plaintext_count", "ciphertext_count")),
    ):
        with (output_dir / filename).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)

    if plots:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError as error:
            raise RuntimeError("--plots requires matplotlib") from error
        for mode in MODES:
            rows = [row for row in histogram_rows if row["mode"] == mode]
            fig, axes = plt.subplots(2, 1, figsize=(11, 5), sharex=True)
            for axis, field, label in (
                (axes[0], "plaintext_count", "Plaintext count"),
                (axes[1], "ciphertext_count", "Ciphertext count"),
            ):
                axis.bar(range(256), [row[field] for row in rows], width=1)
                axis.set_ylabel(label)
            axes[1].set_xlabel("Byte value")
            fig.suptitle(f"{mode}: plaintext and ciphertext byte histograms")
            fig.tight_layout()
            fig.savefig(output_dir / f"histogram_{mode.lower()}.png", dpi=140)
            plt.close(fig)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--block-bits", type=int, choices=(64, 96, 128, 192), default=64)
    parser.add_argument("--rounds", type=int, default=16)
    parser.add_argument("--trials", type=int, default=16)
    parser.add_argument("--sample-bytes", type=int, default=512)
    parser.add_argument("--seed", type=int, default=4020)
    parser.add_argument("--output-dir", type=Path, default=Path("analysis/results"))
    parser.add_argument("--plots", action="store_true", help="generate PNGs; requires matplotlib")
    args = parser.parse_args(argv)
    try:
        results, avalanche_rows, histogram_rows = run_experiments(
            args.block_bits, args.rounds, args.trials, args.sample_bytes, args.seed
        )
        write_results(args.output_dir, results, avalanche_rows, histogram_rows, args.plots)
    except (ValueError, RuntimeError) as error:
        parser.error(str(error))
    for mode, values in results["modes"].items():
        print(
            f"{mode}: plaintext flip {values['plaintext_flip']['mean_percent']:.2f}%, "
            f"key flip {values['key_flip']['mean_percent']:.2f}%, "
            f"entropy {values['ciphertext_entropy_bits_per_byte']:.4f} bits/byte"
        )
    print(f"Saved results to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
