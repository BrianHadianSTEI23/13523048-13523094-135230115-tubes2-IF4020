import argparse
import os
import sys
from typing import List, Optional
from src.modes import encrypt_file, decrypt_file


def parse_hex_or_int(val_str: str) -> int:
    """Parses a hex string (0x...) or decimal integer string into an integer."""
    val_str = val_str.strip()
    if val_str.lower().startswith("0x"):
        return int(val_str, 16)
    return int(val_str)


def parse_hex_bytes(val_str: str, expected_len: int) -> bytes:
    """Parses a hex string into a bytes object of required length."""
    val_str = val_str.strip()
    if val_str.lower().startswith("0x"):
        val_str = val_str[2:]
    if len(val_str) != expected_len * 2:
        raise ValueError(f"value must contain exactly {expected_len * 2} hex digits")
    try:
        raw_bytes = bytes.fromhex(val_str)
    except ValueError as error:
        raise ValueError("value must be valid hexadecimal") from error
    return raw_bytes


def validate_master_key(master_key: int, block_bits: int) -> None:
    if master_key < 0 or master_key >= (1 << block_bits):
        raise ValueError(f"master key must fit in exactly {block_bits} bits")


def parse_master_key(value: str, block_bits: int) -> int:
    stripped = value.strip()
    if stripped.lower().startswith("0x"):
        digits = stripped[2:]
        expected_digits = block_bits // 4
        if len(digits) != expected_digits:
            raise ValueError(
                f"hex master key must contain exactly {expected_digits} hex digits"
            )
        try:
            master_key = int(digits, 16)
        except ValueError as error:
            raise ValueError("master key must be valid hexadecimal") from error
    else:
        master_key = parse_hex_or_int(stripped)
    validate_master_key(master_key, block_bits)
    return master_key


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="OATSIDE block cipher file encryption and decryption"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for cmd in ["encrypt", "decrypt"]:
        sub = subparsers.add_parser(cmd, help=f"{cmd.capitalize()} an input file")
        sub.add_argument(
            "-i", "--input", required=True, help="Path to input file"
        )
        sub.add_argument(
            "-o", "--output", required=True, help="Path to output file"
        )
        sub.add_argument(
            "-k",
            "--key",
            required=True,
            help="Master key (hex integer string, e.g., 0xDEADBEEF12345678)",
        )
        sub.add_argument(
            "-m",
            "--mode",
            default="CBC",
            choices=["ECB", "CBC", "CFB", "OFB", "CTR"],
            help="Cipher mode of operation (default: CBC)",
        )
        sub.add_argument(
            "-b",
            "--block-bits",
            type=int,
            default=64,
            choices=[64, 96, 128, 192],
            help="Block size in bits (default: 64)",
        )
        sub.add_argument(
            "--iv",
            help="Initialization Vector / Nonce in hex (e.g., 0x1234567812345678)",
        )
        sub.add_argument(
            "-r",
            "--rounds",
            type=int,
            default=16,
            help="Number of encryption rounds (default: 16)",
        )

    return parser


def run_cli(args_list: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(args_list)

    try:
        master_key = parse_master_key(args.key, args.block_bits)
        block_bytes = args.block_bits // 8

        if args.rounds < 1:
            raise ValueError("rounds must be at least 1")

        iv_bytes = None
        if args.iv:
            iv_bytes = parse_hex_bytes(args.iv, block_bytes)

        if args.mode == "ECB" and iv_bytes is not None:
            raise ValueError("ECB mode does not use --iv")
        if args.mode != "ECB" and iv_bytes is None:
            label = "counter" if args.mode == "CTR" else "IV"
            raise ValueError(f"{label} is required for {args.mode} mode")

        input_path = os.path.normcase(os.path.realpath(args.input))
        output_path = os.path.normcase(os.path.realpath(args.output))
        if input_path == output_path or (
            os.path.exists(args.input)
            and os.path.exists(args.output)
            and os.path.samefile(args.input, args.output)
        ):
            raise ValueError("input and output paths must be different")

        if args.command == "encrypt":
            encrypt_file(
                input_filepath=args.input,
                output_filepath=args.output,
                master_key=master_key,
                mode=args.mode,
                block_bits=args.block_bits,
                iv=iv_bytes,
                num_rounds=args.rounds,
            )
            print(f"[+] File successfully encrypted -> {args.output}")

        elif args.command == "decrypt":
            decrypt_file(
                input_filepath=args.input,
                output_filepath=args.output,
                master_key=master_key,
                mode=args.mode,
                block_bits=args.block_bits,
                iv=iv_bytes,
                num_rounds=args.rounds,
            )
            print(f"[+] File successfully decrypted -> {args.output}")

        return 0

    except Exception as e:
        print(f"[-] Error executing operation: {e}", file=sys.stderr)
        return 1
