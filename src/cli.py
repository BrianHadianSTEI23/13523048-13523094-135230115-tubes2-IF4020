import argparse
import sys
import os
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
    if len(val_str) % 2 != 0:
        val_str = "0" + val_str
    raw_bytes = bytes.fromhex(val_str)
    if len(raw_bytes) < expected_len:
        raw_bytes = raw_bytes.rjust(expected_len, b"\x00")
    elif len(raw_bytes) > expected_len:
        raw_bytes = raw_bytes[-expected_len:]
    return raw_bytes


def build_parser() -> argparse.ArgumentParser:
    """Constructs the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Custom Hybrid Feistel-SPN Block Cipher CLI Tool"
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
            default=20,
            help="Number of encryption rounds (default: 20)",
        )

    return parser


def run_cli(args_list: Optional[List[str]] = None) -> int:
    """Executes the CLI pipeline based on provided arguments."""
    parser = build_parser()
    args = parser.parse_args(args_list)

    try:
        master_key = parse_hex_or_int(args.key)
        block_bytes = args.block_bits // 8

        iv_bytes = None
        if args.iv:
            iv_bytes = parse_hex_bytes(args.iv, block_bytes)

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