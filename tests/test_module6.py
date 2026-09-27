import unittest
import os
import tempfile
from src.cli import run_cli, parse_hex_or_int, parse_hex_bytes


class TestModule6(unittest.TestCase):
    def test_parse_hex_helpers(self):
        self.assertEqual(parse_hex_or_int("0xDEADBEEF"), 0xDEADBEEF)
        self.assertEqual(parse_hex_or_int("12345"), 12345)
        self.assertEqual(parse_hex_bytes("0x1234567812345678", 8), b"\x12\x34\x56\x78\x12\x34\x56\x78")

    def test_cli_end_to_end_cbc(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_file = os.path.join(tmp_dir, "test.txt")
            enc_file = os.path.join(tmp_dir, "test.enc")
            dec_file = os.path.join(tmp_dir, "test_dec.txt")

            content = b"End-to-End CLI Pipeline Test Verification Content!"
            with open(input_file, "wb") as f:
                f.write(content)

            key_str = "0xDEADBEEF12345678"
            iv_str = "0x1234567887654321"

            # Encrypt via CLI runner
            enc_args = [
                "encrypt",
                "-i", input_file,
                "-o", enc_file,
                "-k", key_str,
                "-m", "CBC",
                "-b", "64",
                "--iv", iv_str,
            ]
            exit_code = run_cli(enc_args)
            self.assertEqual(exit_code, 0)
            self.assertTrue(os.path.exists(enc_file))

            # Decrypt via CLI runner
            dec_args = [
                "decrypt",
                "-i", enc_file,
                "-o", dec_file,
                "-k", key_str,
                "-m", "CBC",
                "-b", "64",
                "--iv", iv_str,
            ]
            exit_code = run_cli(dec_args)
            self.assertEqual(exit_code, 0)

            with open(dec_file, "rb") as f:
                decrypted_content = f.read()

            self.assertEqual(content, decrypted_content)

    def test_cli_end_to_end_ctr(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_file = os.path.join(tmp_dir, "data.bin")
            enc_file = os.path.join(tmp_dir, "data.enc")
            dec_file = os.path.join(tmp_dir, "data_out.bin")

            content = os.urandom(256)
            with open(input_file, "wb") as f:
                f.write(content)

            key_str = "0x0123456789ABCDEF0123456789ABCDEF"
            nonce_str = "0x00000000000000010000000000000001"

            # Encrypt 128-bit CTR mode
            enc_args = [
                "encrypt",
                "-i", input_file,
                "-o", enc_file,
                "-k", key_str,
                "-m", "CTR",
                "-b", "128",
                "--iv", nonce_str,
            ]
            self.assertEqual(run_cli(enc_args), 0)

            # Decrypt 128-bit CTR mode
            dec_args = [
                "decrypt",
                "-i", enc_file,
                "-o", dec_file,
                "-k", key_str,
                "-m", "CTR",
                "-b", "128",
                "--iv", nonce_str,
            ]
            self.assertEqual(run_cli(dec_args), 0)

            with open(dec_file, "rb") as f:
                self.assertEqual(f.read(), content)


if __name__ == "__main__":
    unittest.main()