import inspect
import os
import random
import tempfile
import unittest

from src.cipher_core import decrypt_block, encrypt_block
from src import modes


class TestHandoffContract(unittest.TestCase):
    KEY = 0x0F1E2D3C4B5A6978
    IV = bytes.fromhex("1234567890abcdef")

    def test_public_round_defaults_match_core(self):
        self.assertEqual(inspect.signature(encrypt_block).parameters["num_rounds"].default, 16)
        self.assertEqual(inspect.signature(decrypt_block).parameters["num_rounds"].default, 16)
        for name in (
            "encrypt_ecb", "decrypt_ecb", "encrypt_cbc", "decrypt_cbc",
            "encrypt_cfb", "decrypt_cfb", "encrypt_ofb", "decrypt_ofb",
            "encrypt_ctr", "decrypt_ctr", "encrypt_file", "decrypt_file",
        ):
            with self.subTest(function=name):
                self.assertEqual(
                    inspect.signature(getattr(modes, name)).parameters["num_rounds"].default,
                    16,
                )

    def test_iv_and_counter_must_be_exactly_one_block(self):
        for mode in ("cbc", "cfb", "ofb", "ctr"):
            for bad_iv in (b"", self.IV[:-1], self.IV + b"x"):
                with self.subTest(mode=mode, iv_len=len(bad_iv)):
                    encrypt = getattr(modes, f"encrypt_{mode}")
                    decrypt = getattr(modes, f"decrypt_{mode}")
                    with self.assertRaises(ValueError):
                        encrypt(b"payload", self.KEY, bad_iv)
                    with self.assertRaises(ValueError):
                        decrypt(b"payload", self.KEY, bad_iv)

    def test_ctr_rejects_counter_wrap(self):
        with self.assertRaises(ValueError):
            modes.encrypt_ctr(b"x" * 9, self.KEY, b"\xff" * 8)
        with self.assertRaises(ValueError):
            modes.decrypt_ctr(b"x" * 9, self.KEY, b"\xff" * 8)

    def test_modes_match_independent_block_equations(self):
        plaintext = b"abcdefghijklmnop"
        p0, p1 = plaintext[:8], plaintext[8:]
        iv_int = int.from_bytes(self.IV, "big")

        def e(value):
            return encrypt_block(value, self.KEY, 0, 64, 16).to_bytes(8, "big")

        xor = lambda left, right: bytes(a ^ b for a, b in zip(left, right))
        ecb = e(int.from_bytes(p0, "big")) + e(int.from_bytes(p1, "big"))
        c0 = e(int.from_bytes(xor(p0, self.IV), "big"))
        cbc = c0 + e(int.from_bytes(xor(p1, c0), "big"))
        stream0 = e(iv_int)
        cfb0 = xor(p0, stream0)
        cfb = cfb0 + xor(p1, e(int.from_bytes(cfb0, "big")))
        ofb = xor(p0, stream0) + xor(p1, e(int.from_bytes(stream0, "big")))
        ctr = xor(p0, stream0) + xor(p1, e(iv_int + 1))

        self.assertEqual(modes.encrypt_ecb(plaintext, self.KEY)[:16], ecb)
        self.assertEqual(modes.encrypt_cbc(plaintext, self.KEY, self.IV)[:16], cbc)
        self.assertEqual(modes.encrypt_cfb(plaintext, self.KEY, self.IV), cfb)
        self.assertEqual(modes.encrypt_ofb(plaintext, self.KEY, self.IV), ofb)
        self.assertEqual(modes.encrypt_ctr(plaintext, self.KEY, self.IV), ctr)

    def test_binary_boundary_lengths_all_modes_and_sizes(self):
        rng = random.Random(4020)
        for bits in (64, 96, 128, 192):
            width = bits // 8
            key = rng.getrandbits(bits)
            iv = rng.randbytes(width)
            for length in (0, 1, width - 1, width, width + 1):
                data = rng.randbytes(length)
                for mode in ("ecb", "cbc", "cfb", "ofb", "ctr"):
                    with self.subTest(bits=bits, length=length, mode=mode):
                        encrypt = getattr(modes, f"encrypt_{mode}")
                        decrypt = getattr(modes, f"decrypt_{mode}")
                        args = (data, key) if mode == "ecb" else (data, key, iv)
                        ciphertext = encrypt(*args, block_bits=bits, num_rounds=2)
                        dec_args = (ciphertext, key) if mode == "ecb" else (ciphertext, key, iv)
                        self.assertEqual(decrypt(*dec_args, block_bits=bits, num_rounds=2), data)

    def test_file_api_requires_recoverable_iv(self):
        with tempfile.TemporaryDirectory() as directory:
            source = os.path.join(directory, "input.bin")
            output = os.path.join(directory, "output.bin")
            with open(source, "wb") as stream:
                stream.write(b"binary\x00\xff")
            with self.assertRaises(ValueError):
                modes.encrypt_file(source, output, self.KEY, mode="CBC", iv=None)
            self.assertFalse(os.path.exists(output))

    def test_rejects_malformed_padded_ciphertext_and_same_file(self):
        for mode in ("ecb", "cbc"):
            decrypt = getattr(modes, f"decrypt_{mode}")
            args = (self.KEY,) if mode == "ecb" else (self.KEY, self.IV)
            for ciphertext in (b"", b"x", b"x" * 9):
                with self.subTest(mode=mode, length=len(ciphertext)):
                    with self.assertRaises(ValueError):
                        decrypt(ciphertext, *args)
        with tempfile.TemporaryDirectory() as directory:
            source = os.path.join(directory, "input.bin")
            data = b"must not be overwritten"
            with open(source, "wb") as stream:
                stream.write(data)
            with self.assertRaises(ValueError):
                modes.encrypt_file(source, source, self.KEY, mode="ECB")
            with open(source, "rb") as stream:
                self.assertEqual(stream.read(), data)

    def test_wrong_key_does_not_recover_original_plaintext(self):
        plaintext = b"wrong-key regression\x00\xff"
        wrong_key = self.KEY ^ 1
        for mode in ("ecb", "cbc", "cfb", "ofb", "ctr"):
            with self.subTest(mode=mode):
                encrypt = getattr(modes, f"encrypt_{mode}")
                decrypt = getattr(modes, f"decrypt_{mode}")
                extra = () if mode == "ecb" else (self.IV,)
                ciphertext = encrypt(plaintext, self.KEY, *extra)
                try:
                    recovered = decrypt(ciphertext, wrong_key, *extra)
                except ValueError:
                    if mode not in ("ecb", "cbc"):
                        raise
                else:
                    self.assertNotEqual(recovered, plaintext)

    def test_ecb_and_cbc_reject_corrupt_padding_contents(self):
        malformed = b"ABCDEF\x01\x02"
        with self.assertRaises(ValueError):
            modes.pkcs7_unpad(malformed, 8)

        ecb_ciphertext = encrypt_block(int.from_bytes(malformed, "big"), self.KEY, 0, 64)
        with self.assertRaises(ValueError):
            modes.decrypt_ecb(ecb_ciphertext.to_bytes(8, "big"), self.KEY)

        cbc_input = int.from_bytes(malformed, "big") ^ int.from_bytes(self.IV, "big")
        cbc_ciphertext = encrypt_block(cbc_input, self.KEY, 0, 64)
        with self.assertRaises(ValueError):
            modes.decrypt_cbc(cbc_ciphertext.to_bytes(8, "big"), self.KEY, self.IV)

    def test_same_key_and_iv_produce_same_ciphertext(self):
        plaintext = b"deterministic\x00\xff data"
        for mode in ("ecb", "cbc", "cfb", "ofb", "ctr"):
            with self.subTest(mode=mode):
                encrypt = getattr(modes, f"encrypt_{mode}")
                extra = () if mode == "ecb" else (self.IV,)
                first = encrypt(plaintext, self.KEY, *extra)
                self.assertEqual(encrypt(plaintext, self.KEY, *extra), first)

    def test_repeated_plaintext_blocks_show_expected_mode_behavior(self):
        plaintext = b"REPEATED" * 3
        for mode in ("ecb", "cbc", "cfb", "ofb", "ctr"):
            with self.subTest(mode=mode):
                encrypt = getattr(modes, f"encrypt_{mode}")
                extra = () if mode == "ecb" else (self.IV,)
                ciphertext = encrypt(plaintext, self.KEY, *extra)
                blocks = [ciphertext[i : i + 8] for i in (0, 8, 16)]
                if mode == "ecb":
                    self.assertEqual(blocks[0], blocks[1])
                    self.assertEqual(blocks[1], blocks[2])
                else:
                    self.assertEqual(len(set(blocks)), 3)


if __name__ == "__main__":
    unittest.main()
