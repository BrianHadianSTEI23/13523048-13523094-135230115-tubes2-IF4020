# OATSIDE API Documentation

OATSIDE is an experimental block cipher implemented in Python. This page documents the **local Python API** in `src/cipher_core.py` and `src/modes.py`. 

## Requirements and imports

- Python 3.10 or later.
- No third-party packages are required for the cipher or modes.
- Run the examples from the repository root so Python can find the `src` and `config` packages.

```python
from src.modes import encrypt_cbc, decrypt_cbc
```

## How to use the program

### Option 1: Run the command-line program

Opent terminal in the repository folder (the folder containing `main.py`). 

Check that Python is available and view the program's help:

```powershell
python --version
python main.py --help
```

Create a small text file to try:

```powershell
Set-Content -NoNewline -Encoding ascii message.txt "Hello from OATSIDE"
```

Encrypt it with CBC mode and a 64-bit block:

```powershell
python main.py encrypt -i message.txt -o message.enc -k 0x1234567890ABCDEF -m CBC --iv 0x8765432187654321
```

If successful, the program prints a message saying the file was encrypted and creates `message.enc`. Decrypt it using the **same key, mode, block size, and IV**:

```powershell
python main.py decrypt -i message.enc -o restored.txt -k 0x1234567890ABCDEF -m CBC --iv 0x8765432187654321
```

Confirm that decryption restored the original text:

```powershell
Get-Content restored.txt
```

It should print `Hello from OATSIDE`. The command-line options are `-i` for the input path, `-o` for the output path, `-k` for the key, `-m` for the mode, `-b` for the block size in bits, `--iv` for the IV or initial counter, and `-r` for the number of rounds. The defaults are CBC, 64-bit blocks, and 16 rounds. ECB does not use an IV; CBC, CFB, OFB, and CTR require one. For example, ECB encryption is:

```powershell
python main.py encrypt -i message.txt -o message.enc -k 0x1234567890ABCDEF -m ECB
```

For a 64-bit block, the hexadecimal key and IV each need 16 hex digits (the `0x` prefix is optional). For other block sizes, the key and IV must match the selected block size. The input and output paths must be different. The IV/counter is not stored in the output file, so keep it for decryption.

### Option 2: Use the Python API

From the repository root, import a mode function, provide the data as `bytes` and the key as an integer, then call the matching decryption function with the same key and IV:

```python
from src.modes import encrypt_cbc, decrypt_cbc

key = 0x1234567890ABCDEF
iv = bytes.fromhex("8765432187654321") 
message = b"Secret message"

ciphertext = encrypt_cbc(message, key, iv)
print("Ciphertext:", ciphertext.hex())

restored = decrypt_cbc(ciphertext, key, iv)
print("Decrypted:", restored.decode("utf-8"))
```

To encrypt and decrypt a file from Python, use `encrypt_file` and `decrypt_file` from `src.modes`. They take input and output file paths, a key, a mode, the block size, and an optional IV as `bytes`:

```python
from src.modes import encrypt_file, decrypt_file

key = 0x1234567890ABCDEF
iv = bytes.fromhex("8765432187654321")

encrypt_file("message.txt", "message.enc", key, mode="CBC", iv=iv)
decrypt_file("message.enc", "restored.txt", key, mode="CBC", iv=iv)
```

Use `mode="ECB"` and omit `iv` for ECB. For other modes, provide an IV; CTR treats it as the starting counter. The mode functions return ciphertext or plaintext as `bytes`. The file functions write the result to the specified output path and return `None`.

## Block cipher modes

Mode functions accept and return `bytes`; the key is a Python integer. Supported block sizes are 64, 96, 128, and 192 bits. The default block size is 64 bits, and the default number of rounds is 16.

| Function | Input parameters | Output |
|---|---|---|
| `encrypt_ecb(plaintext, master_key, block_bits=64, num_rounds=16)` | `plaintext: bytes`, `master_key: int`, `block_bits: int`, `num_rounds: int` | Ciphertext as `bytes`; PKCS#7 padding is added |
| `decrypt_ecb(ciphertext, master_key, block_bits=64, num_rounds=16)` | `ciphertext: bytes`, `master_key: int`, `block_bits: int`, `num_rounds: int` | Plaintext as `bytes`, with padding removed |
| `encrypt_cbc(plaintext, master_key, iv, block_bits=64, num_rounds=16)` | `plaintext: bytes`, `master_key: int`, `iv: bytes`, `block_bits: int`, `num_rounds: int` | Ciphertext as `bytes`; PKCS#7 padding is added |
| `decrypt_cbc(ciphertext, master_key, iv, block_bits=64, num_rounds=16)` | `ciphertext: bytes`, `master_key: int`, `iv: bytes`, `block_bits: int`, `num_rounds: int` | Plaintext as `bytes`, with padding removed |
| `encrypt_cfb(plaintext, master_key, iv, block_bits=64, num_rounds=16)` | `plaintext: bytes`, `master_key: int`, `iv: bytes`, `block_bits: int`, `num_rounds: int` | Ciphertext as `bytes`, the same length as the plaintext |
| `decrypt_cfb(ciphertext, master_key, iv, block_bits=64, num_rounds=16)` | `ciphertext: bytes`, `master_key: int`, `iv: bytes`, `block_bits: int`, `num_rounds: int` | Plaintext as `bytes` |
| `encrypt_ofb(plaintext, master_key, iv, block_bits=64, num_rounds=16)` | `plaintext: bytes`, `master_key: int`, `iv: bytes`, `block_bits: int`, `num_rounds: int` | Ciphertext as `bytes`, the same length as the plaintext |
| `decrypt_ofb(ciphertext, master_key, iv, block_bits=64, num_rounds=16)` | `ciphertext: bytes`, `master_key: int`, `iv: bytes`, `block_bits: int`, `num_rounds: int` | Plaintext as `bytes` |
| `encrypt_ctr(plaintext, master_key, nonce, block_bits=64, num_rounds=16)` | `plaintext: bytes`, `master_key: int`, `nonce: bytes`, `block_bits: int`, `num_rounds: int` | Ciphertext as `bytes`, the same length as the plaintext |
| `decrypt_ctr(ciphertext, master_key, nonce, block_bits=64, num_rounds=16)` | `ciphertext: bytes`, `master_key: int`, `nonce: bytes`, `block_bits: int`, `num_rounds: int` | Plaintext as `bytes` |

`master_key` is an unsigned integer that fits the block size (`0 <= master_key < 2**block_bits`). `iv` and `nonce` must be `bytes` with a length of exactly `block_bits / 8`. In CTR mode, `nonce` is the initial big-endian counter value; the counter is incremented for each block, and the function rejects a counter that would exceed the block limit.

ECB and CBC use PKCS#7 padding. They add a full block of padding when the input length is already a multiple of the block size. CFB, OFB, and CTR handle a partial final block without padding. ECB does not use an IV.

## Block API

`src.cipher_core` provides these functions:

```python
encrypt_block(plaintext: int, master_key: int, iv: int,
              block_bits: int, num_rounds: int = 16) -> int
decrypt_block(ciphertext: int, master_key: int, iv: int,
              block_bits: int, num_rounds: int = 16) -> int
```

Inputs and outputs are integers representing one block. `plaintext` or `ciphertext`, `master_key`, and `iv` must be within the unsigned range for the selected block size; `num_rounds` must be a positive integer. In the core functions, `iv` is an XOR input-whitening value. The mode functions pass zero to the core because they handle the IV at the mode layer.

## Usage example

This CBC example uses a 64-bit block. The IV is eight bytes decoded from hexadecimal; save the same IV for decryption.

```python
from src.modes import encrypt_cbc, decrypt_cbc

key = 0x1234567890ABCDEF
iv = bytes.fromhex("8765432187654321")
message = b"Secret message"

ciphertext = encrypt_cbc(message, key, iv)
restored = decrypt_cbc(ciphertext, key, iv)

assert restored == message
print(ciphertext.hex())
```

ECB does not require an IV:

```python
from src.modes import encrypt_ecb, decrypt_ecb

key = 0x1234567890ABCDEF
ciphertext = encrypt_ecb(b"Example", key)
plaintext = decrypt_ecb(ciphertext, key)
```

## File operations

`src.modes` also provides:

```python
encrypt_file(input_filepath: str, output_filepath: str, master_key: int,
             mode: str = "CBC", block_bits: int = 64,
             iv: bytes | None = None, num_rounds: int = 16) -> None
decrypt_file(input_filepath: str, output_filepath: str, master_key: int,
             mode: str = "CBC", block_bits: int = 64,
             iv: bytes | None = None, num_rounds: int = 16) -> None
```

These functions read and write binary files and return no value (`None`). `mode` accepts `ECB`, `CBC`, `CFB`, `OFB`, or `CTR` (case-insensitive). An `iv` is required for every mode except ECB; in CTR mode, it is used as the initial counter. Input and output paths must be different. Validation and I/O failures are raised as Python exceptions, primarily `ValueError` and the built-in file-operation exceptions.

## Errors and security notes

Unsupported block sizes, invalid IV/counter lengths, non-positive round counts, out-of-range keys or blocks, empty or misaligned ECB/CBC ciphertext, invalid padding, and CTR counter overflow raise `ValueError`.


## References

- [Project README](https://github.com/BrianHadianSTEI23/13523048-13523094-135230115-tubes2-IF4020/blob/main/README.md)
