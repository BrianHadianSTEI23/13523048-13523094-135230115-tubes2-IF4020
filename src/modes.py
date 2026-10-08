import os
from typing import Optional
from src.bit_utils import bytes_to_int, int_to_bytes
from src.cipher_core import encrypt_block, decrypt_block


def _validate_iv(iv: bytes, block_bytes: int) -> None:
    if not isinstance(iv, bytes) or len(iv) != block_bytes:
        raise ValueError(f"IV/counter must be exactly {block_bytes} bytes")


def _validate_file_paths(input_filepath: str, output_filepath: str) -> None:
    input_path = os.path.normcase(os.path.realpath(input_filepath))
    output_path = os.path.normcase(os.path.realpath(output_filepath))
    if input_path == output_path or (
        os.path.exists(input_filepath)
        and os.path.exists(output_filepath)
        and os.path.samefile(input_filepath, output_filepath)
    ):
        raise ValueError("input and output paths must be different")


def _validate_padded_ciphertext(ciphertext: bytes, block_bytes: int) -> None:
    if not ciphertext or len(ciphertext) % block_bytes:
        raise ValueError("ciphertext must be non-empty and block-aligned")


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Pads byte data to a multiple of block_size using PKCS#7 standard."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    """Removes PKCS#7 padding from decrypted byte data."""
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid data length for unpadding")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding length byte")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding sequence")
    return data[:-pad_len]


# --- Modes of Operation ---

def encrypt_ecb(
    plaintext: bytes, master_key: int, block_bits: int = 64, num_rounds: int = 16
) -> bytes:
    """Electronic Codebook (ECB) Mode Encryption."""
    block_bytes = block_bits // 8
    padded = pkcs7_pad(plaintext, block_bytes)
    ciphertext = bytearray()
    
    for i in range(0, len(padded), block_bytes):
        p_int = bytes_to_int(padded[i : i + block_bytes])
        c_int = encrypt_block(p_int, master_key, 0, block_bits, num_rounds)
        ciphertext.extend(int_to_bytes(c_int, block_bytes))
        
    return bytes(ciphertext)


def decrypt_ecb(
    ciphertext: bytes, master_key: int, block_bits: int = 64, num_rounds: int = 16
) -> bytes:
    """Electronic Codebook (ECB) Mode Decryption."""
    block_bytes = block_bits // 8
    _validate_padded_ciphertext(ciphertext, block_bytes)
    plaintext = bytearray()
    
    for i in range(0, len(ciphertext), block_bytes):
        c_int = bytes_to_int(ciphertext[i : i + block_bytes])
        p_int = decrypt_block(c_int, master_key, 0, block_bits, num_rounds)
        plaintext.extend(int_to_bytes(p_int, block_bytes))
        
    return pkcs7_unpad(bytes(plaintext), block_bytes)


def encrypt_cbc(
    plaintext: bytes, master_key: int, iv: bytes, block_bits: int = 64, num_rounds: int = 16
) -> bytes:
    """Cipher Block Chaining (CBC) Mode Encryption."""
    block_bytes = block_bits // 8
    _validate_iv(iv, block_bytes)
    padded = pkcs7_pad(plaintext, block_bytes)
    ciphertext = bytearray()
    prev_block = bytes_to_int(iv)
    
    for i in range(0, len(padded), block_bytes):
        p_int = bytes_to_int(padded[i : i + block_bytes])
        input_int = p_int ^ prev_block
        c_int = encrypt_block(input_int, master_key, 0, block_bits, num_rounds)
        ciphertext.extend(int_to_bytes(c_int, block_bytes))
        prev_block = c_int
        
    return bytes(ciphertext)


def decrypt_cbc(
    ciphertext: bytes, master_key: int, iv: bytes, block_bits: int = 64, num_rounds: int = 16
) -> bytes:
    """Cipher Block Chaining (CBC) Mode Decryption."""
    block_bytes = block_bits // 8
    _validate_iv(iv, block_bytes)
    _validate_padded_ciphertext(ciphertext, block_bytes)
    plaintext = bytearray()
    prev_block = bytes_to_int(iv)
    
    for i in range(0, len(ciphertext), block_bytes):
        c_int = bytes_to_int(ciphertext[i : i + block_bytes])
        dec_int = decrypt_block(c_int, master_key, 0, block_bits, num_rounds)
        p_int = dec_int ^ prev_block
        plaintext.extend(int_to_bytes(p_int, block_bytes))
        prev_block = c_int
        
    return pkcs7_unpad(bytes(plaintext), block_bytes)


def encrypt_cfb(
    plaintext: bytes, master_key: int, iv: bytes, block_bits: int = 64, num_rounds: int = 16
) -> bytes:
    """Cipher Feedback (CFB) Mode Encryption."""
    block_bytes = block_bits // 8
    _validate_iv(iv, block_bytes)
    ciphertext = bytearray()
    shift_reg = bytes_to_int(iv)
    
    for i in range(0, len(plaintext), block_bytes):
        chunk = plaintext[i : i + block_bytes]
        keystream_int = encrypt_block(shift_reg, master_key, 0, block_bits, num_rounds)
        keystream_bytes = int_to_bytes(keystream_int, block_bytes)
        c_chunk = bytes(p ^ k for p, k in zip(chunk, keystream_bytes[: len(chunk)]))
        ciphertext.extend(c_chunk)
        if len(c_chunk) == block_bytes:
            shift_reg = bytes_to_int(c_chunk)
            
    return bytes(ciphertext)


def decrypt_cfb(
    ciphertext: bytes, master_key: int, iv: bytes, block_bits: int = 64, num_rounds: int = 16
) -> bytes:
    """Cipher Feedback (CFB) Mode Decryption."""
    block_bytes = block_bits // 8
    _validate_iv(iv, block_bytes)
    plaintext = bytearray()
    shift_reg = bytes_to_int(iv)
    
    for i in range(0, len(ciphertext), block_bytes):
        chunk = ciphertext[i : i + block_bytes]
        keystream_int = encrypt_block(shift_reg, master_key, 0, block_bits, num_rounds)
        keystream_bytes = int_to_bytes(keystream_int, block_bytes)
        p_chunk = bytes(c ^ k for c, k in zip(chunk, keystream_bytes[: len(chunk)]))
        plaintext.extend(p_chunk)
        if len(chunk) == block_bytes:
            shift_reg = bytes_to_int(chunk)
            
    return bytes(plaintext)


def encrypt_ofb(
    plaintext: bytes, master_key: int, iv: bytes, block_bits: int = 64, num_rounds: int = 16
) -> bytes:
    """Output Feedback (OFB) Mode Encryption."""
    block_bytes = block_bits // 8
    _validate_iv(iv, block_bytes)
    ciphertext = bytearray()
    shift_reg = bytes_to_int(iv)
    
    for i in range(0, len(plaintext), block_bytes):
        chunk = plaintext[i : i + block_bytes]
        shift_reg = encrypt_block(shift_reg, master_key, 0, block_bits, num_rounds)
        keystream_bytes = int_to_bytes(shift_reg, block_bytes)
        c_chunk = bytes(p ^ k for p, k in zip(chunk, keystream_bytes[: len(chunk)]))
        ciphertext.extend(c_chunk)
        
    return bytes(ciphertext)


def decrypt_ofb(
    ciphertext: bytes, master_key: int, iv: bytes, block_bits: int = 64, num_rounds: int = 16
) -> bytes:
    """Output Feedback (OFB) Mode Decryption."""
    return encrypt_ofb(ciphertext, master_key, iv, block_bits, num_rounds)


def encrypt_ctr(
    plaintext: bytes, master_key: int, nonce: bytes, block_bits: int = 64, num_rounds: int = 16
) -> bytes:
    """Counter (CTR) Mode Encryption."""
    block_bytes = block_bits // 8
    _validate_iv(nonce, block_bytes)
    ciphertext = bytearray()
    nonce_int = bytes_to_int(nonce)
    block_count = (len(plaintext) + block_bytes - 1) // block_bytes
    if block_count and nonce_int + block_count - 1 >= 1 << block_bits:
        raise ValueError("CTR counter would wrap")
    counter = 0
    
    for i in range(0, len(plaintext), block_bytes):
        chunk = plaintext[i : i + block_bytes]
        ctr_val = nonce_int + counter
        keystream_int = encrypt_block(ctr_val, master_key, 0, block_bits, num_rounds)
        keystream_bytes = int_to_bytes(keystream_int, block_bytes)
        c_chunk = bytes(p ^ k for p, k in zip(chunk, keystream_bytes[: len(chunk)]))
        ciphertext.extend(c_chunk)
        counter += 1
        
    return bytes(ciphertext)


def decrypt_ctr(
    ciphertext: bytes, master_key: int, nonce: bytes, block_bits: int = 64, num_rounds: int = 16
) -> bytes:
    """Counter (CTR) Mode Decryption."""
    return encrypt_ctr(ciphertext, master_key, nonce, block_bits, num_rounds)


# --- High-Level File Encryption/Decryption ---

def encrypt_file(
    input_filepath: str,
    output_filepath: str,
    master_key: int,
    mode: str = "CBC",
    block_bits: int = 64,
    iv: Optional[bytes] = None,
    num_rounds: int = 16,
) -> None:
    """Encrypts a file and writes the ciphertext to output_filepath."""
    _validate_file_paths(input_filepath, output_filepath)
    if mode.upper() in ("CBC", "CFB", "OFB", "CTR"):
        _validate_iv(iv, block_bits // 8)

    with open(input_filepath, "rb") as f:
        plaintext = f.read()

    mode_upper = mode.upper()
    if mode_upper == "ECB":
        ciphertext = encrypt_ecb(plaintext, master_key, block_bits, num_rounds)
    elif mode_upper == "CBC":
        ciphertext = encrypt_cbc(plaintext, master_key, iv, block_bits, num_rounds)
    elif mode_upper == "CFB":
        ciphertext = encrypt_cfb(plaintext, master_key, iv, block_bits, num_rounds)
    elif mode_upper == "OFB":
        ciphertext = encrypt_ofb(plaintext, master_key, iv, block_bits, num_rounds)
    elif mode_upper == "CTR":
        ciphertext = encrypt_ctr(plaintext, master_key, iv, block_bits, num_rounds)
    else:
        raise ValueError(f"Unsupported mode: {mode}")

    with open(output_filepath, "wb") as f:
        f.write(ciphertext)


def decrypt_file(
    input_filepath: str,
    output_filepath: str,
    master_key: int,
    mode: str = "CBC",
    block_bits: int = 64,
    iv: Optional[bytes] = None,
    num_rounds: int = 16,
) -> None:
    """Decrypts a file and writes the plaintext to output_filepath."""
    _validate_file_paths(input_filepath, output_filepath)
    if mode.upper() in ("CBC", "CFB", "OFB", "CTR"):
        _validate_iv(iv, block_bits // 8)
    with open(input_filepath, "rb") as f:
        ciphertext = f.read()

    mode_upper = mode.upper()
    if mode_upper == "ECB":
        plaintext = decrypt_ecb(ciphertext, master_key, block_bits, num_rounds)
    elif mode_upper == "CBC":
        plaintext = decrypt_cbc(ciphertext, master_key, iv, block_bits, num_rounds)
    elif mode_upper == "CFB":
        plaintext = decrypt_cfb(ciphertext, master_key, iv, block_bits, num_rounds)
    elif mode_upper == "OFB":
        plaintext = decrypt_ofb(ciphertext, master_key, iv, block_bits, num_rounds)
    elif mode_upper == "CTR":
        plaintext = decrypt_ctr(ciphertext, master_key, iv, block_bits, num_rounds)
    else:
        raise ValueError(f"Unsupported mode: {mode}")

    with open(output_filepath, "wb") as f:
        f.write(plaintext)
