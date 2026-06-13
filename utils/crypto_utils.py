#!/usr/bin/env python3
"""
Cryptographic and encoding utility functions for bug bounty and security tooling.

Provides a collection of encoding, hashing, JWT parsing, entropy calculation,
and comparison functions used throughout the hunting pipeline.
"""

import base64
import hashlib
import hmac
import math
import os
import re
import secrets
import struct
import zlib
from typing import Any, Dict, List, Optional, Tuple, Union


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string, expressed in bits per symbol.

    Shannon entropy measures the unpredictability/information density of data.
    High entropy (>4.5) often indicates random tokens, secrets, or encrypted data.
    ASCII text typically scores 3.5-4.5. Base64-encoded strings score 5.5-6.0.

    Args:
        data: Input string to analyze.

    Returns:
        Entropy value in bits per symbol (0.0 to 8.0 for ASCII strings).

    Examples:
        >>> shannon_entropy("aaaaaaa")
        0.0
        >>> shannon_entropy("password")
        2.75
        >>> shannon_entropy("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") > 4.0
        True
    """
    if not data:
        return 0.0

    data = str(data)
    length = len(data)
    if length == 0:
        return 0.0

    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def base64_encode(data: Union[str, bytes]) -> str:
    """Encode data to standard Base64.

    Accepts either a string or bytes input. If a string is provided, it is
    UTF-8 encoded before Base64 encoding.

    Args:
        data: Data to encode. Strings are auto-encoded to UTF-8 bytes.

    Returns:
        Base64-encoded string (with padding).

    Raises:
        TypeError: If data is neither str nor bytes.

    Examples:
        >>> base64_encode("hello")
        'aGVsbG8='
        >>> base64_encode(b"world")
        'd29ybGQ='
    """
    if isinstance(data, str):
        data_bytes = data.encode("utf-8")
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        raise TypeError(f"Expected str or bytes, got {type(data).__name__}")

    return base64.b64encode(data_bytes).decode("ascii")


def base64_decode(data: str) -> str:
    """Decode standard Base64 string to UTF-8 string.

    Args:
        data: Base64-encoded string (with or without padding).

    Returns:
        Decoded UTF-8 string.

    Raises:
        ValueError: If the input is not valid Base64.
        TypeError: If data is not a string.

    Examples:
        >>> base64_decode("aGVsbG8=")
        'hello'
    """
    if not isinstance(data, str):
        raise TypeError(f"Expected str, got {type(data).__name__}")

    try:
        # Add padding if missing
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        decoded = base64.b64decode(data, validate=True)
    except Exception as exc:
        raise ValueError(f"Invalid Base64 input: {exc}") from exc

    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return decoded.hex()


def base64url_decode(data: str) -> str:
    """Decode Base64 URL-safe encoded string (handles JWT-style padding).

    JWT uses URL-safe Base64 without padding characters. This function handles
    both padded and unpadded input, and replaces URL-safe characters (-_) with
    standard Base64 characters (+/).

    Args:
        data: Base64 URL-safe encoded string (JWT format).

    Returns:
        Decoded UTF-8 string, or hex string if not valid UTF-8.

    Raises:
        ValueError: If the input cannot be decoded as valid Base64.

    Examples:
        >>> base64url_decode("eyJhbGciOiJIUzI1NiJ9")
        '{"alg":"HS256"}'
        >>> base64url_decode("d29ybGQ")
        'world'
    """
    if not isinstance(data, str):
        raise TypeError(f"Expected str, got {type(data).__name__}")

    # Replace URL-safe characters with standard Base64 characters
    sanitized = data.replace("-", "+").replace("_", "/")

    # Restore padding
    padding = 4 - len(sanitized) % 4
    if padding != 4:
        sanitized += "=" * padding

    try:
        decoded = base64.b64decode(sanitized, validate=True)
    except Exception as exc:
        raise ValueError(f"Invalid Base64url input: {exc}") from exc

    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return decoded.hex()


def hex_encode(data: Union[str, bytes]) -> str:
    """Encode data to hexadecimal string.

    Args:
        data: Data to encode. Strings are auto-encoded to UTF-8 bytes.

    Returns:
        Lowercase hex-encoded string.

    Raises:
        TypeError: If data is neither str nor bytes.

    Examples:
        >>> hex_encode("hello")
        '68656c6c6f'
        >>> hex_encode(b"ABC")
        '414243'
    """
    if isinstance(data, str):
        data_bytes = data.encode("utf-8")
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        raise TypeError(f"Expected str or bytes, got {type(data).__name__}")

    return data_bytes.hex()


def hex_decode(data: str) -> str:
    """Decode hexadecimal string to UTF-8 string.

    Args:
        data: Hex-encoded string.

    Returns:
        Decoded UTF-8 string, or the raw hex string if not valid UTF-8.

    Raises:
        ValueError: If the input is not valid hexadecimal.

    Examples:
        >>> hex_decode("68656c6c6f")
        'hello'
    """
    if not isinstance(data, str):
        raise TypeError(f"Expected str, got {type(data).__name__}")

    # Strip common prefixes
    cleaned = data
    if cleaned.startswith("0x") or cleaned.startswith("0X"):
        cleaned = cleaned[2:]

    # Validate hex format
    if not re.match(r"^[0-9a-fA-F]+$", cleaned):
        raise ValueError("Input is not valid hexadecimal")

    if len(cleaned) % 2 != 0:
        raise ValueError("Hex string length must be even")

    try:
        decoded = bytes.fromhex(cleaned)
    except Exception as exc:
        raise ValueError(f"Invalid hex input: {exc}") from exc

    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return decoded.hex()


def hash_string(
    data: Union[str, bytes],
    algorithm: str = "sha256",
) -> str:
    """Hash a string or bytes using the specified algorithm.

    Returns the hex-encoded digest of the input data.

    Args:
        data: Input data to hash. Strings are UTF-8 encoded before hashing.
        algorithm: Hash algorithm name. Supported:
            - 'md5' (32 hex chars)
            - 'sha1' (40 hex chars)
            - 'sha256' (64 hex chars, default)
            - 'sha512' (128 hex chars)

    Returns:
        Hex-encoded hash digest.

    Raises:
        ValueError: If the algorithm is not supported.

    Examples:
        >>> hash_string("hello", "sha256")
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
        >>> hash_string("hello", "md5")
        '5d41402abc4b2a76b9719d911017c592'
    """
    if isinstance(data, str):
        data_bytes = data.encode("utf-8")
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        raise TypeError(f"Expected str or bytes, got {type(data).__name__}")

    algorithm = algorithm.lower().replace("-", "")

    try:
        hasher = hashlib.new(algorithm)
    except ValueError:
        raise ValueError(
            f"Unsupported hash algorithm: '{algorithm}'. "
            f"Supported: md5, sha1, sha256, sha512"
        )

    hasher.update(data_bytes)
    return hasher.hexdigest()


def hash_file(path: str, algorithm: str = "sha256", chunk_size: int = 65536) -> str:
    """Hash a file on disk using the specified algorithm.

    Reads the file in chunks to handle large files without loading the entire
    file into memory.

    Args:
        path: Path to the file on disk.
        algorithm: Hash algorithm (md5, sha1, sha256, sha512).
        chunk_size: Read chunk size in bytes (default 64KB).

    Returns:
        Hex-encoded hash digest.

    Raises:
        FileNotFoundError: If the file does not exist.
        IsADirectoryError: If the path points to a directory.
        PermissionError: If the file cannot be read.
        ValueError: If the algorithm is not supported.

    Examples:
        >>> hash_file("/etc/hostname", "sha256")  # doctest: +SKIP
        'abc123...'
    """
    if not os.path.isfile(path):
        if os.path.isdir(path):
            raise IsADirectoryError(f"Path is a directory, not a file: {path}")
        raise FileNotFoundError(f"File not found: {path}")

    algorithm = algorithm.lower().replace("-", "")

    try:
        hasher = hashlib.new(algorithm)
    except ValueError:
        raise ValueError(
            f"Unsupported hash algorithm: '{algorithm}'. "
            f"Supported: md5, sha1, sha256, sha512"
        )

    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
    except OSError as exc:
        raise OSError(f"Failed to read file '{path}': {exc}") from exc

    return hasher.hexdigest()


def generate_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token.

    Uses the system's CSPRNG via the `secrets` module to produce a URL-safe
    token suitable for API keys, session tokens, and CSRF tokens.

    Args:
        length: Number of random bytes to generate (default 32, resulting in
                a ~43-character Base64 string). Minimum is 16, maximum is 256.

    Returns:
        URL-safe Base64-encoded token string (no padding).

    Raises:
        ValueError: If length is outside the allowed range (16-256).

    Examples:
        >>> token = generate_token(32)
        >>> len(token) > 40
        True
        >>> isinstance(token, str)
        True
    """
    length = int(length)
    if length < 16 or length > 256:
        raise ValueError("Token length must be between 16 and 256 bytes")

    random_bytes = secrets.token_bytes(length)
    token = base64.urlsafe_b64encode(random_bytes).rstrip(b"=").decode("ascii")
    return token


def jwt_decode(token: str, verify: bool = False) -> Dict[str, Any]:
    """Decode a JWT token without cryptographic verification.

    Extracts and decodes the header, payload, and signature from a JWT string.
    Does NOT verify the signature unless explicitly requested (which requires
    a known secret — not typically available during bug bounty recon).

    Args:
        token: The JWT string (header.payload.signature format).
        verify: If True, validates the structure but NOT the signature.

    Returns:
        Dictionary with 'header' (dict), 'payload' (dict), and 'signature' (str)
        keys.

    Raises:
        ValueError: If the token is malformed or cannot be decoded.
        TypeError: If token is not a string.

    Examples:
        >>> jwt_decode("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQc0eQ...")
        {'header': {'alg': 'HS256'}, 'payload': {'sub': '1234567890'}, 'signature': '...'}
    """
    if not isinstance(token, str):
        raise TypeError(f"Expected str, got {type(token).__name__}")

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"Invalid JWT format: expected 3 parts (header.payload.signature), "
            f"got {len(parts)}"
        )

    header_b64, payload_b64, signature_b64 = parts

    # Validate each part is non-empty
    for idx, part_name in enumerate(["header", "payload", "signature"]):
        if not parts[idx]:
            raise ValueError(f"JWT {part_name} is empty")

    import json

    header_str = base64url_decode(header_b64)
    payload_str = base64url_decode(payload_b64)

    try:
        header = json.loads(header_str)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JWT header JSON: {exc}") from exc

    try:
        payload = json.loads(payload_str)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JWT payload JSON: {exc}") from exc

    return {
        "header": header,
        "payload": payload,
        "signature": signature_b64,
    }


def jwt_parse_header(token: str) -> Dict[str, Any]:
    """Extract and decode only the header portion of a JWT.

    Args:
        token: The JWT string.

    Returns:
        Header dictionary (typically contains 'alg' and 'typ' keys).

    Raises:
        ValueError: If the token is malformed.

    Examples:
        >>> jwt_parse_header("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        {'alg': 'HS256', 'typ': 'JWT'}
    """
    result = jwt_decode(token)
    return result["header"]


def jwt_parse_payload(token: str) -> Dict[str, Any]:
    """Extract and decode only the payload portion of a JWT.

    Args:
        token: The JWT string.

    Returns:
        Payload dictionary (contains claims like sub, iat, exp, etc.).

    Raises:
        ValueError: If the token is malformed.

    Examples:
        >>> jwt_parse_payload("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0...")
        {'sub': '1234567890'}
    """
    result = jwt_decode(token)
    return result["payload"]


def detect_hash_type(hash_string: str) -> Dict[str, Any]:
    """Detect the probable hash type based on length, format, and prefix.

    Analyzes a hash string's length, character set, and common prefixes to
    identify what algorithm likely produced it. Useful when triaging leaked
    credential material or identifying hash formats during password audits.

    Args:
        hash_string: The raw hash string to analyze.

    Returns:
        Dictionary with:
            - 'hex_length': Length of the hex string (or 0 if not hex)
            - 'is_hex': True if the string is valid hexadecimal
            - 'is_bcrypt': True if it matches bcrypt format ($2b$...)
            - 'is_sha512_crypt': True if it matches SHA-512 crypt ($6$...)
            - 'is_md5_crypt': True if it matches MD5 crypt ($1$...)
            - 'candidates': List of possible hash algorithm names
            - 'format': Detection format string

    Examples:
        >>> detect_hash_type("5d41402abc4b2a76b9719d911017c592")
        {'hex_length': 32, 'is_hex': True, 'is_bcrypt': False,
         'is_sha512_crypt': False, 'is_md5_crypt': False,
         'candidates': ['MD5', 'MD4', 'MD2', 'RIPEMD-128']}
        >>> detect_hash_type("$2b$10$...")
        {'hex_length': 0, 'is_hex': False, 'is_bcrypt': True, ...}
    """
    if not isinstance(hash_string, str):
        raise TypeError(f"Expected str, got {type(hash_string).__name__}")

    raw = hash_string.strip()

    result: Dict[str, Any] = {
        "hex_length": 0,
        "is_hex": False,
        "is_bcrypt": False,
        "is_sha512_crypt": False,
        "is_md5_crypt": False,
        "candidates": [],
        "format": "unknown",
    }

    # Check for Unix crypt formats
    if raw.startswith("$2b$") or raw.startswith("$2a$") or raw.startswith("$2y$"):
        result["is_bcrypt"] = True
        result["format"] = "bcrypt"
        result["candidates"] = ["bcrypt"]
        return result

    if raw.startswith("$6$"):
        result["is_sha512_crypt"] = True
        result["format"] = "sha512-crypt"
        result["candidates"] = ["SHA-512 Crypt"]
        return result

    if raw.startswith("$5$"):
        result["format"] = "sha256-crypt"
        result["candidates"] = ["SHA-256 Crypt"]
        return result

    if raw.startswith("$1$"):
        result["is_md5_crypt"] = True
        result["format"] = "md5-crypt"
        result["candidates"] = ["MD5 Crypt"]
        return result

    if raw.startswith("$argon2"):
        result["format"] = "argon2"
        result["candidates"] = ["Argon2"]
        return result

    # Check for PBKDF2 format
    if raw.startswith("$pbkdf2"):
        result["format"] = "pbkdf2"
        result["candidates"] = ["PBKDF2"]
        return result

    # Check for LM/NT hashes
    if re.match(r"^[0-9A-F]{32}$", raw):
        result["hex_length"] = 32
        result["is_hex"] = True
        result["format"] = "ntlm-or-md5"
        result["candidates"] = ["NTLM", "MD5", "MD4", "MD2", "RIPEMD-128"]
        return result

    # Check hex format
    hex_match = re.match(r"^[0-9a-fA-F]+$", raw)
    if hex_match:
        hex_len = len(raw)
        result["hex_length"] = hex_len
        result["is_hex"] = True

        candidates = _get_hash_candidates_by_length(hex_len)
        result["candidates"] = candidates

        # Try to determine a primary format name
        if hex_len == 32:
            result["format"] = "md5"
        elif hex_len == 40:
            result["format"] = "sha1"
        elif hex_len == 56:
            result["format"] = "sha224"
        elif hex_len == 64:
            result["format"] = "sha256"
        elif hex_len == 96:
            result["format"] = "sha384"
        elif hex_len == 128:
            result["format"] = "sha512"
        else:
            result["format"] = f"hex-{hex_len}"
    else:
        result["format"] = "non-hex"
        # Check if it looks like Base64 (high entropy, alphanumeric + / + =)
        if re.match(r"^[A-Za-z0-9+/=]+$", raw) and len(raw) > 20:
            result["format"] = "base64-encoded"

    return result


def _get_hash_candidates_by_length(hex_length: int) -> List[str]:
    """Return known hash algorithm candidates for a given hex digest length.

    Args:
        hex_length: Number of hex characters in the digest.

    Returns:
        List of possible hash algorithm names, ordered by likelihood.
    """
    length_map: Dict[int, List[str]] = {
        8: ["CRC-32", "Adler-32"],
        16: ["CRC-64"],
        32: ["MD5", "MD4", "MD2", "RIPEMD-128"],
        40: ["SHA-1", "RIPEMD-160", "HAS-160"],
        56: ["SHA-224", "SHA-256/224", "SHA3-224"],
        64: ["SHA-256", "SHA-256/256", "SHA3-256", "BLAKE2s-256", "Skein-256"],
        96: ["SHA-384", "SHA-512/256", "SHA3-384", "BLAKE2b-384"],
        128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Skein-512"],
    }
    return length_map.get(hex_length, [f"unknown-hex:{hex_length}"])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte sequences together.

    If the sequences have different lengths, the result is truncated to the
    shorter length (like zip behavior). Useful for single-byte XOR cracking,
    multi-byte XOR key recovery, and cryptographic operations on fixed-size blocks.

    Args:
        a: First byte sequence.
        b: Second byte sequence.

    Returns:
        XOR-ed byte sequence (length = min(len(a), len(b))).

    Raises:
        TypeError: If inputs are not bytes.

    Examples:
        >>> xor_bytes(b"hello", b"world")
        b'\\x1f\\x0a\\x13\\x00\\x0e'
        >>> xor_bytes(b"\\x01\\x02", b"\\x01\\x02")
        b'\\x00\\x00'
    """
    if not isinstance(a, bytes):
        raise TypeError(f"Expected bytes for 'a', got {type(a).__name__}")
    if not isinstance(b, bytes):
        raise TypeError(f"Expected bytes for 'b', got {type(b).__name__}")

    return bytes(x ^ y for x, y in zip(a, b))


def xor_single_byte(data: bytes, key: int) -> bytes:
    """XOR data with a single-byte key.

    Args:
        data: Byte sequence to XOR.
        key: Single byte value (0-255) to XOR against each byte.

    Returns:
        XOR-ed byte sequence of the same length as input.

    Raises:
        TypeError: If data is not bytes.
        ValueError: If key is not in range 0-255.
    """
    if not isinstance(data, bytes):
        raise TypeError(f"Expected bytes, got {type(data).__name__}")
    if not isinstance(key, int) or key < 0 or key > 255:
        raise ValueError("Key must be an integer between 0 and 255")

    return bytes(b ^ key for b in data)


def xor_repeating_key(data: bytes, key: bytes) -> bytes:
    """XOR data with a repeating multi-byte key (Vigenère cipher over bytes).

    The key is repeated cyclically across the data length. This is the core
    operation for many multi-byte XOR ciphers.

    Args:
        data: Byte sequence to encode/decode.
        key: Repeating key byte sequence.

    Returns:
        XOR-ed byte sequence of the same length as data.

    Raises:
        TypeError: If inputs are not bytes.
        ValueError: If key is empty.
    """
    if not isinstance(data, bytes):
        raise TypeError(f"Expected bytes for data, got {type(data).__name__}")
    if not isinstance(key, bytes):
        raise TypeError(f"Expected bytes for key, got {type(key).__name__}")
    if len(key) == 0:
        raise ValueError("Key cannot be empty")

    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks.

    Uses HMAC comparison to ensure the function takes the same amount of time
    regardless of how many characters match. This prevents attackers from using
    response timing to brute-force strings character by character.

    Args:
        a: First string to compare.
        b: Second string to compare.

    Returns:
        True if strings are identical, False otherwise.

    Raises:
        TypeError: If inputs are not strings.

    Examples:
        >>> constant_time_compare("secret", "secret")
        True
        >>> constant_time_compare("secret", "secreX")
        False
    """
    if not isinstance(a, str):
        raise TypeError(f"Expected str for 'a', got {type(a).__name__}")
    if not isinstance(b, str):
        raise TypeError(f"Expected str for 'b', got {type(b).__name__}")

    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def random_byte_string(length: int = 32) -> bytes:
    """Generate a random byte string of the given length.

    Uses `os.urandom` directly for raw random bytes (non-printable).

    Args:
        length: Number of random bytes to generate.

    Returns:
        Random byte sequence.

    Raises:
        ValueError: If length is not positive.
    """
    if length < 1:
        raise ValueError("Length must be positive")
    return os.urandom(length)


def compress(data: Union[str, bytes]) -> bytes:
    """Compress data using zlib (DEFLATE) compression.

    Args:
        data: Data to compress. Strings are UTF-8 encoded first.

    Returns:
        Compressed byte sequence.

    Raises:
        TypeError: If data is neither str nor bytes.
    """
    if isinstance(data, str):
        data_bytes = data.encode("utf-8")
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        raise TypeError(f"Expected str or bytes, got {type(data).__name__}")

    return zlib.compress(data_bytes)


def decompress(data: bytes) -> bytes:
    """Decompress zlib-compressed data.

    Args:
        data: Compressed byte sequence.

    Returns:
        Decompressed byte sequence.

    Raises:
        zlib.error: If data is not valid zlib-compressed data.
        TypeError: If data is not bytes.
    """
    if not isinstance(data, bytes):
        raise TypeError(f"Expected bytes, got {type(data).__name__}")

    return zlib.decompress(data)


def bit_flip_entropy(original: str, modified: str) -> float:
    """Calculate the bit-flip ratio between two strings of the same length.

    Useful for analyzing how much a hash or ciphertext changes when input
    changes (avalanche effect measurement).

    Args:
        original: Original string.
        modified: Modified string.

    Returns:
        Bit-flip ratio (0.0 to 1.0). 0.5 is ideal for cryptographic hashes.

    Raises:
        ValueError: If strings are not the same length or if either is empty.
    """
    if len(original) != len(modified):
        raise ValueError("Strings must have the same length")
    if not original:
        raise ValueError("Strings must not be empty")

    original_bytes = original.encode("utf-8") if isinstance(original, str) else original
    modified_bytes = modified.encode("utf-8") if isinstance(modified, str) else modified

    total_bits = len(original_bytes) * 8
    flipped_bits = 0

    for o, m in zip(original_bytes, modified_bytes):
        xor_result = o ^ m
        # Count set bits in the XOR result
        flipped_bits += bin(xor_result).count("1")

    return flipped_bits / total_bits


if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=False)
    print("crypto_utils.py — all doctests passed.")
