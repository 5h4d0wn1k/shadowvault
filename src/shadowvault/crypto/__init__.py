"""Cryptographic engine for shadowvault.

Provides AES-256-GCM encryption with Argon2id or PBKDF2 key derivation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants
SALT_SIZE = 32
NONCE_SIZE = 12
KEY_SIZE = 32  # 256 bits
TAG_SIZE = 16
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
PBKDF2_ITERATIONS = 600000


class CryptoError(Exception):
    """Base exception for cryptographic operations."""


class DecryptionError(CryptoError):
    """Raised when decryption fails."""


class KeyDerivationError(CryptoError):
    """Raised when key derivation fails."""


def derive_key_argon2(
    password: str,
    salt: bytes | None = None,
    iterations: int = ARGON2_TIME_COST,
    memory_cost: int = ARGON2_MEMORY_COST,
    lanes: int = ARGON2_PARALLELISM,
) -> tuple[bytes, bytes]:
    """Derive a 256-bit key using Argon2id.

    Args:
        password: The master password.
        salt: Salt bytes (generated if None).
        iterations: Number of iterations (time cost).
        memory_cost: Memory usage in KB.
        lanes: Degree of parallelism.

    Returns:
        Tuple of (derived_key, salt).

    Raises:
        KeyDerivationError: If derivation fails.
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)

    try:
        kdf = Argon2id(
            salt=salt,
            length=KEY_SIZE,
            iterations=iterations,
            lanes=lanes,
            memory_cost=memory_cost,
        )
        key = kdf.derive(password.encode("utf-8"))
        return key, salt
    except Exception as e:
        raise KeyDerivationError(f"Argon2id derivation failed: {e}") from e


def derive_key_pbkdf2(
    password: str,
    salt: bytes | None = None,
    iterations: int = PBKDF2_ITERATIONS,
) -> tuple[bytes, bytes]:
    """Derive a 256-bit key using PBKDF2-HMAC-SHA256.

    Args:
        password: The master password.
        salt: Salt bytes (generated if None).
        iterations: Number of iterations.

    Returns:
        Tuple of (derived_key, salt).

    Raises:
        KeyDerivationError: If derivation fails.
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)

    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(password.encode("utf-8"))
        return key, salt
    except Exception as e:
        raise KeyDerivationError(f"PBKDF2 derivation failed: {e}") from e


def derive_key(
    password: str,
    method: str = "argon2",
    salt: bytes | None = None,
    **kwargs,
) -> tuple[bytes, bytes]:
    """Derive a key using the specified method.

    Args:
        password: The master password.
        method: Key derivation method ("argon2" or "pbkdf2").
        salt: Salt bytes (generated if None).
        **kwargs: Additional arguments for the KDF.

    Returns:
        Tuple of (derived_key, salt).
    """
    if method == "argon2":
        return derive_key_argon2(password, salt, **kwargs)
    elif method == "pbkdf2":
        return derive_key_pbkdf2(password, salt, **kwargs)
    else:
        raise ValueError(f"Unsupported key derivation method: {method}")


def encrypt(plaintext: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
    """Encrypt data using AES-256-GCM.

    Args:
        plaintext: Data to encrypt.
        key: 256-bit encryption key.
        associated_data: Optional associated data for authentication.

    Returns:
        Encrypted data with nonce prepended.

    Raises:
        CryptoError: If encryption fails.
    """
    if len(key) != KEY_SIZE:
        raise CryptoError(f"Key must be {KEY_SIZE} bytes")

    try:
        nonce = secrets.token_bytes(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext
    except Exception as e:
        raise CryptoError(f"Encryption failed: {e}") from e


def decrypt(encrypted: bytes, key: bytes, associated_data: bytes | None = None) -> bytes:
    """Decrypt data encrypted with AES-256-GCM.

    Args:
        encrypted: Encrypted data with nonce prepended.
        key: 256-bit encryption key.
        associated_data: Optional associated data for authentication.

    Returns:
        Decrypted plaintext.

    Raises:
        DecryptionError: If decryption fails (wrong key, tampered data).
    """
    if len(key) != KEY_SIZE:
        raise CryptoError(f"Key must be {KEY_SIZE} bytes")

    if len(encrypted) < NONCE_SIZE + TAG_SIZE:
        raise DecryptionError("Invalid encrypted data: too short")

    try:
        nonce = encrypted[:NONCE_SIZE]
        ciphertext = encrypted[NONCE_SIZE:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}") from e


def zeroize(data: bytearray) -> None:
    """Securely zeroize sensitive data in memory.

    Args:
        data: Bytearray to zeroize.
    """
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, bytes):
        raise TypeError("Cannot zeroize immutable bytes; use bytearray")


def generate_key_id(key: bytes) -> str:
    """Generate a fingerprint for a key (for identification, not security).

    Args:
        key: The encryption key.

    Returns:
        Hex-encoded key fingerprint.
    """
    return hashlib.sha256(key).hexdigest()[:16]


def secure_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two byte strings.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        True if equal, False otherwise.
    """
    return hmac.compare_digest(a, b)


def encrypt_string(plaintext: str, key: bytes, associated_data: bytes | None = None) -> bytes:
    """Encrypt a string, returning bytes."""
    return encrypt(plaintext.encode("utf-8"), key, associated_data)


def decrypt_string(encrypted: bytes, key: bytes, associated_data: bytes | None = None) -> str:
    """Decrypt bytes to string."""
    return decrypt(encrypted, key, associated_data).decode("utf-8")
