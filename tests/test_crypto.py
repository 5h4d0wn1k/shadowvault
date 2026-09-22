"""Tests for the cryptographic engine."""

import os
import secrets

import pytest

from shadowvault.crypto import (
    CryptoError,
    DecryptionError,
    decrypt,
    decrypt_string,
    derive_key,
    derive_key_argon2,
    derive_key_pbkdf2,
    encrypt,
    encrypt_string,
    generate_key_id,
    secure_compare,
    zeroize,
)


# Test-specific Argon2 with lower memory cost for faster tests
def fast_argon2(password: str, salt=None, **kwargs):
    """Argon2 with lower memory cost for testing."""
    defaults = {"memory_cost": 8192, "iterations": 1, "lanes": 2}
    defaults.update(kwargs)
    return derive_key_argon2(password, salt=salt, **defaults)


class TestKeyDerivation:
    """Tests for key derivation functions."""

    def fast_argon2_derives_key(self):
        """Argon2id should produce a 32-byte key."""
        key, salt = fast_argon2("test_password")
        assert len(key) == 32
        assert len(salt) == 32

    def fast_argon2_deterministic(self):
        """Same password + salt should produce same key."""
        salt = secrets.token_bytes(32)
        key1, _ = fast_argon2("password", salt=salt)
        key2, _ = fast_argon2("password", salt=salt)
        assert key1 == key2

    def fast_argon2_different_passwords(self):
        """Different passwords should produce different keys."""
        key1, _ = fast_argon2("password1")
        key2, _ = fast_argon2("password2")
        assert key1 != key2

    def fast_argon2_different_salts(self):
        """Different salts should produce different keys."""
        key1, _ = fast_argon2("password")
        key2, _ = fast_argon2("password")
        assert key1 != key2

    def test_pbkdf2_derives_key(self):
        """PBKDF2 should produce a 32-byte key."""
        key, salt = derive_key_pbkdf2("test_password")
        assert len(key) == 32
        assert len(salt) == 32

    def test_pbkdf2_deterministic(self):
        """Same password + salt should produce same key."""
        salt = secrets.token_bytes(32)
        key1, _ = derive_key_pbkdf2("password", salt=salt)
        key2, _ = derive_key_pbkdf2("password", salt=salt)
        assert key1 == key2

    def test_derive_key_argon2_method(self):
        """derive_key with method='argon2' should work."""
        key, salt = derive_key("test", method="argon2", memory_cost=8192, iterations=1)
        assert len(key) == 32

    def test_derive_key_pbkdf2_method(self):
        """derive_key with method='pbkdf2' should work."""
        key, salt = derive_key("test", method="pbkdf2")
        assert len(key) == 32

    def test_derive_key_invalid_method(self):
        """Invalid method should raise ValueError."""
        with pytest.raises(ValueError):
            derive_key("test", method="invalid")

    def fast_argon2_empty_password(self):
        """Argon2 should handle empty password."""
        key, salt = fast_argon2("")
        assert len(key) == 32

    def test_pbkdf2_empty_password(self):
        """PBKDF2 should handle empty password."""
        key, salt = derive_key_pbkdf2("")
        assert len(key) == 32

    def fast_argon2_unicode_password(self):
        """Argon2 should handle unicode password."""
        key, salt = fast_argon2("pässwörd_日本語")
        assert len(key) == 32

    def test_pbkdf2_unicode_password(self):
        """PBKDF2 should handle unicode password."""
        key, salt = derive_key_pbkdf2("pässwörd_日本語")
        assert len(key) == 32


class TestEncryption:
    """Tests for AES-256-GCM encryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt then decrypt should return original plaintext."""
        key, _ = fast_argon2("test")
        plaintext = b"Hello, World!"
        encrypted = encrypt(plaintext, key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_encrypt_returns_different_ciphertext(self):
        """Same plaintext should produce different ciphertext (random nonce)."""
        key, _ = fast_argon2("test")
        plaintext = b"Same message"
        enc1 = encrypt(plaintext, key)
        enc2 = encrypt(plaintext, key)
        assert enc1 != enc2  # Different nonces

    def test_wrong_key_fails_decryption(self):
        """Wrong key should fail to decrypt."""
        key1, _ = fast_argon2("pass1")
        key2, _ = fast_argon2("pass2")
        plaintext = b"Secret data"
        encrypted = encrypt(plaintext, key1)
        with pytest.raises(DecryptionError):
            decrypt(encrypted, key2)

    def test_tampered_ciphertext_fails(self):
        """Tampered ciphertext should fail authentication."""
        key, _ = fast_argon2("test")
        plaintext = b"Auth data"
        encrypted = encrypt(plaintext, key)
        # Tamper with ciphertext
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF
        with pytest.raises(DecryptionError):
            decrypt(bytes(tampered), key)

    def test_wrong_key_length_fails(self):
        """Key with wrong length should raise CryptoError."""
        plaintext = b"Data"
        with pytest.raises(CryptoError):
            encrypt(plaintext, b"short_key")
        with pytest.raises(CryptoError):
            decrypt(b"\x00" * 24 + b"\x00" * 16, b"short_key")

    def test_empty_plaintext(self):
        """Should handle empty plaintext."""
        key, _ = fast_argon2("test")
        encrypted = encrypt(b"", key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == b""

    def test_large_plaintext(self):
        """Should handle large plaintext."""
        key, _ = fast_argon2("test")
        plaintext = os.urandom(1024 * 1024)  # 1MB
        encrypted = encrypt(plaintext, key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_encrypt_with_associated_data(self):
        """Should encrypt with associated data."""
        key, _ = fast_argon2("test")
        plaintext = b"Data"
        aad = b"Associated Data"
        encrypted = encrypt(plaintext, key, associated_data=aad)
        decrypted = decrypt(encrypted, key, associated_data=aad)
        assert decrypted == plaintext

    def test_wrong_associated_data_fails(self):
        """Wrong associated data should fail authentication."""
        key, _ = fast_argon2("test")
        plaintext = b"Data"
        aad1 = b"Data1"
        aad2 = b"Data2"
        encrypted = encrypt(plaintext, key, associated_data=aad1)
        with pytest.raises(DecryptionError):
            decrypt(encrypted, key, associated_data=aad2)

    def test_decrypt_too_short(self):
        """Decrypting data too short should raise DecryptionError."""
        key, _ = fast_argon2("test")
        with pytest.raises(DecryptionError):
            decrypt(b"\x00" * 10, key)

    def test_encrypt_string_roundtrip(self):
        """encrypt_string/decrypt_string should roundtrip."""
        key, _ = fast_argon2("test")
        plaintext = "Hello, Unicode! 日本語"
        encrypted = encrypt_string(plaintext, key)
        decrypted = decrypt_string(encrypted, key)
        assert decrypted == plaintext

    def test_aes_gcm_is_authenticated(self):
        """AES-GCM should be authenticated (tamper detection)."""
        key, _ = fast_argon2("test")
        plaintext = b"Authenticated data"
        encrypted = encrypt(plaintext, key)

        # Flip bit in nonce
        tampered = bytearray(encrypted)
        tampered[0] ^= 0x01
        with pytest.raises(DecryptionError):
            decrypt(bytes(tampered), key)


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_generate_key_id(self):
        """Key ID should be 16 hex chars."""
        key = os.urandom(32)
        kid = generate_key_id(key)
        assert len(kid) == 16
        assert all(c in "0123456789abcdef" for c in kid)

    def test_generate_key_id_deterministic(self):
        """Same key should produce same ID."""
        key = os.urandom(32)
        kid1 = generate_key_id(key)
        kid2 = generate_key_id(key)
        assert kid1 == kid2

    def test_secure_compare_equal(self):
        """Equal strings should return True."""
        assert secure_compare(b"same", b"same")

    def test_secure_compare_not_equal(self):
        """Different strings should return False."""
        assert not secure_compare(b"abc", b"abd")

    def test_secure_compare_different_lengths(self):
        """Different lengths should return False."""
        assert not secure_compare(b"short", b"longer")

    def test_zeroize_bytearray(self):
        """Zeroize should clear bytearray."""
        data = bytearray(b"sensitive data")
        zeroize(data)
        assert all(b == 0 for b in data)

    def test_zeroize_bytes_raises(self):
        """Zeroize on immutable bytes should raise TypeError."""
        with pytest.raises(TypeError):
            zeroize(b"immutable")

    def test_zeroize_already_zeroed(self):
        """Zeroize on already zeroed data should not raise."""
        data = bytearray(10)
        zeroize(data)  # Should not raise

    def test_zeroize_empty(self):
        """Zeroize on empty bytearray should not raise."""
        data = bytearray()
        zeroize(data)
        assert len(data) == 0


class TestKeyDerivationPerformance:
    """Tests for key derivation performance."""

    def fast_argon2_key_uniqueness(self):
        """Different passwords should produce very different keys."""
        keys = set()
        for i in range(100):
            key, _ = fast_argon2(f"password_{i}")
            keys.add(key.hex())
        assert len(keys) == 100  # All unique

    def test_pbkdf2_key_uniqueness(self):
        """Different salts should produce unique keys."""
        keys = set()
        for i in range(100):
            key, _ = derive_key_pbkdf2("password")
            keys.add(key.hex())
        assert len(keys) == 100
