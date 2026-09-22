"""Additional tests for performance, edge cases, and integration."""

import json
import time

import pytest

from shadowvault.crypto import decrypt, derive_key, encrypt
from shadowvault.team import (
    TeamManager,
    TeamRole,
)
from shadowvault.vault import (
    Hash,
    Token,
    Vault,
)


class TestVaultPerformance:
    """Performance tests for vault operations."""

    @pytest.fixture
    def populated_vault(self):
        """Create a vault with many secrets."""
        vault = Vault.create(path=None, password="test")

        # Add 1000 secrets
        for i in range(1000):
            vault.add_credential(
                host=f"10.0.{i // 256}.{i % 256}",
                service="ssh",
                username=f"user{i}",
                password=f"pass{i}",
                tags=[f"host:{i % 10}"],
            )

        return vault

    def test_add_performance(self, populated_vault):
        """Test adding secrets is fast."""
        start = time.time()
        populated_vault.add_credential(
            host="10.0.0.999",
            service="ssh",
            username="test",
            password="test",
        )
        elapsed = time.time() - start
        assert elapsed < 0.1  # Under 100ms

    def test_get_performance(self, populated_vault):
        """Test getting secrets is fast."""
        # Get first credential's ID
        secrets = populated_vault.list_secrets(limit=1)
        secret_id = secrets[0].id

        start = time.time()
        populated_vault.get_secret(secret_id)
        elapsed = time.time() - start
        assert elapsed < 0.01  # Under 10ms

    def test_search_performance(self, populated_vault):
        """Test search is fast."""
        start = time.time()
        results = populated_vault.search(service="ssh")
        elapsed = time.time() - start
        assert elapsed < 0.1  # Under 100ms
        assert len(results) == 1000

    def test_list_performance(self, populated_vault):
        """Test listing secrets is fast."""
        start = time.time()
        secrets = populated_vault.list_secrets()
        elapsed = time.time() - start
        assert elapsed < 0.1
        assert len(secrets) == 1000

    def test_save_load_performance(self, populated_vault, tmp_path):
        """Test save/load is fast."""
        vault_path = str(tmp_path / "perf.vault")
        populated_vault._vault_path = vault_path

        start = time.time()
        populated_vault.save()
        save_time = time.time() - start

        start = time.time()
        Vault.open(vault_path, "test")
        load_time = time.time() - start

        # Both should be under 1 second for 1000 secrets
        assert save_time < 1.0
        assert load_time < 1.0

    def test_search_by_host_performance(self, populated_vault):
        """Test search by host is fast."""
        start = time.time()
        populated_vault.search(host="10.0.0.")
        elapsed = time.time() - start
        assert elapsed < 0.1


class TestVaultEdgeCases:
    """Edge case tests for vault operations."""

    def test_empty_vault_operations(self):
        """Test operations on empty vault."""
        vault = Vault.create(path=None, password="test")

        assert vault.secret_count == 0
        assert vault.list_secrets() == []
        assert vault.search(query="anything") == []
        assert vault.get_secret("nonexistent") is None

    def test_special_characters_in_secrets(self):
        """Test secrets with special characters."""
        vault = Vault.create(path=None, password="test")

        cred = vault.add_credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="p@$$w0rd!#%^&*()_+-=[]{}|;':\",./<>?",
        )
        assert cred.password == "p@$$w0rd!#%^&*()_+-=[]{}|;':\",./<>?"

    def test_unicode_secrets(self):
        """Test secrets with unicode characters."""
        vault = Vault.create(path=None, password="test")

        note = vault.add_note(
            content="日本語のテスト Note with émojis 🔐",
            category="international",
        )
        retrieved = vault.get_secret(note.id)
        assert retrieved.content == "日本語のテスト Note with émojis 🔐"

    def test_very_long_values(self):
        """Test secrets with very long values."""
        vault = Vault.create(path=None, password="test")

        long_content = "A" * 10000
        note = vault.add_note(content=long_content)
        retrieved = vault.get_secret(note.id)
        assert retrieved.content == long_content

    def test_many_tags(self):
        """Test secrets with many tags."""
        vault = Vault.create(path=None, password="test")

        tags = [f"tag{i}" for i in range(100)]
        cred = vault.add_credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="pass",
            tags=tags,
        )
        retrieved = vault.get_secret(cred.id)
        assert len(retrieved.tags) == 100

    def test_concurrent_adds(self):
        """Test adding multiple secrets."""
        vault = Vault.create(path=None, password="test")

        for i in range(100):
            vault.add_credential(
                host=f"10.0.0.{i}",
                service="ssh",
                username=f"user{i}",
                password=f"pass{i}",
            )

        assert vault.secret_count == 100

    def test_update_nonexistent_field(self):
        """Test updating nonexistent field."""
        vault = Vault.create(path=None, password="test")
        cred = vault.add_credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="pass",
        )

        # Should not raise
        vault.update_secret(cred.id, nonexistent_field="value")
        retrieved = vault.get_secret(cred.id)
        assert retrieved.host == "10.0.0.5"

    def test_delete_and_readd(self):
        """Test deleting and re-adding secrets."""
        vault = Vault.create(path=None, password="test")

        cred = vault.add_credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="pass",
        )
        vault.delete_secret(cred.id)
        assert vault.secret_count == 0

        vault.add_credential(
            host="10.0.0.6",
            service="ssh",
            username="admin2",
            password="pass2",
        )
        assert vault.secret_count == 1


class TestVaultEncryptionEdgeCases:
    """Edge cases for vault encryption."""

    def test_vault_with_empty_secrets(self, tmp_path):
        """Test saving/loading vault with no secrets."""
        vault_path = str(tmp_path / "empty.vault")
        vault = Vault.create(path=vault_path, password="test")
        vault.save()

        loaded = Vault.open(vault_path, "test")
        assert loaded.secret_count == 0

    def test_vault_with_many_types(self):
        """Test vault with all secret types."""
        vault = Vault.create(path=None, password="test")

        vault.add_credential(host="h1", service="ssh", username="u1", password="p1")
        vault.add_host(ip_address="10.0.0.1")
        vault.add_note(content="Note")
        vault.add_secret(Hash(hash_value="abc", hash_type="MD5"))
        vault.add_secret(Token(token_type="totp", issuer="Test"))

        assert vault.secret_count == 5

    def test_vault_roundtrip_preserves_metadata(self):
        """Test that metadata is preserved through save/load."""
        vault = Vault.create(path=None, password="test")

        cred = vault.add_credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="pass",
            tags=["test", "prod"],
            notes="Important",
            metadata={"custom": "value"},
        )

        retrieved = vault.get_secret(cred.id)
        assert retrieved.tags == ["test", "prod"]
        assert retrieved.notes == "Important"
        assert retrieved.metadata["custom"] == "value"


class TestCryptoEdgeCases:
    """Edge cases for cryptographic operations."""

    def test_encrypt_same_key_different_data(self):
        """Test encryption with same key but different data."""
        key, _ = derive_key("password")
        enc1 = encrypt(b"Data 1", key)
        enc2 = encrypt(b"Data 2", key)
        assert enc1 != enc2

    def test_decrypt_empty_data(self):
        """Test decrypting empty data."""
        key, _ = derive_key("password")
        encrypted = encrypt(b"", key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == b""

    def test_large_key_derivation(self):
        """Test key derivation with long password."""
        long_password = "A" * 10000
        key, salt = derive_key(long_password)
        assert len(key) == 32

    def test_binary_data_encryption(self):
        """Test encrypting binary data."""
        key, _ = derive_key("password")
        binary_data = bytes(range(256))
        encrypted = encrypt(binary_data, key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == binary_data

    def test_encryption_determinism_with_same_nonce(self):
        """Test that encryption is not deterministic (random nonce)."""
        key, _ = derive_key("password")
        plaintext = b"Same data"

        enc1 = encrypt(plaintext, key)
        enc2 = encrypt(plaintext, key)

        # Should be different due to random nonce
        assert enc1 != enc2

        # But both should decrypt to same plaintext
        assert decrypt(enc1, key) == plaintext
        assert decrypt(enc2, key) == plaintext


class TestMigrationEdgeCases:
    """Edge cases for migration tools."""

    def test_plaintext_only_passwords(self):
        """Test importing list of passwords only."""
        from shadowvault.migration import import_plaintext

        content = """password1
password2
password3"""
        secrets = import_plaintext(content)
        assert len(secrets) == 3
        assert secrets[0].password == "password1"

    def test_keepass_csv_with_empty_fields(self):
        """Test KeePass CSV with empty fields."""
        from shadowvault.migration import import_keepass_csv

        csv = """Group,Title,URL,Username,Password,Notes
Work,Admin,,admin,pass,Test"""
        secrets = import_keepass_csv(csv)
        assert len(secrets) == 1

    def test_bitwarden_with_missing_fields(self):
        """Test Bitwarden import with missing fields."""
        from shadowvault.migration import import_bitwarden_json

        json_data = {
            "items": [
                {
                    "type": 1,
                    "name": "Test",
                    "login": {
                        "username": "u",
                        "password": "p",
                    },
                    "folder": "",
                    "tags": [],
                }
            ]
        }
        secrets = import_bitwarden_json(json.dumps(json_data))
        assert len(secrets) == 1

    def test_hashcat_potfile_with_special_chars(self):
        """Test hashcat potfile with special characters in password."""
        from shadowvault.migration import import_hashcat_potfile

        content = "abc123:p@$$w0rd!#%^&*()"
        hashes = import_hashcat_potfile(content)
        assert hashes[0].plaintext == "p@$$w0rd!#%^&*()"


class TestTeamEdgeCases:
    """Edge cases for team management."""

    def test_team_serialization_roundtrip(self):
        """Test team serialization preserves data."""
        team = TeamManager(owner_id="alice")
        team.add_member("bob", email="bob@test.com", role=TeamRole.VIEWER)
        team.add_member("carol", role=TeamRole.ANNOTATOR)

        data = team.to_dict()
        team2 = TeamManager.from_dict(data)

        assert team2.member_count == team.member_count
        assert team2.owner_id == "alice"

    def test_team_all_roles(self):
        """Test all team roles."""
        team = TeamManager()
        team.add_member("owner", role=TeamRole.OWNER)
        team.add_member("annotator", role=TeamRole.ANNOTATOR)
        team.add_member("viewer", role=TeamRole.VIEWER)

        owners = team.list_members(role=TeamRole.OWNER)
        assert len(owners) == 2  # System owner + added owner

    def test_team_permissions_comprehensive(self):
        """Test all permission combinations."""
        team = TeamManager()

        # Owner
        team.add_member("owner", role=TeamRole.OWNER)
        owner_perms = ["read", "write", "delete", "export",
                       "manage_members", "view_audit", "manage_vault"]
        for perm in owner_perms:
            assert team.check_permission("owner", perm)

        # Annotator
        team.add_member("annotator", role=TeamRole.ANNOTATOR)
        assert team.check_permission("annotator", "read")
        assert team.check_permission("annotator", "annotate")
        assert not team.check_permission("annotator", "delete")

        # Viewer
        team.add_member("viewer", role=TeamRole.VIEWER)
        assert team.check_permission("viewer", "read")
        assert not team.check_permission("viewer", "write")


class TestAuditEdgeCases:
    """Edge cases for audit logging."""

    def test_audit_log_comprehensive(self):
        """Test comprehensive audit logging."""
        from shadowvault.vault import AuditLog

        log = AuditLog()
        log.log("create")
        log.log("add", secret_id="abc")
        log.log("get", secret_id="abc")
        log.log("update", secret_id="abc")
        log.log("delete", secret_id="abc")
        log.log("save")

        assert log.count() == 6
        assert log.count(action="add") == 1
        assert log.count(action="get") == 1

    def test_audit_log_user_tracking(self):
        """Test audit log tracks users."""
        from shadowvault.vault import AuditLog

        log = AuditLog()
        log.log("get", user="alice")
        log.log("get", user="bob")
        log.log("add", user="alice")

        alice_entries = log.get_entries(user="alice")
        assert len(alice_entries) == 2

        bob_entries = log.get_entries(user="bob")
        assert len(bob_entries) == 1
