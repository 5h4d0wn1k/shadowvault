"""Tests for vault operations."""

import os
import time
from datetime import datetime, timezone

import pytest

from shadowvault.team import (
    PermissionDenied,
    TeamError,
    TeamManager,
    TeamRole,
)
from shadowvault.vault import (
    AuditLog,
    AutoLocker,
    Credential,
    EncryptionKey,
    Hash,
    Host,
    MemoryGuard,
    Note,
    SecretType,
    SecureString,
    Token,
    Vault,
    VaultLockedError,
    VaultNotFoundError,
    secret_from_dict,
    zeroize_bytes,
)


class TestSecretSchema:
    """Tests for secret data schemas."""

    def test_credential_creation(self):
        """Test credential creation."""
        cred = Credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="P@ssw0rd!",
        )
        assert cred.host == "10.0.0.5"
        assert cred.service == "ssh"
        assert cred.secret_type == SecretType.CREDENTIAL

    def test_credential_to_dict(self):
        """Test credential serialization."""
        cred = Credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="secret",
            port=22,
            tags=["test"],
            notes="Test note",
        )
        data = cred.to_dict()
        assert data["host"] == "10.0.0.5"
        assert data["service"] == "ssh"
        assert data["port"] == 22
        assert "test" in data["tags"]
        assert data["secret_type"] == "credential"

    def test_credential_from_dict(self):
        """Test credential deserialization."""
        data = {
            "id": "test-id",
            "secret_type": "credential",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "tags": ["test"],
            "notes": "Test",
            "metadata": {},
            "host": "10.0.0.5",
            "port": 22,
            "service": "ssh",
            "username": "admin",
            "password": "secret",
            "domain": "",
            "realm": "",
            "last_used": None,
            "expires_at": None,
            "rotation_recommended": False,
        }
        cred = Credential.from_dict(data)
        assert cred.host == "10.0.0.5"
        assert cred.port == 22

    def test_host_creation(self):
        """Test host creation."""
        host = Host(
            ip_address="10.0.0.1",
            hostname="dc01",
            ports=[22, 80, 443],
            os_info="Windows Server 2019",
            services=["ssh", "http"],
        )
        assert host.ip_address == "10.0.0.1"
        assert host.secret_type == SecretType.HOST
        assert 22 in host.ports

    def test_host_to_dict(self):
        """Test host serialization."""
        host = Host(
            ip_address="10.0.0.1",
            hostname="dc01",
            ports=[22, 80],
        )
        data = host.to_dict()
        assert data["ip_address"] == "10.0.0.1"
        assert data["ports"] == [22, 80]

    def test_note_creation(self):
        """Test note creation."""
        note = Note(
            content="Important finding",
            category="recon",
        )
        assert note.content == "Important finding"
        assert note.secret_type == SecretType.NOTE

    def test_hash_creation(self):
        """Test hash creation."""
        h = Hash(
            hash_value="5d41402abc4b2a76b9719d911017c592",
            hash_type="MD5",
            plaintext="hello",
        )
        assert h.hash_value == "5d41402abc4b2a76b9719d911017c592"
        assert h.plaintext == "hello"

    def test_token_creation(self):
        """Test token creation."""
        token = Token(
            token_type="totp",
            token_value="JBSWY3DPEHPK3PXP",
            issuer="GitHub",
            scopes=["repo", "admin"],
        )
        assert token.token_type == "totp"
        assert "repo" in token.scopes

    def test_key_creation(self):
        """Test encryption key creation."""
        key = EncryptionKey(
            key_type="RSA",
            key_data="-----BEGIN RSA PRIVATE KEY-----",
            key_format="PEM",
            fingerprint="abc123",
        )
        assert key.key_type == "RSA"

    def test_secret_from_dict_factory(self):
        """Test factory function creates correct types."""
        cred_data = {
            "id": "test",
            "secret_type": "credential",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "tags": [],
            "notes": "",
            "metadata": {},
            "host": "",
            "port": 0,
            "service": "",
            "username": "",
            "password": "",
            "domain": "",
            "realm": "",
            "last_used": None,
            "expires_at": None,
            "rotation_recommended": False,
        }
        secret = secret_from_dict(cred_data)
        assert isinstance(secret, Credential)

    def test_secret_from_dict_unknown_type(self):
        """Unknown type should default to Note."""
        data = {
            "id": "test",
            "secret_type": "unknown",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "tags": [],
            "notes": "",
            "metadata": {},
            "content": "",
            "category": "",
        }
        secret = secret_from_dict(data)
        assert isinstance(secret, Note)


class TestAuditLog:
    """Tests for audit logging."""

    def test_log_creation(self):
        """Test audit entry creation."""
        log = AuditLog()
        entry = log.log("test_action", details="test")
        assert entry.action == "test_action"
        assert entry.success is True
        assert len(log) == 1

    def test_log_with_secret_id(self):
        """Test logging with secret ID."""
        log = AuditLog()
        entry = log.log("get", secret_id="abc-123")
        assert entry.secret_id == "abc-123"

    def test_log_filtering(self):
        """Test filtering audit entries."""
        log = AuditLog()
        log.log("add")
        log.log("get")
        log.log("add")
        log.log("delete")

        adds = log.get_entries(action="add")
        assert len(adds) == 2

    def test_log_limit(self):
        """Test limit on audit entries."""
        log = AuditLog()
        for i in range(10):
            log.log(f"action_{i}")

        entries = log.get_entries(limit=5)
        assert len(entries) == 5

    def test_log_offset(self):
        """Test offset on audit entries."""
        log = AuditLog()
        for i in range(10):
            log.log(f"action_{i}")

        entries = log.get_entries(offset=8)
        assert len(entries) == 2

    def test_log_count(self):
        """Test counting audit entries."""
        log = AuditLog()
        log.log("add")
        log.log("get")
        log.log("add")

        assert log.count() == 3
        assert log.count(action="add") == 2

    def test_log_serialization(self):
        """Test audit log serialization."""
        log = AuditLog()
        log.log("test")
        data = log.to_dict()
        assert len(data) == 1
        assert data[0]["action"] == "test"

    def test_log_from_dict(self):
        """Test audit log deserialization."""
        data = [{"timestamp": datetime.now(timezone.utc).isoformat(),
                 "action": "test", "secret_id": None, "user": "local",
                 "details": "", "success": True}]
        log = AuditLog.from_dict(data)
        assert len(log) == 1

    def test_log_json(self):
        """Test JSON serialization."""
        log = AuditLog()
        log.log("test")
        json_str = log.to_json()
        assert "test" in json_str
        log2 = AuditLog.from_json(json_str)
        assert len(log2) == 1

    def test_log_clear(self):
        """Test clearing audit log."""
        log = AuditLog()
        log.log("test")
        log.clear()
        assert len(log) == 0

    def test_log_iteration(self):
        """Test audit log iteration."""
        log = AuditLog()
        log.log("a")
        log.log("b")
        entries = list(log)
        assert len(entries) == 2

    def test_log_user_filter(self):
        """Test filtering by user."""
        log = AuditLog()
        log.log("add", user="alice")
        log.log("get", user="bob")
        log.log("add", user="alice")

        alice_entries = log.get_entries(user="alice")
        assert len(alice_entries) == 2

    def test_log_failed_action(self):
        """Test logging failed actions."""
        log = AuditLog()
        entry = log.log("decrypt", success=False, details="Wrong key")
        assert entry.success is False


class TestVaultOperations:
    """Tests for vault operations."""

    @pytest.fixture
    def vault_path(self, tmp_path):
        """Create a temporary vault path."""
        return str(tmp_path / "test.vault")

    @pytest.fixture
    def vault(self):
        """Create a test vault."""
        return Vault.create(path=None, password="test_password")

    def test_vault_create(self, vault):
        """Test vault creation."""
        assert vault.secret_count == 0
        assert vault.key_id is not None

    def test_vault_add_credential(self, vault):
        """Test adding a credential."""
        cred = vault.add_credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="P@ssw0rd!",
        )
        assert cred.id is not None
        assert vault.secret_count == 1

    def test_vault_add_host(self, vault):
        """Test adding a host."""
        host = vault.add_host(
            ip_address="10.0.0.1",
            hostname="dc01",
            ports=[22, 80, 443],
        )
        assert host.id is not None
        assert vault.secret_count == 1

    def test_vault_add_note(self, vault):
        """Test adding a note."""
        note = vault.add_note(
            content="Important finding",
            category="recon",
        )
        assert note.id is not None

    def test_vault_get_secret(self, vault):
        """Test getting a secret."""
        cred = vault.add_credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="pass",
        )
        retrieved = vault.get_secret(cred.id)
        assert retrieved is not None
        assert retrieved.id == cred.id

    def test_vault_get_nonexistent(self, vault):
        """Test getting nonexistent secret."""
        result = vault.get_secret("nonexistent")
        assert result is None

    def test_vault_delete_secret(self, vault):
        """Test deleting a secret."""
        cred = vault.add_credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="pass",
        )
        assert vault.delete_secret(cred.id) is True
        assert vault.secret_count == 0

    def test_vault_delete_nonexistent(self, vault):
        """Test deleting nonexistent secret."""
        assert vault.delete_secret("nonexistent") is False

    def test_vault_list_secrets(self, vault):
        """Test listing secrets."""
        vault.add_credential(host="10.0.0.1", service="ssh", username="u1", password="p1")
        vault.add_credential(host="10.0.0.2", service="smb", username="u2", password="p2")
        vault.add_note(content="test note")

        # List all
        all_secrets = vault.list_secrets()
        assert len(all_secrets) == 3

        # Filter by type
        creds = vault.list_secrets(secret_type=SecretType.CREDENTIAL)
        assert len(creds) == 2

    def test_vault_list_with_tags(self, vault):
        """Test listing with tag filter."""
        vault.add_credential(host="h1", service="ssh", username="u1", password="p1", tags=["prod"])
        vault.add_credential(host="h2", service="ssh", username="u2", password="p2", tags=["dev"])

        prod = vault.list_secrets(tags=["prod"])
        assert len(prod) == 1

    def test_vault_list_with_limit(self, vault):
        """Test listing with limit."""
        for i in range(10):
            vault.add_credential(host=f"h{i}", service="ssh", username="u", password="p")

        limited = vault.list_secrets(limit=5)
        assert len(limited) == 5

    def test_vault_search_query(self, vault):
        """Test free-text search."""
        vault.add_credential(host="dc01.corp.local", service="ssh", username="admin", password="p1")
        vault.add_credential(host="web01.corp.local", service="http", username="web", password="p2")

        results = vault.search(query="dc01")
        assert len(results) == 1

    def test_vault_search_by_host(self, vault):
        """Test search by host."""
        vault.add_credential(host="10.0.0.5", service="ssh", username="admin", password="p1")
        vault.add_credential(host="10.0.0.6", service="ssh", username="admin", password="p2")

        results = vault.search(host="10.0.0.5")
        assert len(results) == 1

    def test_vault_search_by_service(self, vault):
        """Test search by service."""
        vault.add_credential(host="h1", service="ssh", username="u1", password="p1")
        vault.add_credential(host="h2", service="smb", username="u2", password="p2")

        results = vault.search(service="ssh")
        assert len(results) == 1

    def test_vault_search_by_username(self, vault):
        """Test search by username."""
        vault.add_credential(host="h1", service="ssh", username="admin", password="p1")
        vault.add_credential(host="h2", service="ssh", username="web", password="p2")

        results = vault.search(username="admin")
        assert len(results) == 1

    def test_vault_update_secret(self, vault):
        """Test updating a secret."""
        cred = vault.add_credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="old",
        )
        updated = vault.update_secret(cred.id, password="new", notes="Updated")
        assert updated.password == "new"
        assert updated.notes == "Updated"

    def test_vault_update_nonexistent(self, vault):
        """Test updating nonexistent secret."""
        result = vault.update_secret("nonexistent", notes="test")
        assert result is None

    def test_vault_save_and_load(self, vault_path, vault):
        """Test saving and loading vault."""
        vault._vault_path = vault_path
        vault.add_credential(host="h1", service="ssh", username="u1", password="p1")
        vault.save()

        loaded = Vault.open(vault_path, "test_password")
        assert loaded.secret_count == 1

    def test_vault_load_nonexistent(self):
        """Test loading nonexistent vault."""
        with pytest.raises(VaultNotFoundError):
            Vault.open("/nonexistent/path.vault", "password")

    def test_vault_wrong_password(self, vault_path, vault):
        """Test loading with wrong password."""
        vault._vault_path = vault_path
        vault.save()

        with pytest.raises(Exception):
            Vault.open(vault_path, "wrong_password")

    def test_vault_lock(self, vault):
        """Test locking vault."""
        vault.lock()
        assert vault.is_locked

    def test_vault_unlock(self, vault):
        """Test unlocking vault."""
        vault.lock()
        vault.unlock("test_password")
        assert not vault.is_locked

    def test_vault_locked_error(self, vault):
        """Test operations on locked vault."""
        vault.lock()
        with pytest.raises(VaultLockedError):
            vault.add_credential(host="h1", service="ssh", username="u1", password="p1")

    def test_vault_search_after_add(self, vault):
        """Test search works after adding secrets."""
        vault.add_credential(host="10.0.0.5", service="ssh", username="admin", password="pass")
        vault.add_note(content="Found admin credentials")

        results = vault.search(query="admin")
        assert len(results) >= 1

    def test_vault_audit_log(self, vault):
        """Test audit logging."""
        vault.add_credential(host="h1", service="ssh", username="u1", password="p1")
        entries = vault.get_audit_log()
        assert len(entries) >= 1

    def test_vault_export(self, vault_path, vault):
        """Test vault export."""
        vault._vault_path = vault_path
        vault.add_credential(host="h1", service="ssh", username="u1", password="p1")
        vault.save()

        export_path = str(vault_path) + ".export"
        vault.export_secrets(export_path, password="export_pass")
        assert os.path.exists(export_path)

    def test_vault_import_secrets(self, vault):
        """Test importing secrets."""
        secrets = [
            Credential(host="h1", service="ssh", username="u1", password="p1"),
            Credential(host="h2", service="ssh", username="u2", password="p2"),
        ]
        count = vault.import_secrets(secrets)
        assert count == 2
        assert vault.secret_count == 2

    def test_vault_cleanup(self, vault):
        """Test vault cleanup."""
        vault.add_credential(host="h1", service="ssh", username="u1", password="p1")
        vault.cleanup()
        assert vault.secret_count == 0


class TestOPSEC:
    """Tests for OPSEC features."""

    def test_zeroize_bytes(self):
        """Test memory zeroization."""
        data = bytearray(b"sensitive")
        zeroize_bytes(data)
        assert all(b == 0 for b in data)

    def test_secure_string(self):
        """Test SecureString."""
        s = SecureString("test_password")
        assert s.value == "test_password"
        assert repr(s) == "<SecureString: [REDACTED]>"
        assert str(s) == "[REDACTED]"

    def test_memory_guard(self):
        """Test MemoryGuard context manager."""
        with MemoryGuard() as guard:
            buf = guard.buffer(100)
            buf[0:6] = b"secret"
            assert buf[0:6] == b"secret"

        # Buffer should be zeroed after context exit
        assert all(b == 0 for b in buf)

    def test_auto_locker(self):
        """Test auto-locker."""
        locked = []

        def on_lock():
            locked.append(True)

        locker = AutoLocker(timeout_seconds=1, on_lock=on_lock)
        locker.touch()
        time.sleep(1.5)
        locker._check_timeout()
        assert len(locked) == 1
        locker.cleanup()

    def test_auto_locker_manual_lock(self):
        """Test manual lock."""
        locker = AutoLocker(timeout_seconds=60)
        locker.lock()
        assert locker.is_locked
        locker.cleanup()

    def test_auto_locker_enable_disable(self):
        """Test enabling/disabling auto-lock."""
        locker = AutoLocker(timeout_seconds=60)
        assert locker.is_enabled
        locker.disable()
        assert not locker.is_enabled
        locker.enable()
        assert locker.is_enabled
        locker.cleanup()


class TestTeamManagement:
    """Tests for team RBAC."""

    def test_team_creation(self):
        """Test team creation."""
        team = TeamManager(owner_id="alice")
        assert team.owner_id == "alice"
        assert team.member_count == 1

    def test_add_member(self):
        """Test adding a team member."""
        team = TeamManager()
        member = team.add_member("bob", email="bob@test.com", role=TeamRole.VIEWER)
        assert member.user_id == "bob"
        assert team.member_count == 2

    def test_remove_member(self):
        """Test removing a team member."""
        team = TeamManager()
        team.add_member("bob")
        assert team.remove_member("bob") is True
        assert team.member_count == 1

    def test_remove_owner_fails(self):
        """Test removing owner fails."""
        team = TeamManager(owner_id="alice")
        with pytest.raises(TeamError):
            team.remove_member("alice")

    def test_update_role(self):
        """Test updating member role."""
        team = TeamManager()
        team.add_member("bob", role=TeamRole.VIEWER)
        team.update_role("bob", TeamRole.ANNOTATOR)
        member = team.get_member("bob")
        assert member.role == TeamRole.ANNOTATOR

    def test_deactivate_member(self):
        """Test deactivating a member."""
        team = TeamManager()
        team.add_member("bob")
        team.deactivate_member("bob")
        assert team.member_count == 1  # Inactive members not counted

    def test_activate_member(self):
        """Test activating a member."""
        team = TeamManager()
        team.add_member("bob")
        team.deactivate_member("bob")
        team.activate_member("bob")
        assert team.member_count == 2

    def test_check_permission(self):
        """Test permission checking."""
        team = TeamManager()
        team.add_member("bob", role=TeamRole.VIEWER)

        assert team.check_permission("bob", "read") is True
        assert team.check_permission("bob", "write") is False

    def test_owner_permissions(self):
        """Test owner has all permissions."""
        team = TeamManager(owner_id="alice")
        assert team.check_permission("alice", "read") is True
        assert team.check_permission("alice", "write") is True
        assert team.check_permission("alice", "delete") is True
        assert team.check_permission("alice", "manage_members") is True

    def test_annotator_permissions(self):
        """Test annotator permissions."""
        team = TeamManager()
        team.add_member("bob", role=TeamRole.ANNOTATOR)

        assert team.check_permission("bob", "read") is True
        assert team.check_permission("bob", "annotate") is True
        assert team.check_permission("bob", "delete") is False

    def test_require_permission(self):
        """Test requiring permission."""
        team = TeamManager()
        team.add_member("bob", role=TeamRole.VIEWER)

        # Should not raise
        team.require_permission("bob", "read")

        # Should raise
        with pytest.raises(PermissionDenied):
            team.require_permission("bob", "write")

    def test_list_members(self):
        """Test listing members."""
        team = TeamManager()
        team.add_member("bob", role=TeamRole.VIEWER)
        team.add_member("carol", role=TeamRole.ANNOTATOR)

        all_members = team.list_members()
        assert len(all_members) == 3  # Including owner

        viewers = team.list_members(role=TeamRole.VIEWER)
        assert len(viewers) == 1  # Just bob (owner has OWNER role)

    def test_generate_invitation(self):
        """Test invitation token generation."""
        team = TeamManager()
        token = team.generate_invitation("bob")
        assert "bob:" in token

    def test_team_serialization(self):
        """Test team serialization."""
        team = TeamManager()
        team.add_member("bob", role=TeamRole.VIEWER)

        data = team.to_dict()
        assert len(data) == 2

        team2 = TeamManager.from_dict(data)
        assert team2.member_count == 2

    def test_nonexistent_member(self):
        """Test operations on nonexistent member."""
        team = TeamManager()
        assert team.get_member("nonexistent") is None
        assert team.remove_member("nonexistent") is False

    def test_change_owner_role_fails(self):
        """Test changing owner role fails."""
        team = TeamManager(owner_id="alice")
        with pytest.raises(TeamError):
            team.update_role("alice", TeamRole.VIEWER)
