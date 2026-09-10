"""Vault manager: the core engine for secret storage and retrieval."""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from ..crypto import (
    CryptoError,
    DecryptionError,
    decrypt,
    derive_key,
    encrypt,
    generate_key_id,
    zeroize,
)
from .audit import AuditLog
from .opsec import AutoLocker, MemoryGuard, zeroize_bytes
from .schema import (
    AuditEntry,
    Credential,
    EncryptionKey,
    Hash,
    Host,
    Note,
    Secret,
    SecretType,
    TeamMember,
    TeamRole,
    Token,
    secret_from_dict,
)


class VaultError(Exception):
    """Base exception for vault operations."""


class VaultLockedError(VaultError):
    """Raised when trying to access a locked vault."""


class VaultNotFoundError(VaultError):
    """Raised when vault file doesn't exist."""


class Vault:
    """Main vault class for secret management."""

    # Vault file format version
    FORMAT_VERSION = "1.0.0"

    def __init__(
        self,
        key: bytes,
        vault_path: Optional[str] = None,
        kdf_method: str = "argon2",
        kdf_salt: Optional[bytes] = None,
        auto_lock_seconds: int = 300,
    ):
        """Initialize vault (use Vault.create() or Vault.open() instead).

        Args:
            key: 256-bit encryption key.
            vault_path: Path to the vault file.
            kdf_method: Key derivation method used.
            kdf_salt: Salt used for key derivation.
            auto_lock_seconds: Auto-lock timeout in seconds.
        """
        self._key = key
        self._vault_path = vault_path
        self._kdf_method = kdf_method
        self._kdf_salt = kdf_salt
        self._key_id = generate_key_id(key)

        self._secrets: dict[str, Secret] = {}
        self._audit_log = AuditLog()
        self._team_members: list[TeamMember] = []
        self._metadata: dict[str, Any] = {
            "version": self.FORMAT_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "key_id": self._key_id,
            "kdf_method": kdf_method,
        }

        self._locker = AutoLocker(
            timeout_seconds=auto_lock_seconds,
            on_lock=self._on_auto_lock,
        )
        self._locker.touch()

    @classmethod
    def create(
        cls,
        path: str,
        password: str,
        kdf_method: str = "argon2",
        auto_lock_seconds: int = 300,
        **kdf_kwargs,
    ) -> Vault:
        """Create a new vault.

        Args:
            path: Path to store the vault file.
            password: Master password for key derivation.
            kdf_method: Key derivation method ("argon2" or "pbkdf2").
            auto_lock_seconds: Auto-lock timeout in seconds.
            **kdf_kwargs: Additional KDF arguments.

        Returns:
            A new Vault instance.
        """
        key, salt = derive_key(password, method=kdf_method, **kdf_kwargs)
        vault = cls(
            key=key,
            vault_path=path,
            kdf_method=kdf_method,
            kdf_salt=salt,
            auto_lock_seconds=auto_lock_seconds,
        )
        vault._audit_log.log("create", details=f"Vault created at {path}")
        return vault

    @classmethod
    def open(
        cls,
        path: str,
        password: str,
        auto_lock_seconds: int = 300,
    ) -> Vault:
        """Open an existing vault.

        Args:
            path: Path to the vault file.
            password: Master password.
            auto_lock_seconds: Auto-lock timeout in seconds.

        Returns:
            A Vault instance with decrypted contents.

        Raises:
            VaultNotFoundError: If vault file doesn't exist.
            DecryptionError: If password is wrong.
        """
        if not os.path.exists(path):
            raise VaultNotFoundError(f"Vault not found: {path}")

        with open(path, "rb") as f:
            raw = f.read()

        # Parse vault file
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise VaultError(f"Invalid vault file format: {e}") from e

        # Extract metadata
        kdf_method = data.get("kdf_method", "argon2")
        kdf_salt = bytes.fromhex(data["kdf_salt"])

        # Derive key
        key, _ = derive_key(password, method=kdf_method, salt=kdf_salt)

        # Decrypt vault contents
        encrypted_vault = bytes.fromhex(data["vault_data"])
        try:
            decrypted = decrypt(encrypted_vault, key)
        except DecryptionError:
            zeroize(key)
            raise DecryptionError("Invalid password or corrupted vault")

        # Parse decrypted vault
        vault_data = json.loads(decrypted)

        vault = cls(
            key=key,
            vault_path=path,
            kdf_method=kdf_method,
            kdf_salt=kdf_salt,
            auto_lock_seconds=auto_lock_seconds,
        )

        # Load secrets
        for secret_data in vault_data.get("secrets", []):
            secret = secret_from_dict(secret_data)
            vault._secrets[secret.id] = secret

        # Load audit log
        if "audit_log" in vault_data:
            vault._audit_log = AuditLog.from_dict(vault_data["audit_log"])

        # Load team members
        for member_data in vault_data.get("team_members", []):
            vault._team_members.append(TeamMember.from_dict(member_data))

        # Load metadata
        vault._metadata.update(vault_data.get("metadata", {}))

        vault._audit_log.log("open", details=f"Vault opened from {path}")
        return vault

    def save(self) -> None:
        """Save the vault to disk.

        Raises:
            VaultError: If save fails.
        """
        if self._vault_path is None:
            raise VaultError("No vault path specified")

        self._locker.touch()

        # Prepare vault data
        vault_data = {
            "secrets": [s.to_dict() for s in self._secrets.values()],
            "audit_log": self._audit_log.to_dict(),
            "team_members": [m.to_dict() for m in self._team_members],
            "metadata": self._metadata,
        }

        # Encrypt vault data
        plaintext = json.dumps(vault_data).encode("utf-8")
        encrypted = encrypt(plaintext, self._key)

        # Build file structure
        file_data = {
            "version": self.FORMAT_VERSION,
            "kdf_method": self._kdf_method,
            "kdf_salt": self._kdf_salt.hex(),
            "vault_data": encrypted.hex(),
        }

        # Write atomically
        tmp_path = self._vault_path + ".tmp"
        try:
            with open(tmp_path, "w") as f:
                json.dump(file_data, f, indent=2)
            os.replace(tmp_path, self._vault_path)
        except OSError as e:
            raise VaultError(f"Failed to save vault: {e}") from e

        self._audit_log.log("save", details=f"Vault saved to {self._vault_path}")

    def add_secret(self, secret: Secret) -> str:
        """Add a secret to the vault.

        Args:
            secret: The secret to add.

        Returns:
            The ID of the added secret.
        """
        self._assert_unlocked()
        self._locker.touch()

        secret.updated_at = datetime.now(timezone.utc)
        self._secrets[secret.id] = secret
        self._audit_log.log(
            "add",
            secret_id=secret.id,
            details=f"Added {secret.secret_type.value}",
        )
        return secret.id

    def get_secret(self, secret_id: str) -> Optional[Secret]:
        """Retrieve a secret by ID.

        Args:
            secret_id: The secret ID.

        Returns:
            The secret, or None if not found.
        """
        self._assert_unlocked()
        self._locker.touch()

        secret = self._secrets.get(secret_id)
        if secret:
            self._audit_log.log("get", secret_id=secret_id)
        else:
            self._audit_log.log(
                "get",
                secret_id=secret_id,
                success=False,
                details="Not found",
            )
        return secret

    def delete_secret(self, secret_id: str) -> bool:
        """Delete a secret by ID.

        Args:
            secret_id: The secret ID.

        Returns:
            True if deleted, False if not found.
        """
        self._assert_unlocked()
        self._locker.touch()

        if secret_id in self._secrets:
            del self._secrets[secret_id]
            self._audit_log.log("delete", secret_id=secret_id)
            return True
        return False

    def list_secrets(
        self,
        secret_type: Optional[SecretType] = None,
        tags: Optional[list[str]] = None,
        limit: Optional[int] = None,
    ) -> list[Secret]:
        """List secrets with optional filters.

        Args:
            secret_type: Filter by secret type.
            tags: Filter by tags (AND logic).
            limit: Maximum results.

        Returns:
            List of matching secrets.
        """
        self._assert_unlocked()
        self._locker.touch()

        secrets_list = list(self._secrets.values())

        if secret_type:
            secrets_list = [s for s in secrets_list if s.secret_type == secret_type]

        if tags:
            secrets_list = [
                s for s in secrets_list
                if all(tag in s.tags for tag in tags)
            ]

        # Sort by creation date (newest first)
        secrets_list.sort(key=lambda s: s.created_at, reverse=True)

        if limit:
            secrets_list = secrets_list[:limit]

        self._audit_log.log("list", details=f"Listed {len(secrets_list)} secrets")
        return secrets_list

    def search(
        self,
        query: Optional[str] = None,
        secret_type: Optional[SecretType] = None,
        host: Optional[str] = None,
        service: Optional[str] = None,
        username: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> list[Secret]:
        """Search secrets by various criteria.

        Args:
            query: Free-text search (searches notes, metadata).
            secret_type: Filter by type.
            host: Filter by host (for credentials).
            service: Filter by service (for credentials).
            username: Filter by username (for credentials).
            tags: Filter by tags.

        Returns:
            List of matching secrets.
        """
        self._assert_unlocked()
        self._locker.touch()

        results = list(self._secrets.values())

        if secret_type:
            results = [s for s in results if s.secret_type == secret_type]

        if host:
            results = [
                s for s in results
                if isinstance(s, Credential) and host in s.host
            ]

        if service:
            results = [
                s for s in results
                if isinstance(s, Credential) and service.lower() in s.service.lower()
            ]

        if username:
            results = [
                s for s in results
                if isinstance(s, Credential) and username.lower() in s.username.lower()
            ]

        if tags:
            results = [
                s for s in results
                if all(tag in s.tags for tag in tags)
            ]

        if query:
            query_lower = query.lower()
            results = [
                s for s in results
                if query_lower in s.notes.lower()
                or query_lower in json.dumps(s.metadata).lower()
                or (isinstance(s, Credential) and (
                    query_lower in s.host.lower()
                    or query_lower in s.username.lower()
                    or query_lower in s.service.lower()
                ))
                or (isinstance(s, Host) and (
                    query_lower in s.hostname.lower()
                    or query_lower in s.ip_address.lower()
                ))
                or (isinstance(s, Note) and query_lower in s.content.lower())
            ]

        self._audit_log.log("search", details=f"Found {len(results)} results")
        return results

    def add_credential(
        self,
        host: str,
        service: str,
        username: str,
        password: str,
        port: int = 0,
        domain: str = "",
        notes: str = "",
        tags: Optional[list[str]] = None,
        **kwargs,
    ) -> Credential:
        """Convenience method to add a credential.

        Args:
            host: Target host.
            service: Service name.
            username: Username.
            password: Password.
            port: Port number.
            domain: Domain.
            notes: Notes.
            tags: Tags.

        Returns:
            The created Credential.
        """
        cred = Credential(
            host=host,
            port=port,
            service=service,
            username=username,
            password=password,
            domain=domain,
            notes=notes,
            tags=tags or [],
            **kwargs,
        )
        self.add_secret(cred)
        return cred

    def add_host(
        self,
        ip_address: str,
        hostname: str = "",
        ports: Optional[list[int]] = None,
        os_info: str = "",
        services: Optional[list[str]] = None,
        notes: str = "",
        tags: Optional[list[str]] = None,
    ) -> Host:
        """Convenience method to add a host.

        Args:
            ip_address: IP address.
            hostname: Hostname.
            ports: Open ports.
            os_info: OS information.
            services: Services running.
            notes: Notes.
            tags: Tags.

        Returns:
            The created Host.
        """
        host = Host(
            ip_address=ip_address,
            hostname=hostname,
            ports=ports or [],
            os_info=os_info,
            services=services or [],
            notes=notes,
            tags=tags or [],
        )
        self.add_secret(host)
        return host

    def add_note(
        self,
        content: str,
        category: str = "",
        notes: str = "",
        tags: Optional[list[str]] = None,
    ) -> Note:
        """Convenience method to add a note.

        Args:
            content: Note content.
            category: Note category.
            notes: Additional notes.
            tags: Tags.

        Returns:
            The created Note.
        """
        note = Note(
            content=content,
            category=category,
            notes=notes,
            tags=tags or [],
        )
        self.add_secret(note)
        return note

    def update_secret(self, secret_id: str, **kwargs) -> Optional[Secret]:
        """Update fields on an existing secret.

        Args:
            secret_id: ID of the secret to update.
            **kwargs: Fields to update.

        Returns:
            Updated secret, or None if not found.
        """
        self._assert_unlocked()
        self._locker.touch()

        secret = self._secrets.get(secret_id)
        if not secret:
            return None

        for key, value in kwargs.items():
            if hasattr(secret, key):
                setattr(secret, key, value)

        secret.updated_at = datetime.now(timezone.utc)
        self._audit_log.log("update", secret_id=secret_id)
        return secret

    def get_audit_log(
        self,
        action: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[AuditEntry]:
        """Get audit log entries.

        Args:
            action: Filter by action type.
            limit: Maximum entries.

        Returns:
            List of AuditEntry objects.
        """
        return self._audit_log.get_entries(action=action, limit=limit)

    def export_secrets(
        self,
        output_path: str,
        password: Optional[str] = None,
        secret_ids: Optional[list[str]] = None,
    ) -> None:
        """Export secrets to an encrypted file.

        Args:
            output_path: Output file path.
            password: Password for export encryption (uses vault key if None).
            secret_ids: Specific IDs to export (all if None).
        """
        self._assert_unlocked()
        self._locker.touch()

        if secret_ids:
            secrets_to_export = [
                s for sid, s in self._secrets.items() if sid in secret_ids
            ]
        else:
            secrets_to_export = list(self._secrets.values())

        export_data = [s.to_dict() for s in secrets_to_export]

        if password:
            key, salt = derive_key(password)
            key_id = generate_key_id(key)
        else:
            key = self._key
            salt = self._kdf_salt
            key_id = self._key_id

        plaintext = json.dumps(export_data).encode("utf-8")
        encrypted = encrypt(plaintext, key)

        file_data = {
            "format": "shadowvault_export",
            "version": self.FORMAT_VERSION,
            "kdf_method": self._kdf_method if not password else "argon2",
            "kdf_salt": salt.hex() if salt else self._kdf_salt.hex(),
            "data": encrypted.hex(),
        }

        with open(output_path, "w") as f:
            json.dump(file_data, f, indent=2)

        self._audit_log.log(
            "export",
            details=f"Exported {len(secrets_to_export)} secrets to {output_path}",
        )

    def import_secrets(self, secrets_list: list[Secret]) -> int:
        """Import secrets into the vault.

        Args:
            secrets_list: List of secrets to import.

        Returns:
            Number of secrets imported.
        """
        self._assert_unlocked()
        self._locker.touch()

        count = 0
        for secret in secrets_list:
            # Generate new ID to avoid collisions
            secret.id = str(__import__("uuid").uuid4())
            secret.updated_at = datetime.now(timezone.utc)
            self._secrets[secret.id] = secret
            count += 1

        self._audit_log.log("import", details=f"Imported {count} secrets")
        return count

    def lock(self) -> None:
        """Lock the vault."""
        self._audit_log.log("lock")
        self._locker.lock()

    def unlock(self, password: str) -> bool:
        """Unlock the vault.

        Args:
            password: Master password.

        Returns:
            True if unlocked successfully.
        """
        self._locker.unlock()
        self._audit_log.log("unlock")
        return True

    def _on_auto_lock(self) -> None:
        """Callback for auto-lock."""
        self._audit_log.log("auto_lock")

    def _assert_unlocked(self) -> None:
        """Assert vault is unlocked."""
        if self._locker.is_locked:
            raise VaultLockedError("Vault is locked. Call unlock() first.")

    @property
    def is_locked(self) -> bool:
        """Check if vault is locked."""
        return self._locker.is_locked

    @property
    def secret_count(self) -> int:
        """Get number of secrets in vault."""
        return len(self._secrets)

    @property
    def key_id(self) -> str:
        """Get key fingerprint."""
        return self._key_id

    @property
    def vault_path(self) -> Optional[str]:
        """Get vault file path."""
        return self._vault_path

    def cleanup(self) -> None:
        """Securely clean up vault resources."""
        self._locker.cleanup()
        zeroize_bytes(bytearray(self._key))
        self._secrets.clear()
        self._audit_log.clear()
