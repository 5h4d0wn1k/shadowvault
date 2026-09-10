"""Vault module for shadowvault."""

from .audit import AuditLog
from .manager import (
    Vault,
    VaultError,
    VaultLockedError,
    VaultNotFoundError,
)
from .opsec import (
    AutoLocker,
    MemoryGuard,
    SecureString,
    zeroize_bytes,
)
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

__all__ = [
    "AuditEntry",
    "AuditLog",
    "AutoLocker",
    "Credential",
    "EncryptionKey",
    "Hash",
    "Host",
    "MemoryGuard",
    "Note",
    "Secret",
    "SecretType",
    "SecureString",
    "TeamMember",
    "TeamRole",
    "Token",
    "Vault",
    "VaultError",
    "VaultLockedError",
    "VaultNotFoundError",
    "secret_from_dict",
    "zeroize_bytes",
]
