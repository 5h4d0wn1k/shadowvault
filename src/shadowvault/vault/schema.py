"""Vault data schemas for shadowvault."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SecretType(Enum):
    """Types of secrets stored in the vault."""
    CREDENTIAL = "credential"
    HOST = "host"
    TOKEN = "token"  # noqa: S105
    HASH = "hash"
    KEY = "key"
    NOTE = "note"


class TeamRole(Enum):
    """Roles for team members."""
    OWNER = "owner"
    ANNOTATOR = "annotator"
    VIEWER = "viewer"


@dataclass
class Secret:
    """Base secret record."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    secret_type: SecretType = SecretType.NOTE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "secret_type": self.secret_type.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "tags": self.tags,
            "notes": self.notes,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Secret:
        return cls(
            id=data["id"],
            secret_type=SecretType(data["secret_type"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            tags=data.get("tags", []),
            notes=data.get("notes", ""),
            metadata=data.get("metadata", {}),
        )


@dataclass
class Host(Secret):
    """Host/target information."""
    ip_address: str = ""
    hostname: str = ""
    ports: list[int] = field(default_factory=list)
    os_info: str = ""
    services: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.secret_type = SecretType.HOST

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "ports": self.ports,
            "os_info": self.os_info,
            "services": self.services,
        })
        return base

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Host:
        return cls(
            id=data["id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            tags=data.get("tags", []),
            notes=data.get("notes", ""),
            metadata=data.get("metadata", {}),
            ip_address=data.get("ip_address", ""),
            hostname=data.get("hostname", ""),
            ports=data.get("ports", []),
            os_info=data.get("os_info", ""),
            services=data.get("services", []),
        )


@dataclass
class Credential(Secret):
    """Credential secret."""
    host: str = ""
    port: int = 0
    service: str = ""
    username: str = ""
    password: str = ""
    domain: str = ""
    realm: str = ""
    last_used: datetime | None = None
    expires_at: datetime | None = None
    rotation_recommended: bool = False

    def __post_init__(self):
        self.secret_type = SecretType.CREDENTIAL

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "username": self.username,
            "password": self.password,
            "domain": self.domain,
            "realm": self.realm,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rotation_recommended": self.rotation_recommended,
        })
        return base

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Credential:
        return cls(
            id=data["id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            tags=data.get("tags", []),
            notes=data.get("notes", ""),
            metadata=data.get("metadata", {}),
            host=data.get("host", ""),
            port=data.get("port", 0),
            service=data.get("service", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
            domain=data.get("domain", ""),
            realm=data.get("realm", ""),
            last_used=(
                datetime.fromisoformat(data["last_used"]) if data.get("last_used") else None
            ),
            expires_at=(
                datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None
            ),
            rotation_recommended=data.get("rotation_recommended", False),
        )


@dataclass
class Token(Secret):
    """API/OAuth token."""
    token_type: str = ""
    token_value: str = ""
    issuer: str = ""
    scopes: list[str] = field(default_factory=list)
    expires_at: datetime | None = None

    def __post_init__(self):
        self.secret_type = SecretType.TOKEN

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "token_type": self.token_type,
            "token_value": self.token_value,
            "issuer": self.issuer,
            "scopes": self.scopes,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        })
        return base

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Token:
        return cls(
            id=data["id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            tags=data.get("tags", []),
            notes=data.get("notes", ""),
            metadata=data.get("metadata", {}),
            token_type=data.get("token_type", ""),
            token_value=data.get("token_value", ""),
            issuer=data.get("issuer", ""),
            scopes=data.get("scopes", []),
            expires_at=(
                datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None
            ),
        )


@dataclass
class Hash(Secret):
    """Password hash or hash crack result."""
    hash_value: str = ""
    hash_type: str = ""
    plaintext: str | None = None
    source: str = ""
    crack_time: float | None = None

    def __post_init__(self):
        self.secret_type = SecretType.HASH

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "hash_value": self.hash_value,
            "hash_type": self.hash_type,
            "plaintext": self.plaintext,
            "source": self.source,
            "crack_time": self.crack_time,
        })
        return base

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Hash:
        return cls(
            id=data["id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            tags=data.get("tags", []),
            notes=data.get("notes", ""),
            metadata=data.get("metadata", {}),
            hash_value=data.get("hash_value", ""),
            hash_type=data.get("hash_type", ""),
            plaintext=data.get("plaintext"),
            source=data.get("source", ""),
            crack_time=data.get("crack_time"),
        )


@dataclass
class EncryptionKey(Secret):
    """Encryption key (private keys, symmetric keys)."""
    key_type: str = ""
    key_data: str = ""
    key_format: str = ""
    fingerprint: str = ""
    purpose: str = ""

    def __post_init__(self):
        self.secret_type = SecretType.KEY

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "key_type": self.key_type,
            "key_data": self.key_data,
            "key_format": self.key_format,
            "fingerprint": self.fingerprint,
            "purpose": self.purpose,
        })
        return base

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EncryptionKey:
        return cls(
            id=data["id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            tags=data.get("tags", []),
            notes=data.get("notes", ""),
            metadata=data.get("metadata", {}),
            key_type=data.get("key_type", ""),
            key_data=data.get("key_data", ""),
            key_format=data.get("key_format", ""),
            fingerprint=data.get("fingerprint", ""),
            purpose=data.get("purpose", ""),
        )


@dataclass
class Note(Secret):
    """Freeform note."""
    content: str = ""
    category: str = ""

    def __post_init__(self):
        self.secret_type = SecretType.NOTE

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "content": self.content,
            "category": self.category,
        })
        return base

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Note:
        return cls(
            id=data["id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            tags=data.get("tags", []),
            notes=data.get("notes", ""),
            metadata=data.get("metadata", {}),
            content=data.get("content", ""),
            category=data.get("category", ""),
        )


def secret_from_dict(data: dict[str, Any]) -> Secret:
    """Factory function to create the correct Secret subclass from a dict."""
    secret_type = data.get("secret_type", "note")
    type_map = {
        "credential": Credential,
        "host": Host,
        "token": Token,
        "hash": Hash,
        "key": EncryptionKey,
        "note": Note,
    }
    cls = type_map.get(secret_type, Note)
    return cls.from_dict(data)


@dataclass
class AuditEntry:
    """Audit log entry."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action: str = ""
    secret_id: str | None = None
    user: str = "local"
    details: str = ""
    success: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "secret_id": self.secret_id,
            "user": self.user,
            "details": self.details,
            "success": self.success,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            action=data["action"],
            secret_id=data.get("secret_id"),
            user=data.get("user", "local"),
            details=data.get("details", ""),
            success=data.get("success", True),
        )


@dataclass
class TeamMember:
    """Team member with RBAC."""
    user_id: str = ""
    email: str = ""
    role: TeamRole = TeamRole.VIEWER
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    added_by: str = ""
    active: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "email": self.email,
            "role": self.role.value,
            "added_at": self.added_at.isoformat(),
            "added_by": self.added_by,
            "active": self.active,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TeamMember:
        return cls(
            user_id=data["user_id"],
            email=data["email"],
            role=TeamRole(data["role"]),
            added_at=datetime.fromisoformat(data["added_at"]),
            added_by=data.get("added_by", ""),
            active=data.get("active", True),
        )
