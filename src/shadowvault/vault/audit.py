"""Audit logging for shadowvault."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .schema import AuditEntry


class AuditLog:
    """Append-only audit log for vault operations."""

    def __init__(self):
        self._entries: list[AuditEntry] = []

    def log(
        self,
        action: str,
        secret_id: str | None = None,
        user: str = "local",
        details: str = "",
        success: bool = True,
    ) -> AuditEntry:
        """Log an audit event.

        Args:
            action: The action performed (e.g., "add", "get", "decrypt").
            secret_id: ID of the secret affected (if any).
            user: User performing the action.
            details: Additional details.
            success: Whether the operation succeeded.

        Returns:
            The created AuditEntry.
        """
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            action=action,
            secret_id=secret_id,
            user=user,
            details=details,
            success=success,
        )
        self._entries.append(entry)
        return entry

    def get_entries(
        self,
        action: str | None = None,
        user: str | None = None,
        secret_id: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Retrieve audit entries with optional filters.

        Args:
            action: Filter by action type.
            user: Filter by user.
            secret_id: Filter by secret ID.
            limit: Maximum entries to return.
            offset: Number of entries to skip.

        Returns:
            List of matching AuditEntry objects.
        """
        entries = self._entries

        if action:
            entries = [e for e in entries if e.action == action]
        if user:
            entries = [e for e in entries if e.user == user]
        if secret_id:
            entries = [e for e in entries if e.secret_id == secret_id]

        if offset > 0:
            entries = entries[offset:]

        if limit is not None:
            entries = entries[:limit]

        return entries

    def count(
        self,
        action: str | None = None,
        user: str | None = None,
    ) -> int:
        """Count audit entries with optional filters."""
        entries = self._entries
        if action:
            entries = [e for e in entries if e.action == action]
        if user:
            entries = [e for e in entries if e.user == user]
        return len(entries)

    def to_dict(self) -> list[dict]:
        """Serialize audit log to list of dicts."""
        return [entry.to_dict() for entry in self._entries]

    @classmethod
    def from_dict(cls, data: list[dict]) -> AuditLog:
        """Deserialize audit log from list of dicts."""
        log = cls()
        log._entries = [AuditEntry.from_dict(entry) for entry in data]
        return log

    def to_json(self, indent: int | None = None) -> str:
        """Serialize audit log to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_json(cls, json_str: str) -> AuditLog:
        """Deserialize audit log from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)

    def clear(self) -> None:
        """Clear all audit entries."""
        self._entries.clear()
