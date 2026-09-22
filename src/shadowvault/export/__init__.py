"""Export module for generating encrypted briefing reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..crypto import derive_key, encrypt
from ..vault.schema import (
    Credential,
    Hash,
    Host,
    Note,
    Secret,
    Token,
)


class ExportError(Exception):
    """Base exception for export operations."""


class BriefingGenerator:
    """Generate encrypted briefing reports for client handoff."""

    def __init__(self, vault_name: str = "shadowvault"):
        """Initialize briefing generator.

        Args:
            vault_name: Name of the vault.
        """
        self.vault_name = vault_name
        self._sections: list[dict[str, Any]] = []

    def add_section(self, title: str, content: Any, classification: str = "CONFIDENTIAL") -> None:
        """Add a section to the briefing.

        Args:
            title: Section title.
            content: Section content (dict, list, or string).
            classification: Security classification.
        """
        self._sections.append({
            "title": title,
            "content": content,
            "classification": classification,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def add_hosts_section(self, hosts: list[Host]) -> None:
        """Add a hosts/targets section.

        Args:
            hosts: List of Host objects.
        """
        hosts_data = []
        for host in hosts:
            hosts_data.append({
                "ip_address": host.ip_address,
                "hostname": host.hostname,
                "os_info": host.os_info,
                "ports": host.ports,
                "services": host.services,
                "notes": host.notes,
            })

        self.add_section(
            "Targets & Hosts",
            hosts_data,
            classification="CONFIDENTIAL",
        )

    def add_credentials_section(self, credentials: list[Credential]) -> None:
        """Add a credentials section.

        Args:
            credentials: List of Credential objects.
        """
        creds_data = []
        for cred in credentials:
            creds_data.append({
                "host": cred.host,
                "port": cred.port,
                "service": cred.service,
                "username": cred.username,
                "password": "[REDACTED]",  # Never include in plaintext
                "notes": cred.notes,
            })

        self.add_section(
            "Credentials",
            creds_data,
            classification="SECRET",
        )

    def add_hashes_section(self, hashes: list[Hash]) -> None:
        """Add a hashes/cracked passwords section.

        Args:
            hashes: List of Hash objects.
        """
        hashes_data = []
        for h in hashes:
            hashes_data.append({
                "hash_type": h.hash_type,
                "cracked": h.plaintext is not None,
                "source": h.source,
                "notes": h.notes,
            })

        self.add_section(
            "Hashes & Cracked Credentials",
            hashes_data,
            classification="SECRET",
        )

    def add_tokens_section(self, tokens: list[Token]) -> None:
        """Add a tokens/API keys section.

        Args:
            tokens: List of Token objects.
        """
        tokens_data = []
        for token in tokens:
            tokens_data.append({
                "token_type": token.token_type,
                "issuer": token.issuer,
                "scopes": token.scopes,
                "has_value": bool(token.token_value),
                "notes": token.notes,
            })

        self.add_section(
            "API Tokens & Keys",
            tokens_data,
            classification="SECRET",
        )

    def add_notes_section(self, notes: list[Note]) -> None:
        """Add a notes section.

        Args:
            notes: List of Note objects.
        """
        notes_data = []
        for note in notes:
            notes_data.append({
                "content": note.content,
                "category": note.category,
                "notes": note.notes,
            })

        self.add_section(
            "Notes & Observations",
            notes_data,
            classification="CONFIDENTIAL",
        )

    def add_summary(
        self,
        total_secrets: int,
        by_type: dict[str, int] | None = None,
        engagement_info: dict[str, str] | None = None,
    ) -> None:
        """Add a summary section.

        Args:
            total_secrets: Total number of secrets.
            by_type: Count by secret type.
            engagement_info: Engagement metadata.
        """
        summary = {
            "total_secrets": total_secrets,
            "by_type": by_type or {},
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": self.vault_name,
        }

        if engagement_info:
            summary["engagement"] = engagement_info

        self.add_section("Executive Summary", summary, classification="CONFIDENTIAL")

    def generate(self) -> dict[str, Any]:
        """Generate the briefing document structure.

        Returns:
            Briefing document as dictionary.
        """
        return {
            "format": "shadowvault_briefing",
            "version": "1.0.0",
            "vault": self.vault_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "classification": "CONFIDENTIAL",
            "sections": self._sections,
        }

    def to_json(self, indent: int | None = None) -> str:
        """Generate briefing as JSON string.

        Args:
            indent: JSON indentation.

        Returns:
            JSON string.
        """
        return json.dumps(self.generate(), indent=indent, default=str)

    def encrypt_briefing(
        self,
        password: str,
        output_path: str | None = None,
    ) -> bytes:
        """Encrypt the briefing for secure transport.

        Args:
            password: Encryption password.
            output_path: Optional file path to write encrypted data.

        Returns:
            Encrypted briefing bytes.
        """
        briefing_json = self.to_json().encode("utf-8")
        key, salt = derive_key(password)
        encrypted = encrypt(briefing_json, key)

        result = {
            "format": "shadowvault_encrypted_briefing",
            "version": "1.0.0",
            "kdf_salt": salt.hex(),
            "data": encrypted.hex(),
        }

        result_bytes = json.dumps(result).encode("utf-8")

        if output_path:
            with open(output_path, "wb") as f:
                f.write(result_bytes)

        return result_bytes

    def clear(self) -> None:
        """Clear all sections."""
        self._sections.clear()


def generate_quick_briefing(
    secrets: list[Secret],
    client_name: str = "Client",
    vault_name: str = "shadowvault",
) -> BriefingGenerator:
    """Generate a quick briefing from a list of secrets.

    Args:
        secrets: List of all secrets.
        client_name: Client name.
        vault_name: Vault name.

    Returns:
        Configured BriefingGenerator.
    """
    gen = BriefingGenerator(vault_name=vault_name)

    # Categorize secrets
    hosts = [s for s in secrets if isinstance(s, Host)]
    credentials = [s for s in secrets if isinstance(s, Credential)]
    hashes = [s for s in secrets if isinstance(s, Hash)]
    tokens = [s for s in secrets if isinstance(s, Token)]
    notes = [s for s in secrets if isinstance(s, Note)]

    # Count by type
    by_type = {}
    for s in secrets:
        t = s.secret_type.value
        by_type[t] = by_type.get(t, 0) + 1

    # Add sections
    gen.add_summary(
        total_secrets=len(secrets),
        by_type=by_type,
        engagement_info={"client": client_name},
    )

    if hosts:
        gen.add_hosts_section(hosts)

    if credentials:
        gen.add_credentials_section(credentials)

    if hashes:
        gen.add_hashes_section(hashes)

    if tokens:
        gen.add_tokens_section(tokens)

    if notes:
        gen.add_notes_section(notes)

    return gen
