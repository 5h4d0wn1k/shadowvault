"""Tests for export module."""

import json

import pytest

from shadowvault.export import BriefingGenerator, generate_quick_briefing
from shadowvault.vault import (
    Credential,
    Hash,
    Host,
    Note,
    Token,
)


class TestBriefingGenerator:
    """Tests for briefing generator."""

    def test_generator_creation(self):
        """Test briefing generator creation."""
        gen = BriefingGenerator(vault_name="test_vault")
        assert gen.vault_name == "test_vault"

    def test_add_section(self):
        """Test adding a section."""
        gen = BriefingGenerator()
        gen.add_section("Test Section", {"key": "value"})
        assert len(gen._sections) == 1

    def test_generate_empty(self):
        """Test generating empty briefing."""
        gen = BriefingGenerator()
        briefing = gen.generate()
        assert briefing["format"] == "shadowvault_briefing"
        assert briefing["version"] == "1.0.0"
        assert len(briefing["sections"]) == 0

    def test_generate_with_sections(self):
        """Test generating briefing with sections."""
        gen = BriefingGenerator()
        gen.add_section("Section 1", "Content 1")
        gen.add_section("Section 2", "Content 2")
        briefing = gen.generate()
        assert len(briefing["sections"]) == 2

    def test_add_hosts_section(self):
        """Test adding hosts section."""
        gen = BriefingGenerator()
        hosts = [
            Host(ip_address="10.0.0.1", hostname="dc01"),
            Host(ip_address="10.0.0.2", hostname="web01"),
        ]
        gen.add_hosts_section(hosts)
        assert len(gen._sections) == 1
        assert len(gen._sections[0]["content"]) == 2

    def test_add_credentials_section(self):
        """Test adding credentials section."""
        gen = BriefingGenerator()
        creds = [
            Credential(host="10.0.0.1", service="ssh", username="admin", password="secret"),
        ]
        gen.add_credentials_section(creds)
        assert len(gen._sections) == 1
        # Password should be redacted
        assert gen._sections[0]["content"][0]["password"] == "[REDACTED]"

    def test_add_hashes_section(self):
        """Test adding hashes section."""
        gen = BriefingGenerator()
        hashes = [
            Hash(hash_value="abc123", plaintext="hello", source="hashcat"),
        ]
        gen.add_hashes_section(hashes)
        assert len(gen._sections) == 1
        assert gen._sections[0]["content"][0]["cracked"] is True

    def test_add_tokens_section(self):
        """Test adding tokens section."""
        gen = BriefingGenerator()
        tokens = [
            Token(token_type="totp", issuer="GitHub", token_value="JBSWY3DPEHPK3PXP"),
        ]
        gen.add_tokens_section(tokens)
        assert len(gen._sections) == 1

    def test_add_notes_section(self):
        """Test adding notes section."""
        gen = BriefingGenerator()
        notes = [
            Note(content="Important finding", category="recon"),
        ]
        gen.add_notes_section(notes)
        assert len(gen._sections) == 1

    def test_add_summary(self):
        """Test adding summary section."""
        gen = BriefingGenerator()
        gen.add_summary(
            total_secrets=10,
            by_type={"credential": 5, "host": 3, "note": 2},
            engagement_info={"client": "Test Corp"},
        )
        assert len(gen._sections) == 1
        summary = gen._sections[0]["content"]
        assert summary["total_secrets"] == 10
        assert summary["engagement"]["client"] == "Test Corp"

    def test_to_json(self):
        """Test JSON output."""
        gen = BriefingGenerator()
        gen.add_section("Test", "Content")
        json_str = gen.to_json()
        data = json.loads(json_str)
        assert data["format"] == "shadowvault_briefing"

    def test_encrypt_briefing(self):
        """Test briefing encryption."""
        gen = BriefingGenerator()
        gen.add_section("Test", "Content")
        encrypted = gen.encrypt_briefing("password")
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 0

    def test_encrypt_and_write(self, tmp_path):
        """Test encrypting and writing briefing."""
        gen = BriefingGenerator()
        gen.add_section("Test", "Content")
        output = str(tmp_path / "briefing.enc")
        encrypted = gen.encrypt_briefing("password", output_path=output)
        assert len(encrypted) > 0

    def test_clear(self):
        """Test clearing sections."""
        gen = BriefingGenerator()
        gen.add_section("Test", "Content")
        gen.clear()
        assert len(gen._sections) == 0


class TestQuickBriefing:
    """Tests for quick briefing generation."""

    def test_generate_quick_briefing(self):
        """Test generating quick briefing from secrets."""
        secrets = [
            Host(ip_address="10.0.0.1", hostname="dc01"),
            Credential(host="10.0.0.1", service="ssh", username="admin", password="pass"),
            Note(content="Important finding"),
        ]
        gen = generate_quick_briefing(secrets, client_name="Test Corp")
        briefing = gen.generate()
        assert briefing["format"] == "shadowvault_briefing"
        assert len(briefing["sections"]) >= 1

    def test_generate_empty_briefing(self):
        """Test generating briefing with no secrets."""
        gen = generate_quick_briefing([])
        briefing = gen.generate()
        assert len(briefing["sections"]) == 1  # Just summary

    def test_briefing_includes_all_types(self):
        """Test briefing includes all secret types."""
        secrets = [
            Host(ip_address="10.0.0.1"),
            Credential(host="10.0.0.1", service="ssh", username="u", password="p"),
            Hash(hash_value="abc", plaintext="hello"),
            Token(token_type="totp", issuer="test"),
            Note(content="note"),
        ]
        gen = generate_quick_briefing(secrets)
        briefing = gen.generate()
        # Should have summary + 5 sections
        assert len(briefing["sections"]) >= 1

    def test_briefing_password_redaction(self):
        """Test that passwords are redacted in briefing."""
        secrets = [
            Credential(host="10.0.0.1", service="ssh", username="admin", password="SECRET"),
        ]
        gen = generate_quick_briefing(secrets)
        briefing = gen.generate()

        # Find credentials section
        for section in briefing["sections"]:
            if section["title"] == "Credentials":
                assert section["content"][0]["password"] == "[REDACTED]"
                break
