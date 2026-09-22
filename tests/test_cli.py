"""Tests for CLI interface."""

import getpass
import os
from datetime import datetime, timedelta, timezone

import pytest

from shadowvault.cli.main import (
    build_parser,
    format_secret,
    main,
)
from shadowvault.vault import (
    Credential,
    Hash,
    Host,
    Note,
    Token,
)


class TestCLIFormatting:
    """Tests for CLI output formatting."""

    def test_format_credential(self):
        """Test formatting credential."""
        cred = Credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="secret",
        )
        formatted = format_secret(cred)
        assert "10.0.0.5" in formatted
        assert "admin" in formatted
        assert "ssh" in formatted

    def test_format_host(self):
        """Test formatting host."""
        host = Host(
            ip_address="10.0.0.1",
            hostname="dc01",
            ports=[22, 80, 443],
        )
        formatted = format_secret(host)
        assert "10.0.0.1" in formatted
        assert "dc01" in formatted
        assert "22" in formatted

    def test_format_note(self):
        """Test formatting note."""
        note = Note(content="Test note", category="recon")
        formatted = format_secret(note)
        assert "recon" in formatted

    def test_format_hash(self):
        """Test formatting hash."""
        h = Hash(hash_value="abc123def456", plaintext="hello")
        formatted = format_secret(h)
        assert "abc123" in formatted
        assert "[CRACKED]" in formatted

    def test_format_token(self):
        """Test formatting token."""
        token = Token(token_type="totp", issuer="GitHub")
        formatted = format_secret(token)
        assert "totp" in formatted
        assert "GitHub" in formatted

    def test_format_credential_expiring(self):
        """Test formatting credential with expiry."""
        from datetime import datetime, timedelta, timezone
        cred = Credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="secret",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        formatted = format_secret(cred)
        assert "expires" in formatted

    def test_format_credential_rotation_needed(self):
        """Test formatting credential needing rotation."""
        cred = Credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="secret",
            rotation_recommended=True,
        )
        formatted = format_secret(cred)
        assert "ROTATION" in formatted


class TestCLIParser:
    """Tests for CLI argument parser."""

    def test_parser_creation(self):
        """Test parser creation."""
        parser = build_parser()
        assert parser is not None

    def test_version_flag(self):
        """Test version flag."""
        parser = build_parser()
        args = parser.parse_args(["--version"])
        assert args.version is True

    def test_init_command(self):
        """Test init command parsing."""
        parser = build_parser()
        args = parser.parse_args(["init"])
        assert args.command == "init"

    def test_init_kdf_method(self):
        """Test init with KDF method."""
        parser = build_parser()
        args = parser.parse_args(["init", "--kdf-method", "pbkdf2"])
        assert args.kdf_method == "pbkdf2"

    def test_add_credential(self):
        """Test add credential command."""
        parser = build_parser()
        args = parser.parse_args([
            "add", "credential",
            "--host", "10.0.0.5",
            "--service", "ssh",
            "--username", "admin",
            "--password", "pass",
            "--port", "22",
        ])
        assert args.command == "add"
        assert args.type == "credential"
        assert args.host == "10.0.0.5"

    def test_add_host(self):
        """Test add host command."""
        parser = build_parser()
        args = parser.parse_args([
            "add", "host",
            "--host", "10.0.0.1",
            "--hostname", "dc01",
            "--os", "Windows Server 2019",
        ])
        assert args.type == "host"
        assert args.hostname == "dc01"

    def test_add_note(self):
        """Test add note command."""
        parser = build_parser()
        args = parser.parse_args([
            "add", "note",
            "--content", "Important finding",
            "--category", "recon",
        ])
        assert args.type == "note"
        assert args.content == "Important finding"

    def test_add_hash(self):
        """Test add hash command."""
        parser = build_parser()
        args = parser.parse_args([
            "add", "hash",
            "--hash", "abc123",
            "--hash-type", "MD5",
            "--source", "hashcat",
        ])
        assert args.type == "hash"
        assert args.hash == "abc123"

    def test_get_command(self):
        """Test get command."""
        parser = build_parser()
        args = parser.parse_args(["get", "abc-123"])
        assert args.command == "get"
        assert args.id == "abc-123"

    def test_get_show_password(self):
        """Test get with show-password."""
        parser = build_parser()
        args = parser.parse_args(["get", "abc-123", "--show-password"])
        assert args.show_password is True

    def test_list_command(self):
        """Test list command."""
        parser = build_parser()
        args = parser.parse_args(["list"])
        assert args.command == "list"

    def test_list_with_type(self):
        """Test list with type filter."""
        parser = build_parser()
        args = parser.parse_args(["list", "--type", "credential"])
        assert args.type == "credential"

    def test_list_with_tag(self):
        """Test list with tag filter."""
        parser = build_parser()
        args = parser.parse_args(["list", "--tag", "prod", "--tag", "ssh"])
        assert args.tag == ["prod", "ssh"]

    def test_list_with_limit(self):
        """Test list with limit."""
        parser = build_parser()
        args = parser.parse_args(["list", "--limit", "10"])
        assert args.limit == 10

    def test_search_command(self):
        """Test search command."""
        parser = build_parser()
        args = parser.parse_args(["search", "dc01"])
        assert args.command == "search"
        assert args.query == "dc01"

    def test_search_with_filters(self):
        """Test search with filters."""
        parser = build_parser()
        args = parser.parse_args([
            "search",
            "--host", "10.0.0.0/24",
            "--service", "ssh",
            "--username", "admin",
        ])
        assert args.host == "10.0.0.0/24"
        assert args.service == "ssh"

    def test_export_command(self):
        """Test export command."""
        parser = build_parser()
        args = parser.parse_args(["export", "--output", "export.enc"])
        assert args.command == "export"
        assert args.output == "export.enc"

    def test_export_with_password(self):
        """Test export with password."""
        parser = build_parser()
        args = parser.parse_args(["export", "-o", "export.enc", "--password", "pass"])
        assert args.password == "pass"

    def test_import_command(self):
        """Test import command."""
        parser = build_parser()
        args = parser.parse_args(["import", "--file", "export.csv", "--format", "keepass"])
        assert args.command == "import"
        assert args.file == "export.csv"
        assert args.format == "keepass"

    def test_import_auto_format(self):
        """Test import with auto format detection."""
        parser = build_parser()
        args = parser.parse_args(["import", "-f", "export.csv"])
        assert args.format == "auto"

    def test_import_with_service(self):
        """Test import with service specification."""
        parser = build_parser()
        args = parser.parse_args([
            "import", "-f", "creds.txt",
            "--format", "plaintext",
            "--service", "ssh",
        ])
        assert args.service == "ssh"

    def test_rotate_command(self):
        """Test rotate command."""
        parser = build_parser()
        args = parser.parse_args(["rotate"])
        assert args.command == "rotate"

    def test_rotate_mark(self):
        """Test rotate with mark."""
        parser = build_parser()
        args = parser.parse_args(["rotate", "--mark"])
        assert args.mark is True

    def test_audit_command(self):
        """Test audit command."""
        parser = build_parser()
        args = parser.parse_args(["audit"])
        assert args.command == "audit"

    def test_audit_with_action(self):
        """Test audit with action filter."""
        parser = build_parser()
        args = parser.parse_args(["audit", "--action", "add"])
        assert args.action == "add"

    def test_lock_command(self):
        """Test lock command."""
        parser = build_parser()
        args = parser.parse_args(["lock"])
        assert args.command == "lock"

    def test_unlock_command(self):
        """Test unlock command."""
        parser = build_parser()
        args = parser.parse_args(["unlock"])
        assert args.command == "unlock"

    def test_brief_command(self):
        """Test brief command."""
        parser = build_parser()
        args = parser.parse_args(["brief", "--client", "Test Corp"])
        assert args.command == "brief"
        assert args.client == "Test Corp"

    def test_brief_with_output(self):
        """Test brief with output."""
        parser = build_parser()
        args = parser.parse_args(["brief", "--client", "Corp", "-o", "brief.enc"])
        assert args.output == "brief.enc"

    def test_vault_argument(self):
        """Test vault path argument."""
        parser = build_parser()
        args = parser.parse_args(["--vault", "/path/to/vault", "list"])
        assert args.vault == "/path/to/vault"


class TestCLIIntegration:
    """Integration tests for CLI commands."""

    def test_version_command(self, capsys):
        """Test version command output."""
        ret = main(["--version"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "shadowvault" in captured.out

    def test_no_command(self, capsys):
        """Test no command shows help."""
        ret = main([])
        assert ret == 0
        captured = capsys.readouterr()
        assert "shadowvault" in captured.out

    def test_init_vault(self, tmp_path, monkeypatch):
        """Test initializing a vault."""
        vault_path = str(tmp_path / "test.vault")
        monkeypatch.setattr("sys.stdin", open("/dev/null"))
        monkeypatch.setattr("getpass.getpass", lambda _: "test_password")

        ret = main(["--vault", vault_path, "init"])
        assert ret == 0
        assert os.path.exists(vault_path)

    def test_invalid_command(self):
        """Test invalid command."""
        with pytest.raises(SystemExit) as exc_info:
            main(["invalid_command"])
        assert exc_info.value.code == 2  # argparse error

    def test_rotate_command_end_to_end(self, tmp_path, monkeypatch):
        """Test rotate command runs against a real vault (regression for datetime bug)."""
        vault_path = str(tmp_path / "rotate.vault")
        monkeypatch.setattr(getpass, "getpass", lambda prompt="": "test_password")

        from shadowvault.vault import Vault

        vault = Vault.create(path=vault_path, password="test_password")
        vault.add_credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="secret",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        vault.save()

        ret = main(["--vault", vault_path, "rotate"])
        assert ret == 0

    def test_rotate_mark_end_to_end(self, tmp_path, monkeypatch, capsys):
        """Test rotate --mark end-to-end (regression for datetime bug)."""
        vault_path = str(tmp_path / "mark.vault")
        monkeypatch.setattr(getpass, "getpass", lambda prompt="": "test_password")

        from shadowvault.vault import Vault

        vault = Vault.create(path=vault_path, password="test_password")
        vault.add_credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="secret",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        vault.save()

        ret = main(["--vault", vault_path, "rotate", "--mark"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "Found" in captured.out

    def test_brief_command_end_to_end(self, tmp_path, monkeypatch, capsys):
        """Test brief command runs against a real vault (regression for datetime bug)."""
        vault_path = str(tmp_path / "brief.vault")
        output_path = str(tmp_path / "client_20260101.enc")
        monkeypatch.setattr(getpass, "getpass", lambda prompt="": "test_password")
        monkeypatch.setattr(
            os.path,
            "expanduser",
            lambda path: output_path if "briefing_" in path else path,
        )

        from shadowvault.vault import Vault

        vault = Vault.create(path=vault_path, password="test_password")
        vault.add_credential(
            host="10.0.0.5",
            service="ssh",
            username="admin",
            password="secret",
        )
        vault.save()

        ret = main(["--vault", vault_path, "brief", "--client", "client"])
        assert ret == 0
        assert os.path.exists(output_path)
        captured = capsys.readouterr()
        assert "saved" in captured.out
