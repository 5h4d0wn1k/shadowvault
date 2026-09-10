"""Tests for migration tools."""

import json

import pytest

from shadowvault.migration import (
    detect_format,
    import_bitwarden_json,
    import_hashcat_potfile,
    import_john_potfile,
    import_keepass_csv,
    import_plaintext,
)


class TestKeepassCSVImport:
    """Tests for KeePass CSV import."""

    def test_basic_import(self):
        """Test basic KeePass CSV import."""
        csv = """Group,Title,URL,Username,Password,Notes
Work,Admin SSH,http://10.0.0.5:22,admin,P@ssw0rd!,Admin credentials
Web,GitHub,https://github.com,user@corp.com,secret123,GitHub account"""
        secrets = import_keepass_csv(csv)
        assert len(secrets) == 2
        assert secrets[0].host == "10.0.0.5"
        assert secrets[0].username == "admin"
        assert secrets[1].service == "http"

    def test_url_parsing(self):
        """Test URL parsing in KeePass CSV."""
        csv = """Group,Title,URL,Username,Password,Notes
Test,SSH Server,ssh://192.168.1.100:22,admin,password123,
Test,RDP Server,rdp://10.0.0.10:3389,domain\\user,password456,
"""
        secrets = import_keepass_csv(csv)
        assert len(secrets) == 2
        assert secrets[0].service == "ssh"
        assert secrets[1].service == "rdp"

    def test_empty_csv(self):
        """Test empty CSV."""
        csv = """Group,Title,URL,Username,Password,Notes"""
        secrets = import_keepass_csv(csv)
        assert len(secrets) == 0

    def test_special_characters(self):
        """Test special characters in password."""
        csv = """Group,Title,URL,Username,Password,Notes
Test,Special,http://host.com,user,p@$$w0rd!#%^&*(),
"""
        secrets = import_keepass_csv(csv)
        assert secrets[0].password == "p@$$w0rd!#%^&*()"

    def test_group_tagging(self):
        """Test that group is added as tag."""
        csv = """Group,Title,URL,Username,Password,Notes
Critical,Admin,http://host.com,admin,pass,Important
"""
        secrets = import_keepass_csv(csv)
        assert "keepass:Critical" in secrets[0].tags


class TestBitwardenJSONImport:
    """Tests for Bitwarden JSON import."""

    def test_login_import(self):
        """Test Bitwarden login item import."""
        json_data = {
            "items": [
                {
                    "type": 1,
                    "name": "GitHub",
                    "login": {
                        "username": "user@example.com",
                        "password": "secret123",
                        "totp": "JBSWY3DPEHPK3PXP",
                        "uris": [{"uri": "https://github.com"}],
                    },
                    "notes": "My GitHub account",
                    "folder": "Work",
                    "tags": ["coding"],
                }
            ]
        }
        secrets = import_bitwarden_json(json.dumps(json_data))
        # Should have credential + token
        assert len(secrets) == 2
        creds = [s for s in secrets if hasattr(s, "password")]
        tokens = [s for s in secrets if hasattr(s, "token_value")]
        assert len(creds) == 1
        assert len(tokens) == 1

    def test_secure_note_import(self):
        """Test Bitwarden secure note import."""
        json_data = {
            "items": [
                {
                    "type": 2,
                    "name": "Important Note",
                    "notes": "This is sensitive information",
                    "folder": "",
                    "tags": [],
                }
            ]
        }
        secrets = import_bitwarden_json(json.dumps(json_data))
        assert len(secrets) == 1
        assert secrets[0].content == "This is sensitive information"

    def test_card_import(self):
        """Test Bitwarden card import."""
        json_data = {
            "items": [
                {
                    "type": 3,
                    "name": "Corporate Card",
                    "card": {
                        "cardholderName": "John Doe",
                        "brand": "Visa",
                        "number": "4111111111111111",
                        "expMonth": "12",
                        "expYear": "2025",
                        "code": "123",
                    },
                    "folder": "",
                    "tags": [],
                }
            ]
        }
        secrets = import_bitwarden_json(json.dumps(json_data))
        assert len(secrets) == 1
        assert "Visa" in secrets[0].content

    def test_identity_import(self):
        """Test Bitwarden identity import."""
        json_data = {
            "items": [
                {
                    "type": 4,
                    "name": "My Identity",
                    "identity": {
                        "firstName": "John",
                        "lastName": "Doe",
                        "email": "john@example.com",
                    },
                    "folder": "",
                    "tags": [],
                }
            ]
        }
        secrets = import_bitwarden_json(json.dumps(json_data))
        assert len(secrets) == 1
        assert "john@example.com" in secrets[0].content

    def test_empty_bitwarden(self):
        """Test empty Bitwarden export."""
        json_data = {"items": []}
        secrets = import_bitwarden_json(json.dumps(json_data))
        assert len(secrets) == 0

    def test_bitwarden_with_no_uris(self):
        """Test Bitwarden item without URIs."""
        json_data = {
            "items": [
                {
                    "type": 1,
                    "name": "Local App",
                    "login": {
                        "username": "admin",
                        "password": "pass",
                        "uris": [],
                    },
                    "folder": "",
                    "tags": [],
                }
            ]
        }
        secrets = import_bitwarden_json(json.dumps(json_data))
        assert len(secrets) == 1

    def test_bitwarden_metadata(self):
        """Test Bitwarden import preserves metadata."""
        json_data = {
            "items": [
                {
                    "type": 1,
                    "name": "Test",
                    "login": {
                        "username": "u",
                        "password": "p",
                        "totp": "123",
                        "uris": [{"uri": "https://test.com"}],
                    },
                    "folder": "Work",
                    "tags": ["important"],
                }
            ]
        }
        secrets = import_bitwarden_json(json.dumps(json_data))
        cred = [s for s in secrets if hasattr(s, "password")][0]
        assert cred.metadata["source"] == "bitwarden_json"
        assert "bitwarden:Work" in cred.tags


class TestPlaintextImport:
    """Tests for plaintext import."""

    def test_user_pass_format(self):
        """Test user:pass format."""
        content = """admin:P@ssw0rd!
user:password123
web:secret456"""
        secrets = import_plaintext(content)
        assert len(secrets) == 3
        assert secrets[0].username == "admin"
        assert secrets[0].password == "P@ssw0rd!"

    def test_user_host_pass_format(self):
        """Test user:pass:host format."""
        content = "admin:pass123:10.0.0.5"
        secrets = import_plaintext(content)
        assert len(secrets) == 1
        assert secrets[0].host == "10.0.0.5"

    def test_user_pass_host_port_format(self):
        """Test user:pass:host:port format."""
        content = "admin:pass123:10.0.0.5:22"
        secrets = import_plaintext(content)
        assert len(secrets) == 1
        assert secrets[0].port == 22

    def test_user_at_host_format(self):
        """Test user@host:pass format."""
        content = "admin@10.0.0.5:pass123"
        secrets = import_plaintext(content)
        assert len(secrets) == 1
        assert secrets[0].host == "10.0.0.5"
        assert secrets[0].username == "admin"

    def test_hash_only_format(self):
        """Test hash-only format."""
        content = """5d41402abc4b2a76b9719d911017c592
e99a18c428cb38d5f260853678922e03"""
        secrets = import_plaintext(content, has_password=False)
        assert len(secrets) == 2
        assert secrets[0].hash_value == "5d41402abc4b2a76b9719d911017c592"

    def test_skipping_comments(self):
        """Test skipping comment lines."""
        content = """# Comment line
admin:pass123
# Another comment
user:pass456"""
        secrets = import_plaintext(content)
        assert len(secrets) == 2

    def test_skipping_empty_lines(self):
        """Test skipping empty lines."""
        content = """
admin:pass123

user:pass456

"""
        secrets = import_plaintext(content)
        assert len(secrets) == 2

    def test_custom_delimiter(self):
        """Test custom delimiter."""
        content = "admin|pass123|10.0.0.5"
        secrets = import_plaintext(content, delimiter="|")
        assert len(secrets) == 1
        assert secrets[0].host == "10.0.0.5"

    def test_with_service(self):
        """Test specifying service."""
        content = "admin:pass123:10.0.0.5"
        secrets = import_plaintext(content, service="ssh")
        assert secrets[0].service == "ssh"

    def test_metadata_preserved(self):
        """Test that line numbers are preserved."""
        content = "admin:pass123\nuser:pass456"
        secrets = import_plaintext(content)
        assert secrets[0].metadata["line"] == 1
        assert secrets[1].metadata["line"] == 2


class TestHashcatPotfileImport:
    """Tests for hashcat potfile import."""

    def test_basic_import(self):
        """Test basic hashcat potfile import."""
        content = """5d41402abc4b2a76b9719d911017c592:hello
e99a18c428cb38d5f260853678922e03:abc123"""
        hashes = import_hashcat_potfile(content)
        assert len(hashes) == 2
        assert hashes[0].plaintext == "hello"
        assert hashes[1].plaintext == "abc123"

    def test_single_hash(self):
        """Test single hash import."""
        content = "5d41402abc4b2a76b9719d911017c592:hello"
        hashes = import_hashcat_potfile(content)
        assert len(hashes) == 1

    def test_empty_potfile(self):
        """Test empty potfile."""
        content = ""
        hashes = import_hashcat_potfile(content)
        assert len(hashes) == 0

    def test_blank_lines(self):
        """Test handling of blank lines."""
        content = """
5d41402abc4b2a76b9719d911017c592:hello

e99a18c428cb38d5f260853678922e03:abc123
"""
        hashes = import_hashcat_potfile(content)
        assert len(hashes) == 2

    def test_password_with_colons(self):
        """Test password containing colons."""
        content = "5d41402abc4b2a76b9719d911017c592:pass:word:here"
        hashes = import_hashcat_potfile(content)
        assert hashes[0].plaintext == "pass:word:here"


class TestJohnPotfileImport:
    """Tests for John potfile import."""

    def test_basic_import(self):
        """Test basic John potfile import."""
        content = """admin:5d41402abc4b2a76b9719d911017c592:hello
user:e99a18c428cb38d5f260853678922e03:abc123"""
        hashes = import_john_potfile(content)
        assert len(hashes) == 2
        assert hashes[0].plaintext == "hello"
        assert hashes[0].metadata["username"] == "admin"

    def test_single_entry(self):
        """Test single entry import."""
        content = "admin:5d41402abc4b2a76b9719d911017c592:hello"
        hashes = import_john_potfile(content)
        assert len(hashes) == 1

    def test_empty_potfile(self):
        """Test empty potfile."""
        content = ""
        hashes = import_john_potfile(content)
        assert len(hashes) == 0


class TestFormatDetection:
    """Tests for format detection."""

    def test_detect_bitwarden_json(self):
        """Test detecting Bitwarden JSON."""
        content = json.dumps({"items": [{"type": 1}]})
        assert detect_format(content) == "bitwarden_json"

    def test_detect_keepass_csv(self):
        """Test detecting KeePass CSV."""
        content = "Group,Title,URL,Username,Password,Notes\nWork,Admin,http://host.com,admin,pass,"
        assert detect_format(content) == "keepass_csv"

    def test_detect_potfile(self):
        """Test detecting potfile format."""
        content = "5d41402abc4b2a76b9719d911017c592:hello"
        assert detect_format(content) == "potfile"

    def test_detect_plaintext(self):
        """Test detecting plaintext format."""
        content = "admin:pass123"
        assert detect_format(content) == "plaintext"

    def test_detect_csv(self):
        """Test detecting generic CSV."""
        content = "a,b,c\nd,e,f"
        assert detect_format(content) == "csv"
