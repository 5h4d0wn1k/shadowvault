"""Migration tools for importing secrets from other formats."""

from __future__ import annotations

import csv
import io
import json
from typing import Optional

from ..vault.schema import (
    Credential,
    Hash,
    Host,
    Note,
    Secret,
    SecretType,
    Token,
)


class MigrationError(Exception):
    """Base exception for migration operations."""


def import_keepass_csv(csv_content: str) -> list[Secret]:
    """Import secrets from KeePass CSV export.

    Supports KeePass CSV format with columns:
    - Group, Title, URL, Username, Password, Notes, etc.

    Args:
        csv_content: CSV file content as string.

    Returns:
        List of Secret objects.

    Raises:
        MigrationError: If CSV parsing fails.
    """
    secrets = []

    try:
        reader = csv.DictReader(io.StringIO(csv_content))
        for row in reader:
            # Map KeePass fields
            title = row.get("Title", "")
            url = row.get("URL", "")
            username = row.get("Username", "")
            password = row.get("Password", "")
            notes = row.get("Notes", "")
            group = row.get("Group", "")

            # Parse URL for host/port/service
            host = ""
            port = 0
            service = "other"
            url_clean = ""
            if url:
                # Simple URL parsing
                url_clean = url.replace("https://", "").replace("http://", "")
                host_part = url_clean.split("/")[0]
                if ":" in host_part:
                    host_str, port_str = host_part.rsplit(":", 1)
                    host = host_str
                    try:
                        port = int(port_str)
                    except ValueError:
                        host = host_part
                else:
                    host = host_part

            # Determine service from URL/port
            if "ssh" in url.lower():
                service = "ssh"
            elif "rdp" in url.lower():
                service = "rdp"
            elif "smb" in url.lower():
                service = "smb"
            elif port == 22 or "22" in url:
                service = "ssh"
            elif port == 3389:
                service = "rdp"
            elif port == 445:
                service = "smb"
            elif port in (80, 443) or url.startswith("http"):
                service = "http"
            elif url_clean:
                # Default to http for URLs with no other indicator
                service = "http"

            cred = Credential(
                host=host,
                port=port,
                service=service,
                username=username,
                password=password,
                notes=f"Imported from KeePass. Group: {group}\n{notes}",
                tags=[f"keepass:{group}"] if group else [],
                metadata={"source": "keepass_csv", "title": title, "url": url},
            )
            secrets.append(cred)

    except Exception as e:
        raise MigrationError(f"Failed to parse KeePass CSV: {e}") from e

    return secrets


def import_bitwarden_json(json_content: str) -> list[Secret]:
    """Import secrets from Bitwarden JSON export.

    Supports Bitwarden JSON format with items array containing:
    - type: 1=Login, 2=SecureNote, 3=Card, 4=Identity
    - login: {username, password, totp, uris}
    - notes: string

    Args:
        json_content: JSON file content as string.

    Returns:
        List of Secret objects.

    Raises:
        MigrationError: If JSON parsing fails.
    """
    secrets = []

    try:
        data = json.loads(json_content)
        items = data.get("items", [])

        for item in items:
            item_type = item.get("type", 0)
            name = item.get("name", "")
            notes = item.get("notes", "")
            folder = item.get("folder", "")
            tags = item.get("tags", [])

            # Build tag list
            tag_list = [f"bitwarden:{folder}"] if folder else []
            tag_list.extend([f"tag:{t}" for t in (tags or [])])

            if item_type == 1:  # Login
                login = item.get("login", {})
                username = login.get("username", "")
                password = login.get("password", "")
                totp = login.get("totp", "")
                uris = login.get("uris", [])

                # Extract host from URIs
                host = ""
                port = 0
                service = "http"

                for uri_obj in uris:
                    uri = uri_obj.get("uri", "")
                    if uri:
                        uri_clean = uri.replace("https://", "").replace("http://", "")
                        host = uri_clean.split("/")[0].split(":")[0]
                        port_part = uri_clean.split(":")
                        if len(port_part) > 1:
                            try:
                                port = int(port_part[1].split("/")[0])
                            except ValueError:
                                pass
                        break

                cred = Credential(
                    host=host,
                    port=port,
                    service=service,
                    username=username,
                    password=password,
                    notes=f"Imported from Bitwarden. {name}\n{notes}",
                    tags=tag_list,
                    metadata={
                        "source": "bitwarden_json",
                        "name": name,
                        "totp": totp,
                    },
                )
                secrets.append(cred)

                # Add TOTP if present
                if totp:
                    token = Token(
                        token_type="totp",
                        token_value=totp,
                        issuer=name,
                        notes=f"TOTP for {username}@{host}",
                        tags=tag_list,
                        metadata={"source": "bitwarden_json"},
                    )
                    secrets.append(token)

            elif item_type == 2:  # SecureNote
                note = Note(
                    content=item.get("notes", ""),
                    category="bitwarden",
                    notes=f"Imported from Bitwarden. {name}",
                    tags=tag_list,
                    metadata={"source": "bitwarden_json", "name": name},
                )
                secrets.append(note)

            elif item_type == 3:  # Card
                card = item.get("card", {})
                card_data = {
                    "cardholderName": card.get("cardholderName", ""),
                    "brand": card.get("brand", ""),
                    "number": card.get("number", ""),
                    "expMonth": card.get("expMonth", ""),
                    "expYear": card.get("expYear", ""),
                    "code": card.get("code", ""),
                }
                note = Note(
                    content=json.dumps(card_data),
                    category="bitwarden:card",
                    notes=f"Card: {name}",
                    tags=tag_list,
                    metadata={"source": "bitwarden_json", "name": name},
                )
                secrets.append(note)

            elif item_type == 4:  # Identity
                identity = item.get("identity", {})
                identity_data = {
                    "firstName": identity.get("firstName", ""),
                    "lastName": identity.get("lastName", ""),
                    "email": identity.get("email", ""),
                    "phone": identity.get("phone", ""),
                    "ssn": identity.get("ssn", ""),
                }
                note = Note(
                    content=json.dumps(identity_data),
                    category="bitwarden:identity",
                    notes=f"Identity: {name}",
                    tags=tag_list,
                    metadata={"source": "bitwarden_json", "name": name},
                )
                secrets.append(note)

    except Exception as e:
        raise MigrationError(f"Failed to parse Bitwarden JSON: {e}") from e

    return secrets


def import_plaintext(
    content: str,
    service: str = "unknown",
    delimiter: str = ":",
    has_password: bool = True,
) -> list[Secret]:
    """Import secrets from plaintext list.

    Supports formats:
    - user:pass
    - user:pass:host
    - user:pass:host:port
    - user@host:pass
    - Just passwords (one per line)

    Args:
        content: Plaintext content.
        service: Default service name.
        delimiter: Field delimiter.
        has_password: Whether lines contain passwords.

    Returns:
        List of Secret objects.

    Raises:
        MigrationError: If parsing fails.
    """
    secrets = []

    try:
        for line_num, line in enumerate(content.strip().splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(delimiter)

            if len(parts) == 1:
                # Just a password or hash
                if has_password:
                    cred = Credential(
                        service=service,
                        password=parts[0],
                        notes=f"Imported from plaintext line {line_num}",
                        tags=["import:plaintext"],
                        metadata={"source": "plaintext", "line": line_num},
                    )
                    secrets.append(cred)
                else:
                    h = Hash(
                        hash_value=parts[0],
                        source="plaintext",
                        notes=f"Imported from plaintext line {line_num}",
                        tags=["import:plaintext"],
                        metadata={"source": "plaintext", "line": line_num},
                    )
                    secrets.append(h)

            elif len(parts) == 2:
                # user:pass or user@host:pass
                username = parts[0]
                password = parts[1]

                # Check for user@host format
                if "@" in username:
                    username_part, host = username.split("@", 1)
                    cred = Credential(
                        host=host,
                        service=service,
                        username=username_part,
                        password=password,
                        notes=f"Imported from plaintext line {line_num}",
                        tags=["import:plaintext"],
                        metadata={"source": "plaintext", "line": line_num},
                    )
                else:
                    cred = Credential(
                        service=service,
                        username=username,
                        password=password,
                        notes=f"Imported from plaintext line {line_num}",
                        tags=["import:plaintext"],
                        metadata={"source": "plaintext", "line": line_num},
                    )
                secrets.append(cred)

            elif len(parts) == 3:
                # user:pass:host
                cred = Credential(
                    host=parts[2],
                    service=service,
                    username=parts[0],
                    password=parts[1],
                    notes=f"Imported from plaintext line {line_num}",
                    tags=["import:plaintext"],
                    metadata={"source": "plaintext", "line": line_num},
                )
                secrets.append(cred)

            elif len(parts) >= 4:
                # user:pass:host:port:...
                try:
                    port = int(parts[3])
                except ValueError:
                    port = 0

                cred = Credential(
                    host=parts[2],
                    port=port,
                    service=service,
                    username=parts[0],
                    password=parts[1],
                    notes=f"Imported from plaintext line {line_num}",
                    tags=["import:plaintext"],
                    metadata={"source": "plaintext", "line": line_num},
                )
                secrets.append(cred)

    except Exception as e:
        raise MigrationError(f"Failed to parse plaintext: {e}") from e

    return secrets


def import_hashcat_potfile(content: str) -> list[Hash]:
    """Import cracked passwords from hashcat .pot file.

    Format: hash:plaintext (one per line)

    Args:
        content: Potfile content.

    Returns:
        List of Hash objects with cracked passwords.
    """
    hashes = []

    for line_num, line in enumerate(content.strip().splitlines(), 1):
        line = line.strip()
        if not line:
            continue

        # Split on first colon only
        parts = line.split(":", 1)
        if len(parts) == 2:
            h = Hash(
                hash_value=parts[0],
                plaintext=parts[1],
                source="hashcat",
                notes=f"Imported from hashcat potfile line {line_num}",
                tags=["import:hashcat"],
                metadata={"source": "hashcat_potfile", "line": line_num},
            )
            hashes.append(h)

    return hashes


def import_john_potfile(content: str) -> list[Hash]:
    """Import cracked passwords from John the Ripper .pot file.

    Format: user:hash:plaintext (one per line)

    Args:
        content: Potfile content.

    Returns:
        List of Hash objects with cracked passwords.
    """
    hashes = []

    for line_num, line in enumerate(content.strip().splitlines(), 1):
        line = line.strip()
        if not line:
            continue

        parts = line.split(":")
        if len(parts) >= 3:
            h = Hash(
                hash_value=parts[1],
                plaintext=parts[2],
                source="john",
                notes=f"User: {parts[0]}. Imported from john potfile line {line_num}",
                tags=["import:john"],
                metadata={
                    "source": "john_potfile",
                    "line": line_num,
                    "username": parts[0],
                },
            )
            hashes.append(h)

    return hashes


def detect_format(content: str) -> str:
    """Detect the format of input data.

    Args:
        content: Input content.

    Returns:
        Format identifier string.
    """
    content_stripped = content.strip()

    # Check for JSON
    if content_stripped.startswith("{"):
        try:
            data = json.loads(content_stripped)
            if "items" in data and isinstance(data["items"], list):
                return "bitwarden_json"
            return "json"
        except json.JSONDecodeError:
            pass

    # Check for CSV
    if "," in content_stripped[:100]:
        first_line = content_stripped.split("\n")[0].lower()
        if "title" in first_line and ("username" in first_line or "password" in first_line):
            return "keepass_csv"
        return "csv"

    # Check for potfile format (hash:password - hash is hex)
    lines = content_stripped.splitlines()[:5]
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            parts = line.split(":", 2)
            if len(parts) >= 3:
                # John format: user:hash:password
                return "potfile"
            elif len(parts) == 2:
                # Check if first part looks like a hash (long hex string)
                if len(parts[0]) >= 16 and all(c in "0123456789abcdefABCDEF" for c in parts[0]):
                    return "potfile"

    # Default to plaintext
    return "plaintext"
