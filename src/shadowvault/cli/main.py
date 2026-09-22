"""Command-line interface for shadowvault."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import datetime, timezone

from .. import __version__
from ..crypto import DecryptionError
from ..export import generate_quick_briefing
from ..migration import (
    detect_format,
    import_bitwarden_json,
    import_hashcat_potfile,
    import_john_potfile,
    import_keepass_csv,
    import_plaintext,
)
from ..vault import Vault, VaultLockedError, VaultNotFoundError


class CLIError(Exception):
    """Base exception for CLI errors."""


def print_red(text: str) -> None:
    """Print text in red."""
    print(f"\033[91m{text}\033[0m")


def print_green(text: str) -> None:
    """Print text in green."""
    print(f"\033[92m{text}\033[0m")


def print_yellow(text: str) -> None:
    """Print text in yellow."""
    print(f"\033[93m{text}\033[0m")


def print_cyan(text: str) -> None:
    """Print text in cyan."""
    print(f"\033[96m{text}\033[0m")


def prompt_password(prompt: str = "Master password: ") -> str:
    """Prompt for a password without echoing."""
    return getpass.getpass(prompt)


def prompt_confirm_password() -> str:
    """Prompt for a password twice and confirm match."""
    while True:
        p1 = getpass.getpass("Master password: ")
        p2 = getpass.getpass("Confirm password: ")
        if p1 == p2:
            return p1
        print_red("Passwords do not match. Try again.")


def default_vault_path() -> str:
    """Get default vault path."""
    return os.path.expanduser("~/.shadowvault/main.vault")


def load_vault(args: argparse.Namespace) -> Vault:
    """Load and unlock a vault.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Unlocked Vault instance.
    """
    path = getattr(args, "vault", None) or default_vault_path()
    password = getattr(args, "password", None) or prompt_password()

    try:
        vault = Vault.open(path, password)
        return vault
    except VaultNotFoundError:
        print_red(f"Vault not found: {path}")
        print_yellow(f"Run 'shadowvault init --vault {path}' to create a new vault.")
        sys.exit(1)
    except DecryptionError:
        print_red("Failed to unlock vault: invalid password.")
        sys.exit(1)


def format_secret(secret) -> str:
    """Format a secret for display.

    Args:
        secret: Secret object.

    Returns:
        Formatted string.
    """
    secret_type = secret.secret_type.value
    fmt = f"\033[96m[{secret.id[:8]}]\033[0m \033[92m{secret_type.upper()}\033[0m"

    # Type-specific formatting
    from ..vault import Credential, EncryptionKey, Hash, Host, Note, Token

    if isinstance(secret, Credential):
        fmt += f" {secret.username or '(no user)'}@{secret.host or '(no host)'}"
        if secret.service:
            fmt += f" ({secret.service})"
        if secret.expires_at:
            fmt += f" [expires: {secret.expires_at.date()}]"
        if secret.rotation_recommended:
            fmt += " \033[93m[ROTATION RECOMMENDED]\033[0m"
    elif isinstance(secret, Host):
        fmt += f" {secret.ip_address}"
        if secret.hostname:
            fmt += f" ({secret.hostname})"
        if secret.ports:
            fmt += f" ports: {','.join(str(p) for p in secret.ports)}"
    elif isinstance(secret, Note):
        fmt += f" {secret.category or 'note'}"
    elif isinstance(secret, Hash):
        fmt += f" {secret.hash_value[:20]}..."
        if secret.plaintext:
            fmt += " [CRACKED]"
    elif isinstance(secret, Token):
        fmt += f" {secret.token_type} - {secret.issuer or ''}"
        if secret.scopes:
            fmt += f" scopes: {','.join(secret.scopes)}"
    elif isinstance(secret, EncryptionKey):
        fmt += f" {secret.key_type} - {secret.fingerprint[:16] if secret.fingerprint else ''}"

    return fmt


def cmd_init(args: argparse.Namespace) -> None:
    """Initialize a new vault."""
    path = args.vault or default_vault_path()

    if os.path.exists(path):
        print_red(f"Vault already exists: {path}")
        sys.exit(1)

    password = prompt_confirm_password()

    try:
        vault = Vault.create(
            path=path,
            password=password,
            kdf_method=args.kdf_method,
        )
        vault.save()
        print_green(f"[+] Vault created: {path}")
        print_cyan(f"    KDF: {args.kdf_method}")
        print_cyan(f"    Key ID: {vault.key_id}")

        import stat
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        print_yellow("    File permissions set to 0600 (owner-only)")
    except Exception as e:
        print_red(f"Failed to initialize vault: {e}")
        sys.exit(1)


def cmd_add(args: argparse.Namespace) -> None:
    """Add a secret to the vault."""
    vault = load_vault(args)

    try:
        if args.type == "credential":
            password = args.password
            if not password:
                password = getpass.getpass("Password: ")

            cred = vault.add_credential(
                host=args.host or "",
                service=args.service or "",
                username=args.username or "",
                password=password,
                port=args.port or 0,
                notes=args.notes or "",
                tags=args.tag or [],
            )
            print_green(f"[+] Credential added: {cred.id}")

        elif args.type == "host":
            host = vault.add_host(
                ip_address=args.host or args.ip or "",
                hostname=args.hostname or "",
                os_info=args.os or "",
                notes=args.notes or "",
                tags=args.tag or [],
            )
            print_green(f"[+] Host added: {host.id}")

        elif args.type == "note":
            note_content = args.content
            if not note_content and sys.stdin.isatty():
                print("Enter note content (Ctrl-D to finish):")
                note_content = sys.stdin.read()

            note = vault.add_note(
                content=note_content or "",
                category=args.category or "",
                notes=args.notes or "",
                tags=args.tag or [],
            )
            print_green(f"[+] Note added: {note.id}")

        elif args.type == "hash":
            from ..vault import Hash
            h = Hash(
                hash_value=args.hash or "",
                hash_type=args.hash_type or "",
                source=args.source or "",
                notes=args.notes or "",
                tags=args.tag or [],
            )
            vault.add_secret(h)
            print_green(f"[+] Hash added: {h.id}")

        else:
            print_red(f"Unknown type: {args.type}")
            sys.exit(1)

        vault.save()

    except VaultLockedError:
        print_red("Vault is locked.")
        sys.exit(1)
    except Exception as e:
        print_red(f"Failed to add: {e}")
        sys.exit(1)


def cmd_get(args: argparse.Namespace) -> None:
    """Get a secret from the vault."""
    vault = load_vault(args)

    try:
        secret = vault.get_secret(args.id)

        if secret is None:
            print_red(f"Secret not found: {args.id}")
            sys.exit(1)

        print(format_secret(secret))
        print()

        from ..vault import Credential, EncryptionKey, Hash, Host, Note, Token

        if isinstance(secret, Credential):
            print_yellow("  Credential details:")
            print(f"    Host:      {secret.host}")
            print(f"    Port:      {secret.port}")
            print(f"    Service:   {secret.service}")
            print(f"    Username:  {secret.username}")
            print(f"    Domain:    {secret.domain}")
            if args.show_password:
                print(f"    Password:  {secret.password}")
            else:
                print_yellow("    Password:  [hidden - use --show-password]")

                help_text = _get_password_help(secret)
                if help_text:
                    print(f"    Usage:     {help_text}")

        elif isinstance(secret, Host):
            print_yellow("  Host details:")
            print(f"    IP:        {secret.ip_address}")
            print(f"    Hostname:  {secret.hostname}")
            print(f"    OS:        {secret.os_info}")
            print(f"    Ports:     {', '.join(str(p) for p in secret.ports)}")
            print(f"    Services:  {', '.join(secret.services)}")

        elif isinstance(secret, Note):
            print_yellow("  Note:")
            print(f"    Category:  {secret.category}")
            print("    Content:")
            for line in secret.content.split("\n"):
                print(f"      {line}")

        elif isinstance(secret, Hash):
            print_yellow("  Hash details:")
            print(f"    Type:      {secret.hash_type}")
            print(f"    Value:     {secret.hash_value}")
            if secret.plaintext:
                print_green(f"    Plaintext: {secret.plaintext}")
            print(f"    Source:    {secret.source}")

        elif isinstance(secret, Token):
            print_yellow("  Token details:")
            print(f"    Type:      {secret.token_type}")
            if args.show_password:
                print(f"    Value:     {secret.token_value}")
            else:
                print_yellow("    Value:     [hidden - use --show-password]")
            print(f"    Issuer:    {secret.issuer}")
            print(f"    Scopes:    {', '.join(secret.scopes)}")

        elif isinstance(secret, EncryptionKey):
            print_yellow("  Key details:")
            print(f"    Type:      {secret.key_type}")
            print(f"    Format:    {secret.key_format}")
            print(f"    Fingerprint: {secret.fingerprint}")
            print(f"    Purpose:   {secret.purpose}")

        # Print common fields
        if secret.tags:
            print_yellow("  Tags:")
            print(f"    {', '.join(secret.tags)}")

        if secret.notes:
            print_yellow("  Notes:")
            print(f"    {secret.notes}")

        if secret.metadata:
            print_yellow("  Metadata:")
            for k, v in secret.metadata.items():
                print(f"    {k}: {v}")

        print_yellow("  Timestamps:")
        print(f"    Created:   {secret.created_at}")
        print(f"    Updated:   {secret.updated_at}")

    except VaultLockedError:
        print_red("Vault is locked.")
        sys.exit(1)
    except Exception as e:
        print_red(f"Failed to get secret: {e}")
        sys.exit(1)


def _get_password_help(cred) -> str:
    """Get usage help text for a credential."""
    help_map = {
        "ssh": f"ssh {cred.username}@{cred.host}",
        "smb": f"smbclient -U {cred.username} //{cred.host}",
        "rdp": f"xfreerdp /u:{cred.username} /v:{cred.host}",
        "mysql": f"mysql -h {cred.host} -u {cred.username} -p",
        "postgresql": f"psql -h {cred.host} -U {cred.username}",
        "http": f"curl -u {cred.username}:PASS {cred.host}",
        "ftp": f"ftp {cred.host}",
    }
    return help_map.get(cred.service.lower(), "")


def cmd_list(args: argparse.Namespace) -> None:
    """List secrets in the vault."""
    vault = load_vault(args)

    try:
        secret_type = None
        if args.type:
            from ..vault import SecretType
            try:
                secret_type = SecretType(args.type)
            except ValueError:
                print_red(f"Unknown secret type: {args.type}")
                sys.exit(1)

        secrets = vault.list_secrets(
            secret_type=secret_type,
            tags=args.tag,
            limit=args.limit,
        )

        if not secrets:
            print_yellow("No secrets found.")
            return

        print_yellow(f"Found {len(secrets)} secrets:")
        for secret in secrets:
            print(f"  {format_secret(secret)}")

    except VaultLockedError:
        print_red("Vault is locked.")
        sys.exit(1)


def cmd_search(args: argparse.Namespace) -> None:
    """Search for secrets."""
    vault = load_vault(args)

    try:
        from ..vault import SecretType

        secret_type = None
        if args.type:
            try:
                secret_type = SecretType(args.type)
            except ValueError:
                print_red(f"Unknown secret type: {args.type}")
                sys.exit(1)

        results = vault.search(
            query=args.query,
            secret_type=secret_type,
            host=args.host,
            service=args.service,
            username=args.username,
            tags=args.tag,
        )

        if not results:
            print_yellow("No results found.")
            return

        print_yellow(f"Found {len(results)} results:")
        for secret in results:
            print(f"  {format_secret(secret)}")

    except VaultLockedError:
        print_red("Vault is locked.")
        sys.exit(1)


def cmd_export(args: argparse.Namespace) -> None:
    """Export secrets."""
    vault = load_vault(args)

    try:
        secret_ids = None
        if args.id:
            secret_ids = args.id

        vault.export_secrets(
            output_path=args.output,
            password=args.password,
            secret_ids=secret_ids,
        )
        print_green(f"[+] Exported to: {args.output}")
    except Exception as e:
        print_red(f"Failed to export: {e}")
        sys.exit(1)


def cmd_import(args: argparse.Namespace) -> None:
    """Import secrets from another format."""
    vault = load_vault(args)

    try:
        with open(args.file, encoding="utf-8", errors="replace") as f:
            content = f.read()

        if args.format == "auto":
            args.format = detect_format(content)

        if args.format == "keepass" or args.format == "keepass_csv":
            secrets = import_keepass_csv(content)
            format_name = "KeePass CSV"
        elif args.format == "bitwarden":
            secrets = import_bitwarden_json(content)
            format_name = "Bitwarden JSON"
        elif args.format == "plaintext":
            secrets = import_plaintext(
                content,
                service=args.service or "unknown",
                delimiter=args.delimiter,
            )
            format_name = "plaintext"
        elif args.format == "hashcat":
            secrets = import_hashcat_potfile(content)
            format_name = "hashcat potfile"
        elif args.format == "john":
            secrets = import_john_potfile(content)
            format_name = "john potfile"
        else:
            print_red(f"Unknown import format: {args.format}")
            sys.exit(1)

        count = vault.import_secrets(secrets)
        vault.save()

        print_green(f"[+] Imported {count} secrets from {format_name}")
        print_cyan(f"    File: {args.file}")

    except FileNotFoundError:
        print_red(f"File not found: {args.file}")
        sys.exit(1)
    except Exception as e:
        print_red(f"Failed to import: {e}")
        sys.exit(1)


def cmd_rotate(args: argparse.Namespace) -> None:
    """Mark credentials for rotation."""
    vault = load_vault(args)

    try:
        from ..vault import Credential, SecretType
        secrets = vault.search(query="", secret_type=SecretType.CREDENTIAL)

        now = datetime.now(timezone.utc)

        rotation_candidates = []
        for secret in secrets:
            if not isinstance(secret, Credential):
                continue

            # Check expiry
            rotation_needed = False

            if secret.expires_at:
                expires_at = secret.expires_at
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                if expires_at < now:
                    rotation_needed = True

            if secret.rotation_recommended:
                rotation_needed = True

            if rotation_needed:
                rotation_candidates.append(secret)

        if not rotation_candidates:
            print_green("[+] No credentials need rotation.")
            return

        print_yellow(f"Found {len(rotation_candidates)} credentials needing rotation:")
        for cred in rotation_candidates:
            print(f"  {format_secret(cred)}")

        if args.mark and rotation_candidates:
            for cred in rotation_candidates:
                vault.update_secret(cred.id, rotation_recommended=True)

            vault.save()
            print_green(f"[+] Marked {len(rotation_candidates)} credentials for rotation")

    except Exception as e:
        print_red(f"Rotation check failed: {e}")
        sys.exit(1)


def cmd_audit(args: argparse.Namespace) -> None:
    """View audit log."""
    vault = load_vault(args)

    try:
        entries = vault.get_audit_log(
            action=args.action,
            limit=args.limit,
        )

        if not entries:
            print_yellow("No audit entries found.")
            return

        print_yellow(f"Audit log ({len(entries)} entries):")
        for entry in entries:
            success = "\033[92mOK\033[0m" if entry.success else "\033[91mFAIL\033[0m"
            print(f"  {entry.timestamp} [{success}] {entry.action} "
                  f"secret={entry.secret_id or '-'} user={entry.user} {entry.details}")

    except VaultLockedError:
        print_red("Vault is locked.")
        sys.exit(1)
    except Exception as e:
        print_red(f"Failed to get audit log: {e}")
        sys.exit(1)


def cmd_lock(args: argparse.Namespace) -> None:
    """Lock the vault."""
    path = getattr(args, "vault", None) or default_vault_path()
    password = prompt_password()

    try:
        vault = Vault.open(path, password)
        vault.lock()
        print_yellow("[+] Vault locked.")
    except (VaultNotFoundError, DecryptionError) as e:
        print_red(f"Failed to lock vault: {e}")
        sys.exit(1)


def cmd_unlock(args: argparse.Namespace) -> None:
    """Unlock the vault (for TOTP or passphrase)."""
    path = getattr(args, "vault", None) or default_vault_path()
    password = prompt_password()

    try:
        vault = Vault.open(path, password)
        vault.unlock(password)
        print_green("[+] Vault unlocked.")
    except (VaultNotFoundError, DecryptionError) as e:
        print_red(f"Failed to unlock vault: {e}")
        sys.exit(1)


def cmd_brief(args: argparse.Namespace) -> None:
    """Generate encrypted briefing report."""
    vault = load_vault(args)

    try:
        secrets = vault.list_secrets()

        if not secrets:
            print_red("No secrets to brief.")
            sys.exit(1)

        briefing = generate_quick_briefing(
            secrets,
            client_name=args.client or "Client",
            vault_name=os.path.basename(vault.vault_path or "vault"),
        )

        output_path = args.output or os.path.expanduser(
            f"~/briefing_{args.client or 'client'}_{datetime.now().strftime('%Y%m%d')}.enc"
        )

        # Prompt for brief password
        brief_password = getpass.getpass("Briefing encryption password (client-side): ")

        briefing.encrypt_briefing(
            brief_password,
            output_path=output_path,
        )

        print_green(f"[+] Briefing encrypted and saved: {output_path}")
        print_cyan(f"    Secrets included: {len(secrets)}")
        print_cyan(f"    Client: {args.client or 'Client'}")

    except Exception as e:
        print_red(f"Failed to generate briefing: {e}")
        sys.exit(1)


def cmd_version(args: argparse.Namespace) -> None:
    """Print version info."""
    print(f"shadowvault version {__version__}")
    print("Cryptographic secrets lifecycle manager for offensive security operations")


def load_vault_from_args(args: argparse.Namespace) -> Vault:
    """Load vault for commands that need it."""
    return load_vault(args)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser.

    Returns:
        Configured ArgumentParser.
    """
    parser = argparse.ArgumentParser(
        prog="shadowvault",
        description=(
            "shadowvault - Cryptographic secrets lifecycle manager for offensive "
            "security operations"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  shadowvault init
  shadowvault add credential --host 10.0.0.5 --service ssh --username admin
  shadowvault list --type credential
  shadowvault search --service ssh
  shadowvault get <id> --show-password
  shadowvault export --output export.enc
  shadowvault import keepass --file export.csv
  shadowvault audit
  shadowvault brief --client "Acme Corp"
""",
    )

    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version information",
    )

    # Global connection arguments
    parser.add_argument(
        "--vault",
        "-v",
        help="Path to vault file (default: ~/.shadowvault/main.vault)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # --- init ---
    init_parser = subparsers.add_parser("init", help="Initialize a new vault")
    init_parser.add_argument(
        "--kdf-method",
        choices=["argon2", "pbkdf2"],
        default="argon2",
        help="Key derivation method",
    )
    init_parser.set_defaults(func=cmd_init)

    # --- add ---
    add_parser = subparsers.add_parser("add", help="Add a secret to the vault")
    add_sub = add_parser.add_subparsers(dest="type", help="Secret type")

    # add credential
    cred_parser = add_sub.add_parser("credential", help="Add a credential")
    cred_parser.add_argument("--host", help="Target host")
    cred_parser.add_argument("--port", type=int, default=0, help="Port number")
    cred_parser.add_argument("--service", help="Service name (e.g., ssh, smb)")
    cred_parser.add_argument("--username", "-u", help="Username")
    cred_parser.add_argument("--password", "-p", help="Password (prompted if omitted)")
    cred_parser.add_argument("--domain", help="Domain")
    cred_parser.add_argument("--notes", help="Notes")
    cred_parser.add_argument("--tag", action="append", default=[], help="Tag (can be repeated)")
    cred_parser.set_defaults(func=cmd_add)

    # add host
    host_parser = add_sub.add_parser("host", help="Add a host/target")
    host_parser.add_argument("--host", "--ip", help="IP address")
    host_parser.add_argument("--hostname", help="Hostname")
    host_parser.add_argument("--os", help="OS information")
    host_parser.add_argument("--notes", help="Notes")
    host_parser.add_argument("--tag", action="append", default=[], help="Tag")
    host_parser.set_defaults(func=cmd_add)

    # add note
    note_parser = add_sub.add_parser("note", help="Add a note")
    note_parser.add_argument("--content", help="Note content")
    note_parser.add_argument("--category", help="Note category")
    note_parser.add_argument("--notes", help="Additional notes")
    note_parser.add_argument("--tag", action="append", default=[], help="Tag")
    note_parser.set_defaults(func=cmd_add)

    # add hash
    hash_parser = add_sub.add_parser("hash", help="Add a hash")
    hash_parser.add_argument("--hash", help="Hash value")
    hash_parser.add_argument("--hash-type", help="Hash type (e.g., NTLM)")
    hash_parser.add_argument("--source", help="Hash source")
    hash_parser.add_argument("--notes", help="Notes")
    hash_parser.add_argument("--tag", action="append", default=[], help="Tag")
    hash_parser.set_defaults(func=cmd_add)

    # --- get ---
    get_parser = subparsers.add_parser("get", help="Get a secret by ID")
    get_parser.add_argument("id", help="Secret ID")
    get_parser.add_argument(
        "--show-password",
        action="store_true",
        help="Show password/token value",
    )
    get_parser.set_defaults(func=cmd_get)

    # --- list ---
    list_parser = subparsers.add_parser("list", help="List secrets")
    list_parser.add_argument(
        "--type",
        help="Filter by secret type (credential, host, note, hash, token, key)",
    )
    list_parser.add_argument("--tag", action="append", default=[], help="Filter by tag")
    list_parser.add_argument("--limit", type=int, help="Limit results")
    list_parser.set_defaults(func=cmd_list)

    # --- search ---
    search_parser = subparsers.add_parser("search", help="Search secrets")
    search_parser.add_argument("query", nargs="?", help="Free-text search query")
    search_parser.add_argument("--type", help="Filter by secret type")
    search_parser.add_argument("--host", help="Filter by host (credentials)")
    search_parser.add_argument("--service", help="Filter by service (credentials)")
    search_parser.add_argument("--username", help="Filter by username (credentials)")
    search_parser.add_argument("--tag", action="append", default=[], help="Filter by tag")
    search_parser.set_defaults(func=cmd_search)

    # --- export ---
    export_parser = subparsers.add_parser("export", help="Export secrets")
    export_parser.add_argument("--output", "-o", required=True, help="Output file")
    export_parser.add_argument("--password", help="Export encryption password")
    export_parser.add_argument("--id", action="append", default=[], help="Secret IDs to export")
    export_parser.set_defaults(func=cmd_export)

    # --- import ---
    import_parser = subparsers.add_parser("import", help="Import secrets")
    import_parser.add_argument(
        "--format",
        choices=["keepass", "bitwarden", "plaintext", "hashcat", "john", "auto"],
        default="auto",
        help="Source format",
    )
    import_parser.add_argument("--file", "-f", required=True, help="Input file")
    import_parser.add_argument("--service", help="Service for plaintext imports")
    import_parser.add_argument("--delimiter", default=":", help="Delimiter for plaintext imports")
    import_parser.set_defaults(func=cmd_import)

    # --- rotate ---
    rotate_parser = subparsers.add_parser("rotate", help="Check credential rotation status")
    rotate_parser.add_argument("--mark", action="store_true", help="Mark credentials for rotation")
    rotate_parser.add_argument(
        "--expiry-days",
        type=int,
        default=7,
        help="Days until expiry warning",
    )
    rotate_parser.set_defaults(func=cmd_rotate)

    # --- audit ---
    audit_parser = subparsers.add_parser("audit", help="View audit log")
    audit_parser.add_argument("--action", help="Filter by action type")
    audit_parser.add_argument("--limit", type=int, help="Limit results")
    audit_parser.set_defaults(func=cmd_audit)

    # --- lock ---
    lock_parser = subparsers.add_parser("lock", help="Lock the vault")
    lock_parser.set_defaults(func=cmd_lock)

    # --- unlock ---
    unlock_parser = subparsers.add_parser("unlock", help="Unlock the vault")
    unlock_parser.set_defaults(func=cmd_unlock)

    # --- brief ---
    brief_parser = subparsers.add_parser("brief", help="Generate encrypted briefing report")
    brief_parser.add_argument("--client", help="Client name")
    brief_parser.add_argument("--output", "-o", help="Output file path")
    brief_parser.set_defaults(func=cmd_brief)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the CLI.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        cmd_version(args)
        return 0

    if not args.command:
        parser.print_help()
        return 0

    try:
        args.func(args)
        return 0
    except KeyboardInterrupt:
        print_red("\n[!] Interrupted.")
        return 130
    except Exception as e:
        print_red(f"[!] Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
