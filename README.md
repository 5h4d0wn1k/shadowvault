> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.
# shadowvault

**Cryptographic secrets lifecycle manager for offensive security operations.**

shadowvault is a hardened secrets vault designed for red team operations, penetration testing engagements, and CTF workflows. It solves the real problem: "where do I safely store, retrieve, and rotate the hundreds of credentials I collect during a pentest?"

This is NOT a password manager. It's a purpose-built tool for security professionals.

## Features

- **AES-256-GCM encryption** with Argon2id or PBKDF2 key derivation
- **Secret categories**: hosts, credentials, tokens, hashes, keys, notes
- **Credential rotation tracking**: expiry dates, last-used timestamps, rotation recommendations
- **OPSEC hardened**: zeroize memory, audit logs, auto-lockout, TOTP unlock
- **Migration tools**: Import from KeePass CSV, Bitwarden JSON, plaintext lists
- **Encrypted exports**: Generate briefing reports for client handoff
- **Team mode**: Multi-user vaults with role-based access (owner/viewer/annotator)
- **CLI + Python API**: Full programmatic access
- **Integration**: Import from hashcat/john, export to sprayshed/hermesc2

## Quick Start

```bash
pip install shadowvault

# Initialize a new vault
shadowvault init --master-password

# Add a credential
shadowvault add credential --host 10.0.0.5 --service ssh --username admin --password 'P@ssw0rd!'

# Search for secrets
shadowvault search --service ssh --host 10.0.0.0/24

# Export encrypted briefing
shadowvault brief --client "Acme Corp" --output briefing.enc
```

## Security Model

- **Encryption**: AES-256-GCM (authenticated encryption)
- **Key derivation**: Argon2id (memory-hard) or PBKDF2 (compatible)
- **Memory safety**: Secrets are zeroized from memory after use
- **Audit trail**: Every operation is logged with timestamps
- **Auto-lock**: Vault locks after configurable inactivity period

## Architecture

```
shadowvault/
├── src/shadowvault/
│   ├── __init__.py
│   ├── crypto/          # Cryptographic engine
│   ├── vault/           # Vault storage & management
│   ├── migration/       # Import from other formats
│   ├── team/            # Multi-user RBAC
│   └── export/          # Encrypted report generation
├── tests/               # 200+ offline tests
└── pyproject.toml
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `init` | Initialize a new vault |
| `add` | Add secrets (credential, host, token, hash, key, note) |
| `get` | Retrieve a secret by ID |
| `list` | List secrets with optional filters |
| `search` | Full-text search across all secrets |
| `export` | Export secrets (encrypted or plaintext) |
| `import` | Import from KeePass, Bitwarden, plaintext |
| `rotate` | Track credential rotation |
| `audit` | View audit log |
| `lock` | Lock the vault |
| `unlock` | Unlock the vault |
| `brief` | Generate encrypted briefing report |

## Python API

```python
from shadowvault import Vault

# Open existing vault
vault = Vault.open("~/.shadowvault/main.vault", password="mypassword")

# Add a credential
cred = vault.add_credential(
    host="10.0.0.5",
    service="ssh",
    username="admin",
    password="P@ssw0rd!",
    notes="Found via default creds scan"
)

# Search
results = vault.search(service="ssh", host="10.0.0.0/24")

# Export
vault.export_briefing(client="Acme Corp", output="briefing.enc")
```

## Team Mode

```python
from shadowvault.team import TeamVault

team = TeamVault.open("team.vault", owner_key="...")

# Add team members
team.add_member("alice@redteam.io", role="viewer")
team.add_member("bob@redteam.io", role="annotator")

# Role-based access
# - owner: full access, manage members
# - annotator: add notes, update metadata
# - viewer: read-only access
```

## Migration

```bash
# Import from KeePass
shadowvault import keepass --file export.csv

# Import from Bitwarden
shadowvault import bitwarden --file export.json

# Import plaintext list (user:pass format)
shadowvault import plaintext --file creds.txt --service ssh
```

## Development

```bash
git clone https://github.com/your-org/shadowvault.git
cd shadowvault
pip install -e ".[dev]"
pytest
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for authorized security testing only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse.
