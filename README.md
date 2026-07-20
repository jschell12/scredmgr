# scredmanager

Personal keychain-backed secrets broker for macOS. Replaces a plaintext
`~/.agentsecrets` dotenv with a single Go binary where **secrets live in the
macOS Keychain, metadata lives in 0600 JSON, and nothing secret is ever at
rest in cleartext**.

## Install

```sh
make install    # builds and installs to ~/.local/bin/scredmanager
```

## Architecture

- **Secret** → Keychain generic password: service `scredmanager`, account `token/<id>`
- **Metadata** → `~/.scredmanager/<id>.json`, mode 0600, atomic writes
- `_storage` provenance marker (`keychain | file | mixed`) tells delete/migrate
  where the authoritative copy is. Plaintext in JSON exists only during the
  import-then-migrate window and is stripped only after a verified keychain
  round-trip.

## Commands

| Command | Behavior |
|---|---|
| `set <id> [--from-stdin]` | Masked prompt or stdin (never argv). Fails closed if the service's live check rejects the token |
| `get <id>` | Print secret to stdout — refuses if stdout is a TTY (exit 2) |
| `rm <id>` / `ls` / `status` | Delete both halves / list entries / expiry table with ≤7-day warnings |
| `check <id>` | Live API verify via the service's `checkPath` |
| `curl <id> <url> [args…]` | Injects auth header via curl stdin config (never argv); refuses cross-host URLs |
| `run [--only a,b] -- <cmd…>` | Exec child with secrets as env vars — replaces `source ~/.agentsecrets` |
| `import <dotenv>` | One keychain entry per `export KEY=value` line |
| `export` | Plaintext escape hatch, gated behind `SCREDMANAGER_ALLOW_EXPORT=1` |
| `services` | Emit the manifest |

Every command supports `--json` (`schemaVersion: 1` envelope).

## Services manifest

`~/.scredmanager/services.json`:

```json
[
  {
    "id": "jira",
    "envVar": "JIRA_TOKEN",
    "baseUrl": "https://example.atlassian.net",
    "checkPath": "/rest/api/2/myself",
    "authHeader": "bearer",
    "expiryDays": 90,
    "tokenPage": "https://id.atlassian.com/manage-profile/security/api-tokens"
  }
]
```

`authHeader` values: `bearer`, `basic:<user>`, `token=`, `private-token`, `header:<Name>`.

## Cutover from ~/.agentsecrets

```sh
scredmanager import ~/.agentsecrets
scredmanager ls                        # verify
scredmanager run -- ./script.sh        # replaces `source ~/.agentsecrets`
rm -P ~/.agentsecrets
```

## Development

```sh
make test               # unit tests (fake store)
make integration        # real-keychain tests (macOS only)
make build
```

Security discipline (enforced in review):

1. Secrets travel via stdin/prompt/keychain API — never argv, never logs; the
   redact helper wraps all error paths.
2. Every file write: 0600 + atomic; every dir: 0700.
3. `get` TTY refusal and `curl` host allowlist are hard behavior, not flags.
