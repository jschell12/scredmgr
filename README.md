# scredmanager

Personal keychain-backed secrets broker for macOS. Replaces a plaintext
`~/.agentsecrets` dotenv with a single Go binary: **secrets live in the macOS
Keychain, metadata lives in 0600 JSON, and nothing secret is ever at rest in
cleartext**.

## Install

```sh
make install    # builds and installs to ~/.local/bin/scredmanager
```

## Quick start

Migrate off a plaintext dotenv:

```sh
scredmanager import ~/.agentsecrets   # one keychain entry per export line
scredmanager ls                       # verify
scredmanager run -- ./script.sh       # replaces `source ~/.agentsecrets`
rm -P ~/.agentsecrets
```

Everyday usage:

```sh
scredmanager set jira                 # masked prompt (never argv)
scredmanager get jira | pbcopy        # stdout only — refuses a TTY
scredmanager status                   # expiry table, ≤7-day warnings
scredmanager check jira               # live API verify
scredmanager curl jira /rest/api/2/myself   # auth header injected, argv-safe
scredmanager login github             # guided token mint (browser + verify)
```

Run commands with secrets injected as env vars:

```sh
scredmanager run -- terraform plan
scredmanager run --path work -- cmd   # overlay work/* over root entries
scredmanager run --only jira,github -- cmd
```

Namespaced ids let the same env var map to different accounts:

```sh
scredmanager set jira --env-var JIRA_TOKEN        # personal (root)
scredmanager set work/jira --env-var JIRA_TOKEN   # service account
scredmanager ls --path work                       # only work/* entries
```

SSH keys (private key stays a file; passphrase goes in the keychain):

```sh
scredmanager ssh keygen deploy --passphrase-random
scredmanager ssh show deploy          # public key + fingerprint
scredmanager ssh add deploy           # register with ssh-agent
```

Sync with a remote provider (keychain stays canonical):

```sh
scredmanager sync homelab-vault --push --dry-run
scredmanager sync homelab-vault --pull
scredmanager providers check homelab-vault
```

Daily expiry notifications:

```sh
scredmanager launchd install    # status --quiet --notify at 09:30
```

---

## Command reference

| Command | Behavior |
|---|---|
| `set <id> [--from-stdin] [--env-var VAR]` | Masked prompt or stdin (never argv). Fails closed if the service's live check rejects the token |
| `get <id>` | Print secret to stdout — refuses if stdout is a TTY (exit 2) |
| `rm <id> [--files]` | Delete keychain + metadata (`--files` also deletes ssh key files) |
| `ls [--path ns]` | List entries |
| `status [--quiet] [--notify]` | Expiry table with ≤7-day warnings; `--notify` posts a native notification |
| `check <id>` | Live API verify via the service's `checkPath` |
| `curl <id> <url> [args…]` | Injects auth header via curl stdin config (never argv); refuses cross-host URLs |
| `run [--path ns] [--only a,b] -- <cmd…>` | Exec child with secrets as env vars. `--path` overlays a namespace over the root entries |
| `import <dotenv>` | One keychain entry per `export KEY=value` line |
| `export [--path ns]` | Plaintext escape hatch, gated behind `SCREDMANAGER_ALLOW_EXPORT=1` |
| `login <id> [--clipboard]` | Guided mint: open `tokenPage`, capture, verify fail-closed, store with expiry |
| `services` | Emit the manifest |
| `launchd install` | LaunchAgent running `status --quiet --notify` daily at 09:30 |
| `ssh keygen <name> --passphrase-random\|--passphrase-prompt\|--no-passphrase` | Generate ed25519 key pair; passphrase in keychain, metadata + rotation reminder in the ledger |
| `ssh show <name>` | Public key + fingerprint (TTY-safe) |
| `ssh add <name>` | (Re)register with ssh-agent via stored passphrase |
| `sync <provider> --push\|--pull [--only a,b] [--dry-run] [--overwrite]` | Copy secrets keychain ↔ remote provider |
| `providers` / `providers check <name>` | List configured remote providers / probe connectivity and auth |

Every command supports `--json` (`schemaVersion: 1` envelope).

## Architecture

- **Secret** → Keychain generic password: service `scredmanager`, account `token/<id>`
- **Metadata** → `~/.scredmanager/<id>.json`, mode 0600, atomic writes
- `_storage` provenance marker (`keychain | file | mixed`) tells delete/migrate
  where the authoritative copy is. Plaintext in JSON exists only during the
  import-then-migrate window and is stripped only after a verified keychain
  round-trip.

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

## Namespaced paths

Ids may be namespaced with slash-separated path segments (`work/jira`):

- Root entries (no path) are always the base; `--path <ns>` overlays entries
  directly under that namespace, overriding any base entry with the same
  `envVar`. Without `--path`, only root entries are injected.
- `get`, `rm`, `check`, `curl`, `login`, and `sync --only` all accept
  path-qualified ids.
- Manifest lookup falls back to the basename: `work/github` inherits the
  `github` service's `envVar`, live check, and expiry.
- Metadata lives in nested dirs (`~/.scredmanager/work/jira.json`, 0700);
  keychain accounts use the full id (`token/work/jira`).

## Guided login

No headless-browser automation — three capture modes:

- **Masked prompt** (default): opens `tokenPage` in your real browser; paste the
  fresh token into a no-echo prompt.
- **`--clipboard`**: polls the clipboard for a *new* value matching the
  service's optional `tokenPattern` regex, then clears the clipboard after
  storing.
- **Device-code flow** (automatic when the manifest has `deviceFlow`): pure
  RFC 8628 API — shows a user code, opens the verification page, polls for the
  token. GitHub endpoints are the defaults:

```json
{
  "id": "github",
  "envVar": "GITHUB_TOKEN",
  "baseUrl": "https://api.github.com",
  "checkPath": "/user",
  "tokenPattern": "^(ghp|gho)_[A-Za-z0-9]{36}$",
  "deviceFlow": { "clientId": "<oauth-app-client-id>", "scope": "repo" }
}
```

Captured tokens are verified against `checkPath` before storage (fail closed).

## SSH keys

`ssh keygen <name>` wraps `ssh-keygen -t ed25519`. **Private keys stay as files
(default `~/.ssh/id_<name>`) and never enter the keychain** — scredmanager owns
the ledger: metadata under id `ssh:<name>` (fingerprint, key path, rotation
expiry — default 365 days, surfaced by `ls`/`status` and the daily launchd
notification) and, optionally, the passphrase in the keychain.

Exactly one passphrase mode is required: `--passphrase-random` (32 random
bytes, stored in keychain — recommended), `--passphrase-prompt` (masked
prompt, stored), or `--no-passphrase` (explicit opt-out).

**How the passphrase reaches ssh-keygen without leaking:** `-N <pass>` would
put it on argv (visible in `ps`), so scredmanager instead sets
`SSH_ASKPASS=<itself>` + `SSH_ASKPASS_REQUIRE=force` (OpenSSH ≥ 8.4) and
re-execs itself as the askpass helper. Only the entry **id** rides in the
environment; the passphrase travels keychain → helper stdout → ssh-keygen's
own pipe. The same mechanism drives `ssh add` (`ssh-add
--apple-use-keychain`). Add `UseKeychain yes` to `~/.ssh/config` for agent
persistence across reboots.

`get ssh:<name>` prints the passphrase under the usual non-TTY discipline;
`rm ssh:<name> --files` also deletes the key pair files.

## Remote providers

The keychain remains the **canonical local store**; remote backends are
explicit, direction-only sync targets configured in
`~/.scredmanager/providers.json` (must be 0600).

- `sync <provider> --push` copies local entries to the provider (always
  overwriting remote). `--pull` copies remote entries into the keychain,
  skipping ones that already exist locally unless `--overwrite`. There is
  **no merge and no delete propagation**; `--dry-run` shows the plan without
  transferring any secret values.
- SSH entries are never pushed unless explicitly named in `--only`
  (passphrases don't belong remote by default).
- Pulled entries get `syncedFrom`/`syncedAt` metadata plus manifest defaults
  (env var, expiry) when the id matches a service.

### Vault

`type: vault` speaks KV v2 over stdlib HTTP — no `vault` CLI needed:

```json
{"providers": [
  {"name": "homelab-vault", "type": "vault",
   "vault": {"addr": "https://vault.local:8200", "mount": "secret",
             "pathPrefix": "scredmanager/", "tokenRef": "vault-token"}}
]}
```

The token comes from the keychain entry named by `tokenRef` (the Vault token
is itself a managed, expirable secret) with `VAULT_TOKEN` as fallback. For a
privately-signed endpoint, point `caCert` at the CA PEM file (fallback:
`VAULT_CACERT`, same convention as the vault CLI). LIST is single-level:
nested paths under the prefix are skipped.

### 1Password

`type: 1password` drives the official `op` CLI (biometric auth stays op's
problem — run sync from a real terminal, not headless):

```json
{"name": "op-private", "type": "1password",
 "op": {"vault": "Private", "account": "my.1password.com",
        "itemPrefix": "scredmanager/"}}
```

Entries are PASSWORD items titled `<itemPrefix><id>`. Reads use `op item get
--reveal` (secret on stdout); writes pipe item JSON to `op item create -`
(stdin). Updates are delete-then-create because `op item edit` only takes
values on argv.

### AWS

`type: aws-sm` (Secrets Manager) and `type: aws-ps` (SSM Parameter Store)
drive the `aws` CLI, inheriting profiles/SSO/region handling:

```json
{"name": "aws-sm", "type": "aws-sm",
 "aws": {"region": "us-east-1", "profile": "personal", "prefix": "scredmanager/"}},
{"name": "aws-ps", "type": "aws-ps",
 "aws": {"region": "us-east-1", "profile": "personal", "prefix": "/scredmanager/"}}
```

`--secret-string` / `--value` would leak on argv, so writes pipe their
payload via `--cli-input-json file:///dev/stdin`. SM updates fall back from
`create-secret` to `put-secret-value`; PS writes SecureString with
Overwrite. `Check` is `sts get-caller-identity`.

### LastPass

`type: lastpass` is **pull-only**: the upstream `lpass` CLI is unmaintained,
so it is deliberately kept out of the write path (`sync --push` is refused;
Put/Delete return read-only errors). Intended for break-glass recovery of
secrets that already live in LastPass:

```json
{"name": "old-lastpass", "type": "lastpass",
 "lastpass": {"folder": "scredmanager"}}
```

Entries are `<folder>/<id>`; reads use `lpass show --password` (secret on
stdout). Log in first with `lpass login <email>`.

## GUI (Tauri v2)

One engine (the CLI), two front-ends. **The GUI never owns a secret and never
touches the keychain** — the Rust backend does nothing but spawn
`scredmanager <cmd> --json` and relay the envelope to a static HTML/JS view
(no npm, no bundler; `withGlobalTauri`).

```sh
make gui-run      # dev: compile + open the window (needs Rust: brew install rust)
make gui          # release binary at gui/src-tauri/target/release/scredmanager-gui
make gui-audit    # verify no keychain/Security.framework dependency in gui/
```

- Service list with status/expiry badges (green/amber/red) from `status --json`
- Per-service **Login** button: clipboard capture by default, device-code flow
  when the manifest configures `deviceFlow` (masked prompt needs a TTY, so the
  GUI never uses it)
- **Import dotenv** field, ad-hoc entry management, expiry banner
- "notify on launch" setting reuses `status --quiet --notify` — can replace
  the launchd job
- `get`/`run`/`export` are deliberately **not** exposed: no secret ever enters
  the GUI process

## Development

```sh
make test               # unit tests (fake store)
make integration        # real-keychain tests (macOS only)
make build
```

Security discipline (enforced in review):

1. Secrets travel via stdin/prompt/keychain API — never argv, never logs; the
   redact helper wraps all error paths. For subprocesses this includes env:
   secrets never ride on child argv or environment (askpass/stdin only).
2. Every file write: 0600 + atomic; every dir: 0700.
3. `get` TTY refusal and `curl` host allowlist are hard behavior, not flags.
4. GUI has no keychain code path (`make gui-audit`) and no secret-bearing
   commands in its IPC whitelist.
