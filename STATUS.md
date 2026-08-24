# STATUS

## 2026-08-24

### Completed
- **LAN secret sharing** (PR #14, merged): `share` / `receive --stdin` / `inbox ls|import`.
  - Sender pipes a wire-format-v1 JSON payload into `ssh -o BatchMode=yes <host> scredmgr receive --stdin --json` — secrets travel stdin-only, never argv/env; key-based ssh auth required.
  - VPN gate: detects an active VPN (macOS `scutil --nc list` + default-route iface; Linux `ip route`), warns + confirms on a TTY, fails closed non-TTY; `--ignore-vpn` overrides. Detection errors warn but don't block.
  - Interactive host picker from `~/.ssh/config` (`--probe` annotates reachability) and entry multi-select; non-TTY requires `--to`/`--only`.
  - Receiver validates ids, skips existing unless `--overwrite`, records `sharedFrom`/`sharedAt`, rolls back on meta-write failure; `ssh`-kind entries skipped unless named explicitly.
  - **Encrypted inbox**: locked-keychain receivers (non-interactive ssh) spool entries as AES-256-GCM blobs (AAD = filename) under `~/.scredmgr/inbox/`; `inbox import` in a GUI session drains them, keeping blobs while still locked (idempotent).
  - **Linux backend**: encrypted `FileStore` (AES-256-GCM, AAD = id, machine-local `store.key`, `_storage: "encfile"`) behind a `NewPlatformStore()` build-tag split; `make build-linux` cross-compiles amd64+arm64. `status --notify` and `launchd` now return macOS-only errors elsewhere.
- **End-to-end verified** on both peer types:
  - macOS peer (headless over ssh): share → `spooled` → import-while-locked keeps blob → `inbox import` in a GUI session stores → secret round-trip + provenance meta confirmed → re-share reports `skipped`. Blob at rest verified 0600 with no plaintext.
  - Linux peer: `make build-linux` binary installed → share → `sent` (direct FileStore store) → round-trip OK, `encfile` meta, `store.key` 600 / `.secrets` 700.

### In progress
- Nothing.

### Blockers
- None.

### Next steps
- Optionally follow `Include` directives when parsing `~/.ssh/config` for the host picker.
- Consider a libsecret backend on Linux to replace the file-based key at rest.
- Consider `--path` support in the GUI (Tauri) entry list (carried over).

## 2026-08-21

### Completed
- **Public release**: repository is now public at https://github.com/jschell12/scredmgr.
  - Pre-release audit of the full git history (all branches, deleted files, commit messages): no secrets, no personal data beyond git authorship — clean.
  - Deleted 11 stale merged branches; `main` is the only branch.
  - Added MIT license (PR #12).
  - Set repo description and topics (cli, go, keychain, macos, secrets-management, tauri).

### In progress
- Nothing.

### Blockers
- None.

### Next steps
- Consider `--path` support in the GUI (Tauri) entry list (carried over).
- Optionally teach `sync` to map namespaces to provider path prefixes (carried over).

## 2026-08-06

### Completed
- **Namespaced secret paths** (PR #8, merged): ids may carry slash-separated path segments (`work/jira`) so the same env var can map to different accounts (personal `JIRA_TOKEN` vs a service account).
  - `run --path <ns> -- cmd` / `export --path <ns>`: namespace entries overlay root entries, overriding on envVar collision; no `--path` = root only (back-compat).
  - `ls --path <ns>` filter; `get`/`rm`/`check`/`curl`/`sync --only` accept path-qualified ids.
  - Manifest lookup falls back to basename (`work/github` inherits the `github` service).
  - Metadata nests under `~/.scredmgr/<ns>/` (0700, empty dirs pruned); keychain account = full id (`token/work/jira`); `.`/`..`/empty segments rejected.
  - New tests: path validation, nested meta round-trip, recursive ListIDs, dir pruning, overlay resolution, manifest fallback. Full suite green.
- Rebuilt and installed to `~/.local/bin/scredmgr` (stable codesign identity — no keychain re-prompts).
- **README restructure**: quick-start examples up top, full command/flag reference and provider docs at bottom; milestone (M6–M9) labels removed.

### In progress
- Nothing.

### Blockers
- None.

### Next steps
- Consider `--path` support in the GUI (Tauri) entry list.
- Optionally teach `sync` to map namespaces to provider path prefixes (Vault KV already tolerates `/` in ids).
