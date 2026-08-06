# STATUS

## 2026-08-06

### Completed
- **Namespaced secret paths** (PR #8, merged): ids may carry slash-separated path segments (`work/jira`) so the same env var can map to different accounts (personal `JIRA_TOKEN` vs a service account).
  - `run --path <ns> -- cmd` / `export --path <ns>`: namespace entries overlay root entries, overriding on envVar collision; no `--path` = root only (back-compat).
  - `ls --path <ns>` filter; `get`/`rm`/`check`/`curl`/`sync --only` accept path-qualified ids.
  - Manifest lookup falls back to basename (`work/github` inherits the `github` service).
  - Metadata nests under `~/.scredmanager/<ns>/` (0700, empty dirs pruned); keychain account = full id (`token/work/jira`); `.`/`..`/empty segments rejected.
  - New tests: path validation, nested meta round-trip, recursive ListIDs, dir pruning, overlay resolution, manifest fallback. Full suite green.
- Rebuilt and installed to `~/.local/bin/scredmanager` (stable codesign identity — no keychain re-prompts).

### In progress
- Nothing.

### Blockers
- None.

### Next steps
- Consider `--path` support in the GUI (Tauri) entry list.
- Optionally teach `sync` to map namespaces to provider path prefixes (Vault KV already tolerates `/` in ids).
