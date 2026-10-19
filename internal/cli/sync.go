package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmgr/internal/manifest"
	"github.com/jschell12/scredmgr/internal/provider"
	"github.com/jschell12/scredmgr/internal/store"
)

// openProvider is swapped out in tests.
var openProvider = provider.Open

type syncResult struct {
	ID string `json:"id"`
	// pushed | pulled | would-push | would-pull | skipped | failed, plus for
	// --newer: unchanged (local already matches the remote's latest write)
	// and kept-local (local changed after the remote copy; not overwritten);
	// --create-only: held (exists locally, never replaced).
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
}

func newSyncCmd() *cobra.Command {
	var (
		push       bool
		pull       bool
		only       string
		dryRun     bool
		overwrite  bool
		newer      bool
		createOnly bool
		since      string
		include    string
	)
	cmd := &cobra.Command{
		Use:   "sync <provider>",
		Short: "Push or pull secrets between the keychain and a remote provider",
		Long: "Explicit, direction-only sync. The keychain remains the canonical local\n" +
			"store: --push copies local entries to the provider (always overwriting\n" +
			"remote), --pull copies remote entries into the keychain (skipping existing\n" +
			"local entries unless --overwrite). There is no merge and no delete\n" +
			"propagation.\n\n" +
			"For unattended pulls: --newer replaces a local entry only when the\n" +
			"remote value was written after the entry last changed locally (else\n" +
			"kept-local); --create-only pulls only ids missing locally (existing\n" +
			"ones are held); --since <RFC3339> skips remote entries written before\n" +
			"that time. Ids removed with `rm` are tombstoned: no pull recreates them\n" +
			"from a remote copy written at or before the removal. The provider's own\n" +
			"credential (a Vault tokenRef) never syncs. --include takes\n" +
			"comma-separated glob patterns (path.Match; * does not cross /).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if push == pull {
				return errors.New("exactly one of --push or --pull is required")
			}
			configs, err := provider.LoadConfigs()
			if err != nil {
				return err
			}
			cfg, err := provider.FindConfig(configs, args[0])
			if err != nil {
				return err
			}
			p, err := openProvider(*cfg, backend)
			if err != nil {
				return err
			}
			if push && !p.Writable() {
				return fmt.Errorf("provider %s is read-only; --push is not supported", p.Name())
			}
			if push && (newer || createOnly || since != "") {
				return errors.New("--newer, --create-only and --since apply to --pull only")
			}
			var sinceT *time.Time
			if since != "" {
				t, err := time.Parse(time.RFC3339, since)
				if err != nil {
					return fmt.Errorf("--since: want an RFC3339 time (e.g. 2026-10-19T17:00:00Z): %w", err)
				}
				sinceT = &t
			}
			var patterns []string
			if include != "" {
				for _, pat := range strings.Split(include, ",") {
					pat = strings.TrimSpace(pat)
					if pat == "" {
						continue
					}
					if _, err := path.Match(pat, ""); err != nil {
						return fmt.Errorf("--include: bad pattern %q: %w", pat, err)
					}
					patterns = append(patterns, pat)
				}
			}

			var onlySet map[string]bool
			if only != "" {
				onlySet = make(map[string]bool)
				for _, id := range strings.Split(only, ",") {
					onlySet[strings.TrimSpace(id)] = true
				}
			}

			ctx := cmd.Context()
			var results []syncResult
			filter := idFilter{only: onlySet, include: patterns, exclude: map[string]bool{}}
			for _, own := range cfg.OwnSecretIDs() {
				filter.exclude[own] = true
			}
			if push {
				results, err = syncPush(ctx, p, filter, dryRun)
			} else {
				results, err = syncPull(ctx, p, filter, pullOpts{
					dryRun: dryRun, overwrite: overwrite, newer: newer, createOnly: createOnly, since: sinceT,
				})
			}
			if err != nil {
				return err
			}

			counts := map[string]int{}
			for _, r := range results {
				counts[r.Action]++
			}
			failed := counts["failed"]

			if jsonOut {
				emit(map[string]any{
					"provider":  p.Name(),
					"direction": map[bool]string{true: "push", false: "pull"}[push],
					"dryRun":    dryRun,
					"results":   results,
					"pushed":    counts["pushed"],
					"pulled":    counts["pulled"],
					"skipped":   counts["skipped"],
					"unchanged": counts["unchanged"],
					"keptLocal": counts["kept-local"],
					"held":      counts["held"],
					"failed":    failed,
				})
			} else {
				for _, r := range results {
					if r.Reason != "" {
						fmt.Printf("%-12s %s (%s)\n", r.Action, r.ID, r.Reason)
					} else {
						fmt.Printf("%-12s %s\n", r.Action, r.ID)
					}
				}
				if len(results) == 0 {
					fmt.Println("nothing to sync")
				}
			}
			if failed > 0 {
				return &exitCodeError{code: exitError, err: fmt.Errorf("%d item(s) failed", failed)}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&push, "push", false, "copy local entries to the provider")
	cmd.Flags().BoolVar(&pull, "pull", false, "copy provider entries into the keychain")
	cmd.Flags().StringVar(&only, "only", "", "comma-separated ids to limit the sync to")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the plan without transferring any values")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "pull: replace entries that already exist locally")
	cmd.Flags().BoolVar(&newer, "newer", false, "pull: replace a local entry only when the remote value is newer than its last local change")
	cmd.Flags().StringVar(&since, "since", "", "pull: skip remote entries written before this RFC3339 time")
	cmd.Flags().StringVar(&include, "include", "", "comma-separated id glob patterns to limit the sync to")
	cmd.MarkFlagsMutuallyExclusive("push", "pull")
	cmd.Flags().BoolVar(&createOnly, "create-only", false, "pull: only create ids missing locally; report existing ones as held")
	cmd.MarkFlagsMutuallyExclusive("overwrite", "newer", "create-only")
	return cmd
}

// idFilter is the --only / --include selection. A nil only and empty include
// select everything.
type idFilter struct {
	only    map[string]bool
	include []string
	// exclude always wins, over --only and --include alike.
	exclude map[string]bool
}

func (f idFilter) match(id string) bool {
	if f.exclude[id] {
		return false
	}
	if f.only != nil && !f.only[id] {
		return false
	}
	if len(f.include) == 0 {
		return true
	}
	for _, pat := range f.include {
		if ok, _ := path.Match(pat, id); ok {
			return true
		}
	}
	return false
}

func syncPush(ctx context.Context, p provider.Provider, filter idFilter, dryRun bool) ([]syncResult, error) {
	only := filter.only
	ids, err := store.ListIDs()
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	var results []syncResult
	for _, id := range ids {
		if !filter.match(id) {
			continue
		}
		m, err := store.ReadMeta(id)
		if err != nil {
			results = append(results, syncResult{ID: id, Action: "failed", Reason: err.Error()})
			continue
		}
		// ssh passphrases don't belong remote unless explicitly requested.
		if m.Kind == "ssh" && only == nil {
			results = append(results, syncResult{ID: id, Action: "skipped", Reason: "ssh entry (name it in --only to push its passphrase)"})
			continue
		}
		if m.Storage == store.StorageFile || m.Storage == store.StorageMixed {
			results = append(results, syncResult{ID: id, Action: "skipped", Reason: "not migrated to keychain yet"})
			continue
		}
		if !store.SecretInBackend(m) {
			results = append(results, syncResult{ID: id, Action: "skipped", Reason: "no keychain secret"})
			continue
		}
		if dryRun {
			results = append(results, syncResult{ID: id, Action: "would-push"})
			continue
		}
		secret, err := backend.Get(id)
		if err != nil {
			results = append(results, syncResult{ID: id, Action: "failed", Reason: err.Error()})
			continue
		}
		if err := p.Put(ctx, id, secret); err != nil {
			results = append(results, syncResult{ID: id, Action: "failed", Reason: err.Error()})
			continue
		}
		// Record the remote write time we produced, so a later --newer pull
		// (and its --dry-run) sees this entry as unchanged without fetching
		// the value back. Best effort: the push itself already succeeded.
		if ts, ok := p.(provider.Timestamped); ok {
			if at, err := ts.UpdatedAt(ctx, id); err == nil {
				m.SyncedFrom, m.SyncedAt, m.RemoteAt = p.Name(), store.Stamp(time.Now()), at.UTC().Format(time.RFC3339Nano)
				if err := store.WriteMeta(id, m); err != nil {
					results = append(results, syncResult{ID: id, Action: "pushed", Reason: "provenance not recorded: " + err.Error()})
					continue
				}
			}
		}
		results = append(results, syncResult{ID: id, Action: "pushed"})
	}
	return results, nil
}

type pullOpts struct {
	dryRun     bool
	overwrite  bool
	newer      bool
	createOnly bool
	since      *time.Time
}

// localChangeTime is the latest moment the local entry's value was written:
// set/import/pull stamp createdAt, a pull stamps syncedAt, a share sharedAt.
// ok is false when no timestamp parses, in which case --newer keeps local.
func localChangeTime(m *store.Meta) (time.Time, bool) {
	var latest time.Time
	ok := false
	for _, s := range []string{m.CreatedAt, m.SyncedAt, m.SharedAt} {
		if s == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			continue
		}
		if !ok || t.After(latest) {
			latest, ok = t, true
		}
	}
	return latest, ok
}

// remoteAfter reports whether remoteAt is strictly later than the recorded
// RFC3339 stamp. An unparseable stamp counts as "after" so the time
// comparison below decides instead.
func remoteAfter(remoteAt time.Time, recorded string) bool {
	t, err := time.Parse(time.RFC3339Nano, recorded)
	if err != nil {
		return true
	}
	return remoteAt.After(t)
}

func syncPull(ctx context.Context, p provider.Provider, filter idFilter, o pullOpts) ([]syncResult, error) {
	ts, _ := p.(provider.Timestamped)
	if (o.newer || o.since != nil) && ts == nil {
		return nil, fmt.Errorf("provider %s cannot report write times; --newer/--since are not supported", p.Name())
	}
	remoteIDs, err := p.List(ctx)
	if err != nil {
		return nil, err
	}
	sort.Strings(remoteIDs)
	services, err := manifest.Load()
	if err != nil {
		return nil, err
	}
	var results []syncResult
	add := func(id, action, reason string) {
		results = append(results, syncResult{ID: id, Action: action, Reason: reason})
	}
	for _, id := range remoteIDs {
		if !filter.match(id) {
			continue
		}
		if err := store.ValidateID(id); err != nil {
			add(id, "skipped", "invalid id for local store")
			continue
		}
		prev, perr := store.ReadMeta(id)
		exists := perr == nil

		if exists {
			switch {
			case o.createOnly:
				add(id, "held", "")
				continue
			case !o.overwrite && !o.newer:
				add(id, "skipped", "exists locally (use --overwrite)")
				continue
			}
		}

		var tomb time.Time
		tombstoned := false
		if !exists {
			t, ok, err := store.Tombstone(id)
			if err != nil {
				add(id, "failed", "tombstones unreadable: "+err.Error())
				continue
			}
			tomb, tombstoned = t, ok
			if tombstoned && ts == nil {
				add(id, "skipped", "removed locally; provider cannot report write times")
				continue
			}
		}

		// The remote write time, from metadata only, when any rule needs it.
		var remoteAt time.Time
		remoteStamp := ""
		// Scheduled modes always read it, so a deleted remote version is a
		// clean skip rather than a failed fetch.
		if ts != nil && (o.since != nil || tombstoned || o.newer || o.createOnly) {
			at, err := ts.UpdatedAt(ctx, id)
			if errors.Is(err, provider.ErrNoCurrentValue) {
				add(id, "skipped", "remote current version is deleted")
				continue
			}
			if err != nil {
				add(id, "failed", err.Error())
				continue
			}
			remoteAt, remoteStamp = at, at.UTC().Format(time.RFC3339Nano)
		}
		if tombstoned && !remoteAt.After(tomb) {
			add(id, "skipped", "removed locally at "+tomb.UTC().Format(time.RFC3339)+"; remote copy is not newer")
			continue
		}
		if o.since != nil && remoteAt.Before(*o.since) {
			if exists {
				add(id, "unchanged", "")
			} else {
				add(id, "skipped", "written before --since")
			}
			continue
		}

		// compareLocal: remote is newer than the local entry, so fetch the
		// value and skip the keychain write if it already matches.
		compareLocal := false
		if exists && o.newer {
			localAt, ok := localChangeTime(prev)
			switch {
			case prev.SyncedFrom == p.Name() && prev.RemoteAt != "" && !remoteAfter(remoteAt, prev.RemoteAt):
				// Nothing written remotely since the copy we hold (pulled or pushed).
				add(id, "unchanged", "")
				continue
			case !ok:
				add(id, "kept-local", "local entry has no timestamp")
				continue
			case !remoteAt.After(localAt) && prev.SyncedFrom == p.Name():
				add(id, "unchanged", "")
				continue
			case !remoteAt.After(localAt):
				add(id, "kept-local", "local entry changed after the remote copy")
				continue
			}
			compareLocal = true
		}

		if o.dryRun {
			if compareLocal {
				// A real run fetches the value and reports unchanged if it
				// matches; dry-run never transfers values, so it cannot know.
				add(id, "would-pull", "remote is newer; unchanged if the values match")
			} else {
				add(id, "would-pull", "")
			}
			continue
		}
		secret, err := p.Get(ctx, id)
		if err != nil {
			add(id, "failed", err.Error())
			continue
		}
		now := time.Now()
		if compareLocal {
			if cur, err := backend.Get(id); err == nil && bytes.Equal(cur, secret) {
				// Same value (e.g. pushed by an older scredmgr): record
				// provenance so the next run sees local as current.
				prev.SyncedFrom, prev.SyncedAt, prev.RemoteAt = p.Name(), store.Stamp(now), remoteStamp
				if err := store.WriteMeta(id, prev); err != nil {
					add(id, "failed", err.Error())
					continue
				}
				add(id, "unchanged", "")
				continue
			}
		}
		if err := backend.Set(id, secret); err != nil {
			add(id, "failed", err.Error())
			continue
		}
		var m *store.Meta
		if exists {
			// Replace the value, keep everything else about the entry:
			// label, env var, notes, expiry, ssh fields, share provenance.
			cp := *prev
			m = &cp
			m.Token = ""
		} else {
			m = &store.Meta{}
		}
		m.CreatedAt = store.Stamp(now)
		m.Storage = store.PlatformStorage()
		m.SyncedFrom, m.SyncedAt, m.RemoteAt = p.Name(), store.Stamp(now), remoteStamp
		if svc := manifest.Find(services, id); svc != nil {
			if m.EnvVar == "" {
				m.EnvVar = svc.EnvVar
			}
			if svc.ExpiryDays > 0 && m.ExpiresAt == "" {
				m.ExpiresAt = now.AddDate(0, 0, svc.ExpiryDays).Format(time.RFC3339)
			}
		}
		if err := store.WriteMeta(id, m); err != nil {
			if !exists {
				backend.Delete(id) // no keychain-only orphans
			}
			add(id, "failed", err.Error())
			continue
		}
		add(id, "pulled", "")
	}
	return results, nil
}
