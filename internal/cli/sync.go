package cli

import (
	"context"
	"errors"
	"fmt"
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
	ID     string `json:"id"`
	Action string `json:"action"` // pushed | pulled | would-push | would-pull | skipped | failed
	Reason string `json:"reason,omitempty"`
}

func newSyncCmd() *cobra.Command {
	var (
		push      bool
		pull      bool
		only      string
		dryRun    bool
		overwrite bool
	)
	cmd := &cobra.Command{
		Use:   "sync <provider>",
		Short: "Push or pull secrets between the keychain and a remote provider",
		Long: "Explicit, direction-only sync. The keychain remains the canonical local\n" +
			"store: --push copies local entries to the provider (always overwriting\n" +
			"remote), --pull copies remote entries into the keychain (skipping existing\n" +
			"local entries unless --overwrite). There is no merge and no delete\n" +
			"propagation.",
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

			var onlySet map[string]bool
			if only != "" {
				onlySet = make(map[string]bool)
				for _, id := range strings.Split(only, ",") {
					onlySet[strings.TrimSpace(id)] = true
				}
			}

			ctx := cmd.Context()
			var results []syncResult
			if push {
				results, err = syncPush(ctx, p, onlySet, dryRun)
			} else {
				results, err = syncPull(ctx, p, onlySet, dryRun, overwrite)
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
	cmd.MarkFlagsMutuallyExclusive("push", "pull")
	return cmd
}

func syncPush(ctx context.Context, p provider.Provider, only map[string]bool, dryRun bool) ([]syncResult, error) {
	ids, err := store.ListIDs()
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	var results []syncResult
	for _, id := range ids {
		if only != nil && !only[id] {
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
		if m.Storage == store.StorageNone {
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
		results = append(results, syncResult{ID: id, Action: "pushed"})
	}
	return results, nil
}

func syncPull(ctx context.Context, p provider.Provider, only map[string]bool, dryRun, overwrite bool) ([]syncResult, error) {
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
	for _, id := range remoteIDs {
		if only != nil && !only[id] {
			continue
		}
		if err := store.ValidateID(id); err != nil {
			results = append(results, syncResult{ID: id, Action: "skipped", Reason: "invalid id for local store"})
			continue
		}
		if _, err := store.ReadMeta(id); err == nil && !overwrite {
			results = append(results, syncResult{ID: id, Action: "skipped", Reason: "exists locally (use --overwrite)"})
			continue
		}
		if dryRun {
			results = append(results, syncResult{ID: id, Action: "would-pull"})
			continue
		}
		secret, err := p.Get(ctx, id)
		if err != nil {
			results = append(results, syncResult{ID: id, Action: "failed", Reason: err.Error()})
			continue
		}
		if err := backend.Set(id, secret); err != nil {
			results = append(results, syncResult{ID: id, Action: "failed", Reason: err.Error()})
			continue
		}
		now := time.Now()
		m := &store.Meta{
			CreatedAt:  now.Format(time.RFC3339),
			Storage:    store.StorageKeychain,
			SyncedFrom: p.Name(),
			SyncedAt:   now.Format(time.RFC3339),
		}
		if prev, err := store.ReadMeta(id); err == nil {
			m.Label, m.EnvVar, m.Notes = prev.Label, prev.EnvVar, prev.Notes
		}
		if svc := manifest.Find(services, id); svc != nil {
			if m.EnvVar == "" {
				m.EnvVar = svc.EnvVar
			}
			if svc.ExpiryDays > 0 {
				m.ExpiresAt = now.AddDate(0, 0, svc.ExpiryDays).Format(time.RFC3339)
			}
		}
		if err := store.WriteMeta(id, m); err != nil {
			backend.Delete(id) // no keychain-only orphans
			results = append(results, syncResult{ID: id, Action: "failed", Reason: err.Error()})
			continue
		}
		results = append(results, syncResult{ID: id, Action: "pulled"})
	}
	return results, nil
}
