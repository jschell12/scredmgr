package cli

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmgr/internal/safety"
	"github.com/jschell12/scredmgr/internal/share"
	"github.com/jschell12/scredmgr/internal/store"
)

// isLockedKeychainErr is swapped out in tests.
var isLockedKeychainErr = store.IsLockedKeychainErr

type shareResult struct {
	ID     string `json:"id"`
	Action string `json:"action"` // stored | skipped | spooled | failed | sent | would-send
	Reason string `json:"reason,omitempty"`
}

func newReceiveCmd() *cobra.Command {
	var (
		fromStdin bool
		overwrite bool
	)
	cmd := &cobra.Command{
		Use:   "receive --stdin",
		Short: "Receive secrets shared from another machine (payload on stdin)",
		Long: "Counterpart of `scredmgr share`: reads a share payload from stdin and\n" +
			"stores each entry in the local secret backend. Existing entries are\n" +
			"skipped unless --overwrite. If the keychain is locked (no GUI session,\n" +
			"e.g. over ssh), remaining entries are spooled to an encrypted inbox —\n" +
			"drain it with `scredmgr inbox import` from a logged-in session.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !fromStdin {
				return errors.New("receive requires --stdin (interactive receive is not supported)")
			}
			p, err := share.Decode(cmd.InOrStdin())
			if err != nil {
				return err
			}
			results, spillover := applyShared(p.Entries, p.From, overwrite)
			if len(spillover) > 0 {
				spool := &share.Payload{
					Version: share.Version,
					From:    p.From,
					SentAt:  p.SentAt,
					Entries: spillover,
				}
				path, err := share.Spool(spool)
				if err != nil {
					for _, e := range spillover {
						results = append(results, shareResult{ID: e.ID, Action: "failed",
							Reason: "keychain locked and inbox spool failed: " + err.Error()})
					}
				} else {
					for _, e := range spillover {
						results = append(results, shareResult{ID: e.ID, Action: "spooled"})
					}
					fmt.Fprintf(os.Stderr, "scredmgr: keychain is locked (no GUI session): %d entr%s spooled to %s — run `scredmgr inbox import` in a logged-in session\n",
						len(spillover), map[bool]string{true: "y", false: "ies"}[len(spillover) == 1], path)
				}
			}
			return emitShareResults(p.From, results)
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "read the share payload from stdin (required)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "replace entries that already exist locally")
	return cmd
}

// applyShared stores shared entries locally. On the first locked-keychain
// error it stops and returns that entry plus all remaining ones as spillover
// for the caller to spool — a locked keychain will not unlock mid-loop.
func applyShared(entries []share.Entry, from string, overwrite bool) (results []shareResult, spillover []share.Entry) {
	for i, e := range entries {
		if err := store.ValidateID(e.ID); err != nil {
			results = append(results, shareResult{ID: e.ID, Action: "skipped", Reason: "invalid id for local store"})
			continue
		}
		secret, err := base64.StdEncoding.DecodeString(e.SecretB64)
		if err != nil {
			results = append(results, shareResult{ID: e.ID, Action: "failed", Reason: "bad base64 secret"})
			continue
		}
		if len(secret) == 0 {
			results = append(results, shareResult{ID: e.ID, Action: "failed", Reason: "empty secret"})
			continue
		}
		safety.Track(secret)
		if _, err := store.ReadMeta(e.ID); err == nil && !overwrite {
			results = append(results, shareResult{ID: e.ID, Action: "skipped", Reason: "exists locally (use --overwrite)"})
			continue
		}
		if err := backend.Set(e.ID, secret); err != nil {
			if isLockedKeychainErr(err) {
				return results, entries[i:]
			}
			results = append(results, shareResult{ID: e.ID, Action: "failed", Reason: err.Error()})
			continue
		}
		now := time.Now().Format(time.RFC3339)
		m := &store.Meta{
			Label:      e.Label,
			EnvVar:     e.EnvVar,
			ExpiresAt:  e.ExpiresAt,
			Notes:      e.Notes,
			Kind:       e.Kind,
			CreatedAt:  now,
			Storage:    store.PlatformStorage(),
			SharedFrom: from,
			SharedAt:   now,
		}
		if prev, err := store.ReadMeta(e.ID); err == nil {
			if m.Label == "" {
				m.Label = prev.Label
			}
			if m.EnvVar == "" {
				m.EnvVar = prev.EnvVar
			}
			if m.Notes == "" {
				m.Notes = prev.Notes
			}
		}
		if err := store.WriteMeta(e.ID, m); err != nil {
			backend.Delete(e.ID) // no backend-only orphans
			results = append(results, shareResult{ID: e.ID, Action: "failed", Reason: err.Error()})
			continue
		}
		results = append(results, shareResult{ID: e.ID, Action: "stored"})
	}
	return results, nil
}

// emitShareResults prints per-entry outcomes (JSON envelope or plain rows)
// and returns a non-nil exit error when any entry failed.
func emitShareResults(from string, results []shareResult) error {
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Action]++
	}
	if jsonOut {
		emit(map[string]any{
			"from":    from,
			"results": results,
			"stored":  counts["stored"],
			"skipped": counts["skipped"],
			"spooled": counts["spooled"],
			"failed":  counts["failed"],
		})
	} else {
		for _, r := range results {
			if r.Reason != "" {
				fmt.Printf("%-12s %s (%s)\n", r.Action, r.ID, r.Reason)
			} else {
				fmt.Printf("%-12s %s\n", r.Action, r.ID)
			}
		}
	}
	if failed := counts["failed"]; failed > 0 {
		return &exitCodeError{code: exitError, err: fmt.Errorf("%d item(s) failed", failed)}
	}
	return nil
}
