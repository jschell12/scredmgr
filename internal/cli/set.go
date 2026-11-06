package cli

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmgr/internal/manifest"
	"github.com/jschell12/scredmgr/internal/safety"
	"github.com/jschell12/scredmgr/internal/store"
)

func newSetCmd() *cobra.Command {
	var (
		fromStdin  bool
		envVar     string
		label      string
		notes      string
		expiryDays int
		ifChanged  bool
	)
	cmd := &cobra.Command{
		Use:   "set <id>",
		Short: "Store a secret (masked prompt or stdin — never argv)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			if err := store.ValidateID(id); err != nil {
				return err
			}

			var secret []byte
			var err error
			if fromStdin || !safety.IsTTY(os.Stdin) {
				secret, err = io.ReadAll(os.Stdin)
				if err != nil {
					return err
				}
				secret = bytes.TrimRight(secret, "\r\n")
			} else {
				secret, err = safety.ReadMasked(fmt.Sprintf("Secret for %s: ", id))
				if err != nil {
					return err
				}
			}
			if len(secret) == 0 {
				return errors.New("refusing to store an empty secret")
			}
			safety.Track(secret)

			// --if-changed: an identical stored value is left alone. Writing
			// it again can raise a keychain prompt per entry, which is what a
			// login-time sync of every file-based secret ran into (2026-11-06).
			// Checked before the live verification so an unchanged entry costs
			// no network call either.
			if ifChanged && storedEquals(id, secret) {
				if err := refreshMetaIfNeeded(id, envVar, label, notes); err != nil {
					return err
				}
				if jsonOut {
					emit(map[string]any{"id": id, "unchanged": true})
				} else {
					fmt.Printf("unchanged %s (keychain)\n", id)
				}
				return nil
			}

			services, err := manifest.Load()
			if err != nil {
				return err
			}
			svc := manifest.Find(services, id)

			// Fail closed: if the service defines a live check, a token that
			// does not pass it is not stored.
			if svc != nil && svc.CheckPath != "" {
				if err := manifest.Verify(svc, string(secret)); err != nil {
					return fmt.Errorf("verification failed, secret NOT stored: %w", err)
				}
			}

			now := time.Now()
			m := &store.Meta{
				Label:     label,
				EnvVar:    envVar,
				Notes:     notes,
				CreatedAt: store.Stamp(now),
				Storage:   store.PlatformStorage(),
			}
			if prev, err := store.ReadMeta(id); err == nil {
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
			if svc != nil {
				if m.EnvVar == "" {
					m.EnvVar = svc.EnvVar
				}
				if expiryDays == 0 {
					expiryDays = svc.ExpiryDays
				}
			}
			if expiryDays > 0 {
				m.ExpiresAt = now.AddDate(0, 0, expiryDays).Format(time.RFC3339)
			}

			if err := backend.Set(id, secret); err != nil {
				return err
			}
			if err := store.WriteMeta(id, m); err != nil {
				return err
			}

			if jsonOut {
				emit(map[string]any{"id": id, "envVar": m.EnvVar, "expiresAt": m.ExpiresAt, "storage": m.Storage})
			} else {
				fmt.Printf("stored %s (keychain)\n", id)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "from-stdin", false, "read the secret from stdin instead of prompting")
	cmd.Flags().StringVar(&envVar, "env-var", "", "environment variable name for `run`")
	cmd.Flags().StringVar(&label, "label", "", "human-readable label")
	cmd.Flags().StringVar(&notes, "notes", "", "free-form notes")
	cmd.Flags().IntVar(&expiryDays, "expiry-days", 0, "days until expiry (default from manifest)")
	cmd.Flags().BoolVar(&ifChanged, "if-changed", false, "skip the keychain write when the stored value is already identical")
	return cmd
}

// storedEquals reports whether id already holds exactly secret in the
// backend. Any read failure (missing item, locked keychain, denied access)
// returns false, so the caller writes: a failed read never counts as "same".
// The stored value is compared in memory and never printed; the copy is
// zeroed before returning.
func storedEquals(id string, secret []byte) bool {
	cur, err := backend.Get(id)
	if err != nil {
		return false
	}
	defer clear(cur)
	return subtle.ConstantTimeCompare(cur, secret) == 1
}

// refreshMetaIfNeeded brings an unchanged entry's metadata in line with any
// fields the caller passed, without touching the keychain. A missing metadata
// file is recreated; an existing one keeps its creation and expiry stamps.
func refreshMetaIfNeeded(id, envVar, label, notes string) error {
	prev, err := store.ReadMeta(id)
	if err != nil {
		return store.WriteMeta(id, &store.Meta{
			Label:     label,
			EnvVar:    envVar,
			Notes:     notes,
			CreatedAt: store.Stamp(time.Now()),
			Storage:   store.PlatformStorage(),
		})
	}
	changed := false
	for _, f := range []struct {
		dst *string
		v   string
	}{
		{&prev.EnvVar, envVar}, {&prev.Label, label}, {&prev.Notes, notes},
	} {
		if f.v != "" && *f.dst != f.v {
			*f.dst = f.v
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return store.WriteMeta(id, prev)
}
