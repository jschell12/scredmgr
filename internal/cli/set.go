package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmanager/internal/manifest"
	"github.com/jschell12/scredmanager/internal/safety"
	"github.com/jschell12/scredmanager/internal/store"
)

func newSetCmd() *cobra.Command {
	var (
		fromStdin  bool
		envVar     string
		label      string
		notes      string
		expiryDays int
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
				CreatedAt: now.Format(time.RFC3339),
				Storage:   store.StorageKeychain,
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
	return cmd
}
