package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmanager/internal/manifest"
	"github.com/jschell12/scredmanager/internal/safety"
	"github.com/jschell12/scredmanager/internal/store"
)

func newImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <dotenv-file>",
		Short: "Import a dotenv file — one entry per KEY, straight into the keychain",
		Long: "Parses `export KEY=value` lines. If a manifest service declares that envVar,\n" +
			"the secret is stored under the service id; otherwise under custom:<KEY>.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			safety.Track(content)
			pairs, err := parseDotenv(string(content))
			if err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}

			services, err := manifest.Load()
			if err != nil {
				return err
			}

			now := time.Now().Format(time.RFC3339)
			type result struct {
				ID     string `json:"id"`
				EnvVar string `json:"envVar"`
			}
			var imported []result
			for _, kv := range pairs {
				key, val := kv[0], kv[1]
				if val == "" {
					fmt.Fprintf(os.Stderr, "skipping %s: empty value\n", key)
					continue
				}
				safety.Track([]byte(val))

				id := "custom:" + key
				if svc := manifest.FindByEnvVar(services, key); svc != nil {
					id = svc.ID
				}
				if err := backend.Set(id, []byte(val)); err != nil {
					return fmt.Errorf("store %s: %w", id, err)
				}
				m := &store.Meta{
					EnvVar:    key,
					CreatedAt: now,
					Storage:   store.StorageKeychain,
				}
				if svc := manifest.Find(services, id); svc != nil && svc.ExpiryDays > 0 {
					m.ExpiresAt = time.Now().AddDate(0, 0, svc.ExpiryDays).Format(time.RFC3339)
				}
				if err := store.WriteMeta(id, m); err != nil {
					return err
				}
				imported = append(imported, result{ID: id, EnvVar: key})
			}

			if jsonOut {
				emit(map[string]any{"imported": imported, "source": path})
			} else {
				for _, r := range imported {
					fmt.Printf("imported %s (envVar %s)\n", r.ID, r.EnvVar)
				}
				fmt.Printf("\n%d entries imported into the keychain.\n", len(imported))
				fmt.Printf("REMINDER: the source file still holds plaintext secrets — shred it:\n")
				fmt.Printf("  rm -P %s\n", strings.ReplaceAll(path, " ", "\\ "))
			}
			return nil
		},
	}
}
