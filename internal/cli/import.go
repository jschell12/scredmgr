package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmgr/internal/manifest"
	"github.com/jschell12/scredmgr/internal/safety"
	"github.com/jschell12/scredmgr/internal/store"
)

func newImportCmd() *cobra.Command {
	var ifChanged bool
	cmd := &cobra.Command{
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

			now := store.Stamp(time.Now())
			type result struct {
				ID     string `json:"id"`
				EnvVar string `json:"envVar"`
			}
			var imported, unchanged []result
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
				if ifChanged && storedEquals(id, []byte(val)) {
					if err := refreshMetaIfNeeded(id, key, "", ""); err != nil {
						return err
					}
					unchanged = append(unchanged, result{ID: id, EnvVar: key})
					continue
				}
				if err := backend.Set(id, []byte(val)); err != nil {
					return fmt.Errorf("store %s: %w", id, err)
				}
				m := &store.Meta{
					EnvVar:    key,
					CreatedAt: now,
					Storage:   store.PlatformStorage(),
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
				emit(map[string]any{"imported": imported, "unchanged": unchanged, "source": path})
			} else {
				for _, r := range imported {
					fmt.Printf("imported %s (envVar %s)\n", r.ID, r.EnvVar)
				}
				for _, r := range unchanged {
					fmt.Printf("unchanged %s (envVar %s)\n", r.ID, r.EnvVar)
				}
				fmt.Printf("\n%d entries imported into the keychain", len(imported))
				if ifChanged {
					fmt.Printf(", %d unchanged", len(unchanged))
				}
				fmt.Printf(".\n")
				fmt.Printf("REMINDER: the source file still holds plaintext secrets — shred it:\n")
				fmt.Printf("  rm -P %s\n", strings.ReplaceAll(path, " ", "\\ "))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&ifChanged, "if-changed", false, "skip keys whose stored value is already identical")
	return cmd
}
