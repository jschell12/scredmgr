package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmanager/internal/safety"
	"github.com/jschell12/scredmanager/internal/store"
)

func newExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Print `export` lines (escape hatch — gated behind SCREDMANAGER_ALLOW_EXPORT=1)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("SCREDMANAGER_ALLOW_EXPORT") != "1" {
				return errors.New("export writes plaintext secrets to stdout; set SCREDMANAGER_ALLOW_EXPORT=1 if you really mean it (prefer `scredmanager run`)")
			}
			fmt.Fprintln(os.Stderr, "WARNING: emitting plaintext secrets. Prefer `scredmanager run -- <cmd>`.")

			ids, err := store.ListIDs()
			if err != nil {
				return err
			}
			for _, id := range ids {
				m, err := store.LoadAndMigrate(id, backend)
				if err != nil {
					return err
				}
				if m.EnvVar == "" {
					continue
				}
				secret, err := store.GetSecret(id, backend)
				if err != nil {
					return err
				}
				safety.Track(secret)
				fmt.Printf("export %s='%s'\n", m.EnvVar, strings.ReplaceAll(string(secret), "'", `'\''`))
			}
			return nil
		},
	}
}
