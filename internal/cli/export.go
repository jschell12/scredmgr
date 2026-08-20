package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func newExportCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "export [--path ns]",
		Short: "Print `export` lines (escape hatch — gated behind SCREDMGR_ALLOW_EXPORT=1)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// SCREDMANAGER_ALLOW_EXPORT honored as legacy fallback.
			if os.Getenv("SCREDMGR_ALLOW_EXPORT") != "1" && os.Getenv("SCREDMANAGER_ALLOW_EXPORT") != "1" {
				return errors.New("export writes plaintext secrets to stdout; set SCREDMGR_ALLOW_EXPORT=1 if you really mean it (prefer `scredmgr run`)")
			}
			fmt.Fprintln(os.Stderr, "WARNING: emitting plaintext secrets. Prefer `scredmgr run -- <cmd>`.")

			pairs, _, err := resolveEnv(path, nil, backend)
			if err != nil {
				return err
			}
			for _, p := range pairs {
				fmt.Printf("export %s='%s'\n", p.EnvVar, strings.ReplaceAll(string(p.Secret), "'", `'\''`))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "namespace whose entries overlay the root entries (e.g. work)")
	return cmd
}
