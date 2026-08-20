package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmgr/internal/manifest"
	"github.com/jschell12/scredmgr/internal/safety"
	"github.com/jschell12/scredmgr/internal/store"
)

func newCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <id>",
		Short: "Verify the stored secret against the service's live API",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			services, err := manifest.Load()
			if err != nil {
				return err
			}
			svc := manifest.Find(services, id)
			if svc == nil {
				return fmt.Errorf("no service %q in services.json (check requires a manifest entry)", id)
			}
			secret, err := store.GetSecret(id, backend)
			if err != nil {
				return err
			}
			safety.Track(secret)
			if err := manifest.Verify(svc, string(secret)); err != nil {
				return err
			}
			if jsonOut {
				emit(map[string]any{"id": id, "valid": true})
			} else {
				fmt.Printf("%s: token valid\n", id)
			}
			return nil
		},
	}
}
