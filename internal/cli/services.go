package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmgr/internal/manifest"
)

func newServicesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "services",
		Short: "Emit the services manifest",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			services, err := manifest.Load()
			if err != nil {
				return err
			}
			if jsonOut {
				emit(services)
				return nil
			}
			if len(services) == 0 {
				fmt.Println("no services defined (edit ~/.scredmgr/services.json)")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tENV VAR\tBASE URL\tAUTH\tEXPIRY")
			for _, s := range services {
				expiry := "-"
				if s.ExpiryDays > 0 {
					expiry = fmt.Sprintf("%dd", s.ExpiryDays)
				}
				auth := s.AuthHeader
				if auth == "" {
					auth = "bearer"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.ID, orDash(s.EnvVar), orDash(s.BaseURL), auth, expiry)
			}
			return w.Flush()
		},
	}
}
