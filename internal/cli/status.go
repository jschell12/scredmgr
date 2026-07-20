package cli

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

const expiryWarnDays = 7

type statusInfo struct {
	entryInfo
	State string `json:"state"` // ok | expiring | expired | no-expiry
}

func newStatusCmd() *cobra.Command {
	var quiet bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show entry health with ≤7-day expiry warnings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			now := time.Now()
			entries, err := collectEntries(now)
			if err != nil {
				return err
			}
			var rows []statusInfo
			warnings := 0
			for _, e := range entries {
				s := statusInfo{entryInfo: e, State: "no-expiry"}
				if e.DaysLeft != nil {
					switch {
					case *e.DaysLeft < 0:
						s.State = "expired"
						warnings++
					case *e.DaysLeft <= expiryWarnDays:
						s.State = "expiring"
						warnings++
					default:
						s.State = "ok"
					}
				}
				rows = append(rows, s)
			}

			if jsonOut {
				emit(map[string]any{"entries": rows, "warnings": warnings})
				return nil
			}
			if quiet {
				for _, r := range rows {
					switch r.State {
					case "expired":
						fmt.Printf("%s: EXPIRED (%s)\n", r.ID, r.ExpiresAt[:10])
					case "expiring":
						fmt.Printf("%s: expires in %dd (%s)\n", r.ID, *r.DaysLeft, r.ExpiresAt[:10])
					}
				}
				return nil
			}
			if len(rows) == 0 {
				fmt.Println("no entries")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSTATE\tEXPIRES\tENV VAR\tSTORAGE")
			for _, r := range rows {
				exp := "-"
				if r.ExpiresAt != "" {
					exp = r.ExpiresAt[:10]
					if r.DaysLeft != nil {
						exp = fmt.Sprintf("%s (%dd)", exp, *r.DaysLeft)
					}
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.State, exp, orDash(r.EnvVar), r.Storage)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&quiet, "quiet", false, "only print expiring/expired entries (for launchd)")
	return cmd
}
