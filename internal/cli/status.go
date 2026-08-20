package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
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
	var quiet, notify bool
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
			var warnLines []string
			warnings := 0
			for _, e := range entries {
				s := statusInfo{entryInfo: e, State: "no-expiry"}
				if e.DaysLeft != nil {
					switch {
					case *e.DaysLeft < 0:
						s.State = "expired"
						warnings++
						warnLines = append(warnLines, fmt.Sprintf("%s: EXPIRED", e.ID))
					case *e.DaysLeft <= expiryWarnDays:
						s.State = "expiring"
						warnings++
						warnLines = append(warnLines, fmt.Sprintf("%s: %dd left", e.ID, *e.DaysLeft))
					default:
						s.State = "ok"
					}
				}
				rows = append(rows, s)
			}

			if notify && warnings > 0 {
				if err := postNotification("scredmgr", strings.Join(warnLines, ", ")); err != nil {
					fmt.Fprintf(os.Stderr, "notification failed: %v\n", err)
				}
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
	cmd.Flags().BoolVar(&notify, "notify", false, "post a macOS notification when entries are expiring/expired")
	return cmd
}

// postNotification shows a native notification via osascript. Only entry ids
// and day counts are included — never secret material.
func postNotification(title, message string) error {
	script := fmt.Sprintf("display notification %q with title %q", message, title)
	return exec.Command("osascript", "-e", script).Run()
}
