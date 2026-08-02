package cli

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmanager/internal/store"
)

type entryInfo struct {
	ID          string `json:"id"`
	Label       string `json:"label,omitempty"`
	EnvVar      string `json:"envVar,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
	Storage     string `json:"storage"`
	DaysLeft    *int   `json:"daysLeft,omitempty"`
}

func collectEntries(now time.Time) ([]entryInfo, error) {
	ids, err := store.ListIDs()
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	var out []entryInfo
	for _, id := range ids {
		m, err := store.ReadMeta(id)
		if err != nil {
			return nil, err
		}
		e := entryInfo{ID: id, Label: m.Label, EnvVar: m.EnvVar, Kind: m.Kind, Fingerprint: m.Fingerprint, ExpiresAt: m.ExpiresAt, Storage: m.Storage}
		if d, ok := m.ExpiresIn(now); ok {
			days := int(d.Hours() / 24)
			e.DaysLeft = &days
		}
		out = append(out, e)
	}
	return out, nil
}

func newLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List entries with expiry and storage provenance",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := collectEntries(time.Now())
			if err != nil {
				return err
			}
			if jsonOut {
				emit(entries)
				return nil
			}
			if len(entries) == 0 {
				fmt.Println("no entries")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tENV VAR\tEXPIRES\tSTORAGE")
			for _, e := range entries {
				exp := "-"
				if e.ExpiresAt != "" {
					exp = e.ExpiresAt
					if e.DaysLeft != nil {
						exp = fmt.Sprintf("%s (%dd)", e.ExpiresAt[:10], *e.DaysLeft)
					}
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.ID, orDash(e.EnvVar), exp, e.Storage)
			}
			return w.Flush()
		},
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
