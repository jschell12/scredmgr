package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmgr/internal/share"
)

func newInboxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inbox",
		Short: "Manage share payloads spooled while the keychain was locked",
	}
	cmd.AddCommand(newInboxLsCmd(), newInboxImportCmd())
	return cmd
}

func newInboxLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List spooled share payloads",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			infos, err := share.ListSpooled()
			if err != nil {
				return err
			}
			if jsonOut {
				emit(map[string]any{"spooled": infos})
				return nil
			}
			if len(infos) == 0 {
				fmt.Println("inbox is empty")
				return nil
			}
			for _, in := range infos {
				fmt.Printf("%s  from %s at %s: %s\n", in.Path, in.From, in.SentAt, strings.Join(in.IDs, ", "))
			}
			return nil
		},
	}
}

func newInboxImportCmd() *cobra.Command {
	var overwrite bool
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Store spooled entries into the secret backend and drain the inbox",
		Long: "Run this from a logged-in (GUI) session where the keychain is\n" +
			"unlockable. Each blob is deleted only after all of its entries were\n" +
			"stored or skipped; a still-locked keychain leaves blobs in place.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			infos, err := share.ListSpooled()
			if err != nil {
				return err
			}
			var results []shareResult
			for _, in := range infos {
				p, err := share.OpenSpooled(in.Path)
				if err != nil {
					results = append(results, shareResult{ID: in.Path, Action: "failed", Reason: err.Error()})
					continue
				}
				blobResults, spillover := applyShared(p.Entries, p.From, overwrite)
				results = append(results, blobResults...)
				if len(spillover) > 0 {
					// Keychain still locked: keep the blob untouched for a
					// later import. Entries already stored will be skipped
					// then (idempotent re-import).
					for _, e := range spillover {
						results = append(results, shareResult{ID: e.ID, Action: "spooled", Reason: "keychain still locked; blob kept"})
					}
					continue
				}
				failed := false
				for _, r := range blobResults {
					if r.Action == "failed" {
						failed = true
						break
					}
				}
				if !failed {
					if err := share.RemoveSpooled(in.Path); err != nil {
						results = append(results, shareResult{ID: in.Path, Action: "failed", Reason: "drained but not deleted: " + err.Error()})
					}
				}
			}
			if len(results) == 0 && !jsonOut {
				fmt.Println("inbox is empty")
				return nil
			}
			return emitShareResults("inbox", results)
		},
	}
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "replace entries that already exist locally")
	return cmd
}
