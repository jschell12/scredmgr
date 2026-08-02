package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmanager/internal/store"
)

func newRmCmd() *cobra.Command {
	var files bool
	cmd := &cobra.Command{
		Use:   "rm <id>",
		Short: "Delete a secret and its metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			if err := store.ValidateID(id); err != nil {
				return err
			}

			var meta *store.Meta
			if files {
				m, err := store.ReadMeta(id)
				if err != nil {
					return fmt.Errorf("--files: cannot read metadata for %s: %w", id, err)
				}
				if m.Kind != "ssh" {
					return errors.New("--files only applies to ssh entries")
				}
				meta = m
			}

			keychainErr := backend.Delete(id)
			if keychainErr != nil && !errors.Is(keychainErr, store.ErrNotFound) {
				return keychainErr
			}
			if err := store.DeleteMeta(id); err != nil {
				return err
			}

			var removedFiles []string
			if meta != nil && meta.KeyPath != "" {
				for _, p := range []string{meta.KeyPath, meta.KeyPath + ".pub"} {
					if err := os.Remove(p); err == nil {
						removedFiles = append(removedFiles, p)
					} else if !os.IsNotExist(err) {
						return err
					}
				}
			}

			removedSecret := keychainErr == nil
			if jsonOut {
				emit(map[string]any{"id": id, "removedSecret": removedSecret, "removedMeta": true, "removedFiles": removedFiles})
			} else {
				if removedSecret {
					fmt.Printf("removed %s (keychain + metadata)\n", id)
				} else {
					fmt.Printf("removed %s (metadata only; no keychain item found)\n", id)
				}
				for _, p := range removedFiles {
					fmt.Printf("removed %s\n", p)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&files, "files", false, "also delete the key files of an ssh entry")
	return cmd
}
