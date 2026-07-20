package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmanager/internal/store"
)

func newRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <id>",
		Short: "Delete a secret and its metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			if err := store.ValidateID(id); err != nil {
				return err
			}
			keychainErr := backend.Delete(id)
			if keychainErr != nil && !errors.Is(keychainErr, store.ErrNotFound) {
				return keychainErr
			}
			if err := store.DeleteMeta(id); err != nil {
				return err
			}
			removedSecret := keychainErr == nil
			if jsonOut {
				emit(map[string]any{"id": id, "removedSecret": removedSecret, "removedMeta": true})
			} else {
				if removedSecret {
					fmt.Printf("removed %s (keychain + metadata)\n", id)
				} else {
					fmt.Printf("removed %s (metadata only; no keychain item found)\n", id)
				}
			}
			return nil
		},
	}
}
