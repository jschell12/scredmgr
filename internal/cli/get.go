package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmanager/internal/safety"
	"github.com/jschell12/scredmanager/internal/store"
)

func newGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Print the secret to stdout (pipes and $( ) only — refuses a TTY)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			// Hard behavior, not a flag: never paint a secret onto a terminal.
			if safety.IsTTY(os.Stdout) {
				return &exitCodeError{
					code: exitTTY,
					err:  errors.New("refusing to print a secret to a terminal; use $(scredmanager get " + id + ") or pipe it"),
				}
			}
			secret, err := store.GetSecret(id, backend)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) || os.IsNotExist(err) {
					return &exitCodeError{code: exitMissing, err: fmt.Errorf("no entry for %q", id)}
				}
				return err
			}
			safety.Track(secret)
			os.Stdout.Write(secret)
			fmt.Println()
			return nil
		},
	}
}
