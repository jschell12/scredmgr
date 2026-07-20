// Package cli implements the scredmanager command surface.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmanager/internal/safety"
	"github.com/jschell12/scredmanager/internal/store"
)

// exit codes
const (
	exitOK      = 0
	exitError   = 1
	exitTTY     = 2 // `get` refused because stdout is a TTY
	exitMissing = 3 // entry not found
)

// exitCodeError carries a specific process exit code up to Execute.
type exitCodeError struct {
	code int
	err  error
}

func (e *exitCodeError) Error() string { return e.err.Error() }
func (e *exitCodeError) Unwrap() error { return e.err }

var (
	jsonOut bool
	backend store.Store = store.NewKeychainStore()
)

// SetStore overrides the storage backend (tests only).
func SetStore(s store.Store) { backend = s }

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "scredmanager",
		Short:         "Personal keychain-backed secrets broker",
		Long:          "scredmanager stores secrets in the macOS Keychain and metadata in 0600 JSON.\nConsumers fetch on demand ($(scredmanager get …)) or never see the token at all\n(scredmanager curl, scredmanager run).",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON (schemaVersion 1)")

	root.AddCommand(
		newSetCmd(),
		newGetCmd(),
		newRmCmd(),
		newLsCmd(),
		newStatusCmd(),
		newCheckCmd(),
		newCurlCmd(),
		newRunCmd(),
		newImportCmd(),
		newExportCmd(),
		newServicesCmd(),
		newLoginCmd(),
		newLaunchdCmd(),
	)
	return root
}

// Execute runs the CLI and returns the process exit code. All error output
// passes through the redactor so secrets never reach stderr.
func Execute() int {
	err := newRootCmd().Execute()
	if err == nil {
		return exitOK
	}
	code := exitError
	if ec, ok := err.(*exitCodeError); ok {
		code = ec.code
	}
	if jsonOut {
		emitError(err)
	} else {
		fmt.Fprintln(os.Stderr, "scredmanager: "+safety.Redact(err.Error()))
	}
	return code
}
