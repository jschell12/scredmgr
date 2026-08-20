// Package cli implements the scredmgr command surface.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmgr/internal/safety"
	"github.com/jschell12/scredmgr/internal/store"
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
		Use:           "scredmgr",
		Short:         "Personal keychain-backed secrets broker",
		Long:          "scredmgr stores secrets in the macOS Keychain and metadata in 0600 JSON.\nConsumers fetch on demand ($(scredmgr get …)) or never see the token at all\n(scredmgr curl, scredmgr run).",
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
		newSSHCmd(),
		newSyncCmd(),
		newProvidersCmd(),
	)
	return root
}

// Execute runs the CLI and returns the process exit code. All error output
// passes through the redactor so secrets never reach stderr.
func Execute() int {
	// One-time copy of entries from the pre-rename "scredmanager" keychain
	// service. Best effort: a failure must not block normal commands.
	if err := store.MigrateLegacy(); err != nil {
		fmt.Fprintln(os.Stderr, "scredmgr: legacy keychain migration: "+safety.Redact(err.Error()))
	}
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
		fmt.Fprintln(os.Stderr, "scredmgr: "+safety.Redact(err.Error()))
	}
	return code
}
