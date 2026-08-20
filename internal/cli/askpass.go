package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/jschell12/scredmgr/internal/safety"
	"github.com/jschell12/scredmgr/internal/sshkey"
)

// MaybeAskpass handles the SSH_ASKPASS re-exec: when ssh-keygen/ssh-add call
// this binary back as their askpass helper, SCREDMGR_ASKPASS_ID carries the
// entry id (never the secret). The passphrase is read from the keychain and
// written to stdout — the pipe owned by the calling ssh tool.
//
// Returns (exitCode, true) when running as the helper, (0, false) otherwise.
func MaybeAskpass() (int, bool) {
	id := os.Getenv(sshkey.AskpassIDEnv)
	if id == "" {
		return 0, false
	}
	code := askpass(id, os.Stdout)
	return code, true
}

func askpass(id string, w io.Writer) int {
	secret, err := backend.Get(id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scredmgr askpass: "+safety.Redact(err.Error()))
		return exitError
	}
	safety.Track(secret)
	// ssh strips the trailing newline from askpass output.
	w.Write(secret)
	w.Write([]byte("\n"))
	return exitOK
}
