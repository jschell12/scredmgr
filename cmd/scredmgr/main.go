package main

import (
	"os"

	"github.com/jschell12/scredmgr/internal/cli"
)

func main() {
	// SSH_ASKPASS re-exec: ssh-keygen/ssh-add call this binary back to fetch
	// a key passphrase from the keychain (see internal/cli/askpass.go).
	if code, ok := cli.MaybeAskpass(); ok {
		os.Exit(code)
	}
	os.Exit(cli.Execute())
}
