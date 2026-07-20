// Package safety holds security-critical helpers: TTY detection, masked
// prompts, and output redaction.
package safety

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// IsTTY reports whether f is attached to a terminal.
func IsTTY(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// ReadMasked prompts on the controlling terminal and reads a secret without
// echo. It fails if no TTY is available (use stdin modes in that case).
func ReadMasked(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("no TTY available for masked prompt; use --from-stdin")
	}
	defer tty.Close()

	fmt.Fprint(tty, prompt)
	secret, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return nil, err
	}
	return secret, nil
}
