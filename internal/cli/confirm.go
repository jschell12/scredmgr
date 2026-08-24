package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// promptTTY prints prompt on the controlling terminal and reads one echoed
// line from it. Used for non-secret choices (host/entry pickers, y/N).
func promptTTY(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("no TTY available for interactive prompt")
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// confirmTTY asks a yes/no question on the controlling terminal.
// Anything but "y"/"yes" (case-insensitive) is no.
func confirmTTY(prompt string) (bool, error) {
	line, err := promptTTY(prompt)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(line) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
