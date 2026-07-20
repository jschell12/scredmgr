package loginflow

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Clipboard abstracts the system clipboard so the watch loop is testable.
type Clipboard interface {
	Read() (string, error)
	Clear() error
}

// SystemClipboard uses pbpaste/pbcopy. The secret moves via the child's
// stdout/stdin pipes — never argv.
type SystemClipboard struct{}

func (SystemClipboard) Read() (string, error) {
	out, err := exec.Command("pbpaste").Output()
	if err != nil {
		return "", fmt.Errorf("pbpaste: %w", err)
	}
	return string(out), nil
}

func (SystemClipboard) Clear() error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader("")
	return cmd.Run()
}

// WaitForToken polls the clipboard until a value appears that (a) differs
// from whatever was on the clipboard when the wait started, and (b) matches
// pattern (if non-nil). Requiring a change prevents grabbing a stale value
// that predates the mint.
func WaitForToken(ctx context.Context, clip Clipboard, pattern *regexp.Regexp, interval time.Duration) (string, error) {
	initial, err := clip.Read()
	if err != nil {
		return "", err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("clipboard watch: %w", ctx.Err())
		case <-ticker.C:
			cur, err := clip.Read()
			if err != nil {
				return "", err
			}
			cur = strings.TrimSpace(cur)
			if cur == "" || cur == strings.TrimSpace(initial) {
				continue
			}
			if pattern != nil && !pattern.MatchString(cur) {
				continue
			}
			return cur, nil
		}
	}
}
