package share

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/jschell12/scredmgr/internal/safety"
)

// ExecCapture runs a command with the payload on stdin and returns stdout
// even when the command exits non-zero — a remote `scredmgr receive --json`
// reports per-entry failures in its envelope AND exits 1, and the sender
// needs both. stderr is redacted into the returned error. Secrets ride only
// on stdin, never argv or env.
func ExecCapture(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	if _, err := exec.LookPath(name); err != nil {
		return nil, fmt.Errorf("%s not found in PATH", name)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s %s: %w: %s", name,
			safety.Redact(strings.Join(args, " ")), err,
			safety.Redact(strings.TrimSpace(errBuf.String())))
	}
	return out.Bytes(), nil
}
