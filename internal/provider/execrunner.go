package provider

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/jschell12/scredmgr/internal/safety"
)

// Runner executes an external CLI (op, aws, lpass). Secret values may travel
// via stdin or arrive on stdout — never on argv. Implementations and callers
// must uphold that invariant; tests assert it.
type Runner func(ctx context.Context, name string, args []string, stdin []byte) (stdout []byte, err error)

// ExecRunner is the production Runner. stderr is redacted before it is
// wrapped into the returned error.
func ExecRunner(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	if _, err := exec.LookPath(name); err != nil {
		return nil, fmt.Errorf("%s CLI not found in PATH (install it to use this provider)", name)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, redactArgs(args), err,
			safety.Redact(strings.TrimSpace(errBuf.String())))
	}
	return out.Bytes(), nil
}

func redactArgs(args []string) string {
	return safety.Redact(strings.Join(args, " "))
}
