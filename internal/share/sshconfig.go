package share

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DefaultSSHConfigPath returns ~/.ssh/config.
func DefaultSSHConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "config"), nil
}

// ParseSSHConfigHosts collects concrete Host aliases from an ssh_config.
// Wildcard patterns (*, ?), negations (!), and Match blocks are skipped.
// Include directives are not followed (documented v1 limitation).
func ParseSSHConfigHosts(r io.Reader) []string {
	var hosts []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "Host") {
			continue
		}
		for _, alias := range fields[1:] {
			if strings.ContainsAny(alias, "*?") || strings.HasPrefix(alias, "!") {
				continue
			}
			if !seen[alias] {
				seen[alias] = true
				hosts = append(hosts, alias)
			}
		}
	}
	return hosts
}

// ProbeHost reports whether host answers a non-interactive ssh connection
// within a short timeout. Used only to annotate the host picker.
func ProbeHost(ctx context.Context, run Runner, host string) bool {
	_, err := run(ctx, "ssh",
		[]string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=2", host, "exit"}, nil)
	return err == nil
}
