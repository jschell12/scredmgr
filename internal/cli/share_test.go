package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jschell12/scredmgr/internal/share"
	"github.com/jschell12/scredmgr/internal/store"
)

type recordedCall struct {
	name  string
	args  []string
	stdin []byte
}

// withShareSeams installs a fake runner and VPN detector, restoring on cleanup.
func withShareSeams(t *testing.T, vpn share.VPNInfo, response string, runErr error) *[]recordedCall {
	t.Helper()
	var calls []recordedCall
	prevRunner, prevVPN := shareRunner, detectVPN
	shareRunner = func(_ context.Context, name string, args []string, stdin []byte) ([]byte, error) {
		calls = append(calls, recordedCall{name: name, args: append([]string(nil), args...), stdin: append([]byte(nil), stdin...)})
		return []byte(response), runErr
	}
	detectVPN = func(context.Context, share.Runner) (share.VPNInfo, error) { return vpn, nil }
	t.Cleanup(func() { shareRunner, detectVPN = prevRunner, prevVPN })
	return &calls
}

func remoteEnvelope(t *testing.T, results ...shareResult) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"schemaVersion": 1, "ok": true,
		"data": map[string]any{"results": results},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestShareSendsSecretsOnStdinNeverArgv(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "GITHUB_TOKEN", "gh-secret", nil)
	calls := withShareSeams(t, share.VPNInfo{}, remoteEnvelope(t, shareResult{ID: "GITHUB_TOKEN", Action: "stored"}), nil)

	if err := runCLI(t, "share", "--to", "mac-mini", "--only", "GITHUB_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(*calls))
	}
	c := (*calls)[0]
	if c.name != "ssh" {
		t.Fatalf("ran %q, want ssh", c.name)
	}
	joined := strings.Join(c.args, " ")
	if strings.Contains(joined, "gh-secret") {
		t.Fatalf("secret leaked to argv: %v", c.args)
	}
	if !strings.Contains(joined, "mac-mini scredmgr receive --stdin --json") {
		t.Fatalf("unexpected ssh args: %v", c.args)
	}
	if !strings.Contains(joined, "BatchMode=yes") {
		t.Fatalf("BatchMode missing: %v", c.args)
	}
	p, err := share.Decode(bytes.NewReader(c.stdin))
	if err != nil {
		t.Fatalf("stdin is not a valid payload: %v", err)
	}
	if len(p.Entries) != 1 || p.Entries[0].ID != "GITHUB_TOKEN" {
		t.Fatalf("payload = %+v", p)
	}
}

func TestShareVPNFailsClosedNonTTY(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "GITHUB_TOKEN", "gh-secret", nil)
	calls := withShareSeams(t, share.VPNInfo{Active: true, Interface: "utun4"}, "", nil)

	err := runCLI(t, "share", "--to", "mac-mini", "--only", "GITHUB_TOKEN")
	if err == nil {
		t.Fatal("share proceeded with VPN active and no TTY")
	}
	if !strings.Contains(err.Error(), "utun4") {
		t.Fatalf("error lacks VPN detail: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatal("ssh invoked despite VPN refusal")
	}
}

func TestShareIgnoreVPNProceeds(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "GITHUB_TOKEN", "gh-secret", nil)
	calls := withShareSeams(t, share.VPNInfo{Active: true, Interface: "utun4"}, remoteEnvelope(t, shareResult{ID: "GITHUB_TOKEN", Action: "stored"}), nil)

	if err := runCLI(t, "share", "--to", "mac-mini", "--only", "GITHUB_TOKEN", "--ignore-vpn"); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("ssh calls = %d, want 1", len(*calls))
	}
}

func TestShareDryRunReadsNoSecrets(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "GITHUB_TOKEN", "gh-secret", nil)
	calls := withShareSeams(t, share.VPNInfo{}, "", nil)

	if err := runCLI(t, "share", "--to", "mac-mini", "--only", "GITHUB_TOKEN", "--dry-run"); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatal("dry-run invoked ssh")
	}
	if n := fake.GetCalls(); n != 0 {
		t.Fatalf("dry-run read %d secrets from the store", n)
	}
}

func TestShareSkipsSSHEntriesUnlessNamed(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "GITHUB_TOKEN", "gh-secret", nil)
	addLocal(t, fake, "ssh:mykey", "passphrase", &store.Meta{Kind: "ssh", Storage: store.StorageKeychain})
	calls := withShareSeams(t, share.VPNInfo{}, remoteEnvelope(t, shareResult{ID: "x", Action: "stored"}), nil)

	// Without --only naming it, the ssh entry is skipped. Use --only with
	// both ids: explicit naming sends the ssh entry too.
	if err := runCLI(t, "share", "--to", "m", "--only", "GITHUB_TOKEN,ssh:mykey"); err != nil {
		t.Fatal(err)
	}
	p, err := share.Decode(bytes.NewReader((*calls)[0].stdin))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 2 {
		t.Fatalf("explicit --only should include ssh entry: %+v", p.Entries)
	}
}

func TestShareRemotePartialFailureExitsNonZero(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "A", "va", nil)
	addLocal(t, fake, "B", "vb", nil)
	resp := remoteEnvelope(t,
		shareResult{ID: "A", Action: "stored"},
		shareResult{ID: "B", Action: "failed", Reason: "boom"},
	)
	// Remote exits 1 on partial failure; stdout still has the envelope.
	withShareSeams(t, share.VPNInfo{}, resp, errors.New("exit status 1"))

	err := runCLI(t, "share", "--to", "m", "--only", "A,B")
	if err == nil {
		t.Fatal("partial remote failure should exit non-zero")
	}
	if !strings.Contains(err.Error(), "1 item(s) failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestShareRemoteScredmgrMissing(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "A", "va", nil)
	withShareSeams(t, share.VPNInfo{}, "", errors.New("ssh: zsh:1: command not found: scredmgr"))

	err := runCLI(t, "share", "--to", "m", "--only", "A")
	if err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("expected friendly missing-binary error, got: %v", err)
	}
}

func TestShareRequiresToWhenNonTTY(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "A", "va", nil)
	withShareSeams(t, share.VPNInfo{}, "", nil)

	if err := runCLI(t, "share", "--only", "A"); err == nil {
		t.Fatal("share without --to and without TTY accepted")
	}
}
