package sshkey

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFingerprint(t *testing.T) {
	out := "256 SHA256:AbCdEf1234567890abcdef1234567890AbCdEf12345 me@host (ED25519)\n"
	fp, err := parseFingerprint(out)
	if err != nil {
		t.Fatal(err)
	}
	if fp != "SHA256:AbCdEf1234567890abcdef1234567890AbCdEf12345" {
		t.Fatalf("got %q", fp)
	}
	if _, err := parseFingerprint("garbage"); err == nil {
		t.Fatal("expected error for garbage output")
	}
}

func TestCheckVersionOutput(t *testing.T) {
	cases := []struct {
		out string
		ok  bool
	}{
		{"OpenSSH_9.6p1, LibreSSL 3.3.6", true},
		{"OpenSSH_8.4p1", true},
		{"OpenSSH_8.3p1", false},
		{"OpenSSH_7.9p1", false},
		{"OpenSSH_10.0p1", true},
		{"not ssh at all", false},
	}
	for _, c := range cases {
		err := checkVersionOutput(c.out)
		if (err == nil) != c.ok {
			t.Errorf("%q: got err=%v, want ok=%v", c.out, err, c.ok)
		}
	}
}

func TestRandomPassphrase(t *testing.T) {
	a, err := RandomPassphrase(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomPassphrase(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) < 40 { // 32 bytes base64url ~ 43 chars
		t.Fatalf("passphrase too short: %d", len(a))
	}
	if string(a) == string(b) {
		t.Fatal("two passphrases identical")
	}
}

func TestAskpassEnv(t *testing.T) {
	env, err := AskpassEnv("ssh:test")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{"SSH_ASKPASS=", "SSH_ASKPASS_REQUIRE=force", AskpassIDEnv + "=ssh:test"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
}

// TestKeygenNoPassphrase runs the real ssh-keygen (present on every macOS/Linux
// dev box) against a temp dir.
func TestKeygenNoPassphrase(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_test")
	res, err := Keygen(context.Background(), KeygenOptions{
		Type:    "ed25519",
		KeyPath: keyPath,
		Comment: "test@scredmgr",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("private key missing: %v", err)
	}
	if _, err := os.Stat(keyPath + ".pub"); err != nil {
		t.Fatalf("public key missing: %v", err)
	}
	if !strings.HasPrefix(res.Fingerprint, "SHA256:") {
		t.Fatalf("bad fingerprint %q", res.Fingerprint)
	}
	if !strings.HasPrefix(res.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("bad public key %q", res.PublicKey)
	}
	if !strings.Contains(res.PublicKey, "test@scredmgr") {
		t.Fatalf("comment missing from %q", res.PublicKey)
	}
}
