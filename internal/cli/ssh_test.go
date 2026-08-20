package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jschell12/scredmgr/internal/store"
)

func withTestEnv(t *testing.T) (*store.FakeStore, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SCREDMGR_HOME", dir)
	fake := store.NewFakeStore()
	prev := backend
	SetStore(fake)
	t.Cleanup(func() { SetStore(prev) })
	return fake, dir
}

func runCLI(t *testing.T, args ...string) error {
	t.Helper()
	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(new(bytes.Buffer))
	return root.Execute()
}

func TestAskpassWritesSecret(t *testing.T) {
	fake, _ := withTestEnv(t)
	if err := fake.Set("ssh:demo", []byte("hunter2")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := askpass("ssh:demo", &out); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if out.String() != "hunter2\n" {
		t.Fatalf("got %q", out.String())
	}
	if code := askpass("ssh:missing", &out); code != exitError {
		t.Fatalf("missing entry: exit %d, want %d", code, exitError)
	}
}

func TestSSHKeygenNoPassphrase(t *testing.T) {
	_, home := withTestEnv(t)
	keyPath := filepath.Join(t.TempDir(), "id_t1")
	if err := runCLI(t, "ssh", "keygen", "t1", "--no-passphrase", "--file", keyPath, "--expiry-days", "30"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key missing: %v", err)
	}
	m, err := store.ReadMeta("ssh:t1")
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != "ssh" || m.Storage != store.StorageNone || m.KeyPath != keyPath {
		t.Fatalf("bad meta: %+v", m)
	}
	if !strings.HasPrefix(m.Fingerprint, "SHA256:") {
		t.Fatalf("bad fingerprint %q", m.Fingerprint)
	}
	if m.ExpiresAt == "" {
		t.Fatal("expiry not set")
	}
	// meta file lives in the temp home
	if _, err := os.Stat(filepath.Join(home, "ssh:t1.json")); err != nil {
		t.Fatalf("meta file: %v", err)
	}
	// second run without --force refuses
	if err := runCLI(t, "ssh", "keygen", "t1", "--no-passphrase", "--file", keyPath); err == nil {
		t.Fatal("expected refusal without --force")
	}
}

func TestSSHKeygenRequiresExactlyOnePassphraseMode(t *testing.T) {
	withTestEnv(t)
	if err := runCLI(t, "ssh", "keygen", "t2", "--file", filepath.Join(t.TempDir(), "k")); err == nil {
		t.Fatal("expected error with no passphrase mode")
	}
	if err := runCLI(t, "ssh", "keygen", "t2", "--no-passphrase", "--passphrase-random", "--file", filepath.Join(t.TempDir(), "k")); err == nil {
		t.Fatal("expected error with two passphrase modes")
	}
}

func TestRmFiles(t *testing.T) {
	fake, _ := withTestEnv(t)
	keyPath := filepath.Join(t.TempDir(), "id_t3")
	if err := runCLI(t, "ssh", "keygen", "t3", "--no-passphrase", "--file", keyPath); err != nil {
		t.Fatal(err)
	}
	if err := runCLI(t, "rm", "ssh:t3", "--files"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{keyPath, keyPath + ".pub"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s not removed", p)
		}
	}
	if _, err := store.ReadMeta("ssh:t3"); !os.IsNotExist(err) {
		t.Fatalf("meta not removed: %v", err)
	}
	_ = fake
}

func TestRmFilesRejectsNonSSH(t *testing.T) {
	fake, _ := withTestEnv(t)
	if err := fake.Set("plain", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteMeta("plain", &store.Meta{Storage: store.StorageKeychain}); err != nil {
		t.Fatal(err)
	}
	if err := runCLI(t, "rm", "plain", "--files"); err == nil {
		t.Fatal("expected --files to reject non-ssh entry")
	}
}

func TestSSHShow(t *testing.T) {
	withTestEnv(t)
	keyPath := filepath.Join(t.TempDir(), "id_t4")
	if err := runCLI(t, "ssh", "keygen", "t4", "--no-passphrase", "--file", keyPath); err != nil {
		t.Fatal(err)
	}
	if err := runCLI(t, "ssh", "show", "t4"); err != nil {
		t.Fatal(err)
	}
	if err := runCLI(t, "ssh", "show", "nope"); err == nil {
		t.Fatal("expected error for missing entry")
	}
}
