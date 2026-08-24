package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jschell12/scredmgr/internal/share"
	"github.com/jschell12/scredmgr/internal/store"
)

func runCLIWithStdin(t *testing.T, stdin []byte, args ...string) error {
	t.Helper()
	root := newRootCmd()
	root.SetArgs(args)
	root.SetIn(bytes.NewReader(stdin))
	root.SetOut(new(bytes.Buffer))
	return root.Execute()
}

func encodePayload(t *testing.T, entries ...share.Entry) []byte {
	t.Helper()
	p := &share.Payload{Version: share.Version, From: "macbook", SentAt: "2026-08-24T12:00:00Z", Entries: entries}
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestReceiveStoresEntry(t *testing.T) {
	fake, _ := withTestEnv(t)
	payload := encodePayload(t, share.Entry{ID: "jira", SecretB64: b64("tok"), EnvVar: "JIRA_TOKEN", Label: "Jira"})
	if err := runCLIWithStdin(t, payload, "receive", "--stdin"); err != nil {
		t.Fatal(err)
	}
	got, err := fake.Get("jira")
	if err != nil || string(got) != "tok" {
		t.Fatalf("secret = %q, %v", got, err)
	}
	m, err := store.ReadMeta("jira")
	if err != nil {
		t.Fatal(err)
	}
	if m.SharedFrom != "macbook" || m.SharedAt == "" || m.EnvVar != "JIRA_TOKEN" || m.Label != "Jira" {
		t.Fatalf("meta = %+v", m)
	}
	if m.Storage != store.PlatformStorage() {
		t.Fatalf("storage = %q, want %q", m.Storage, store.PlatformStorage())
	}
}

func TestReceiveSkipsExistingUnlessOverwrite(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "jira", "old", nil)

	payload := encodePayload(t, share.Entry{ID: "jira", SecretB64: b64("new")})
	if err := runCLIWithStdin(t, payload, "receive", "--stdin"); err != nil {
		t.Fatal(err)
	}
	if got, _ := fake.Get("jira"); string(got) != "old" {
		t.Fatalf("existing entry overwritten without --overwrite: %q", got)
	}
	if err := runCLIWithStdin(t, payload, "receive", "--stdin", "--overwrite"); err != nil {
		t.Fatal(err)
	}
	if got, _ := fake.Get("jira"); string(got) != "new" {
		t.Fatalf("entry not overwritten with --overwrite: %q", got)
	}
}

func TestReceiveRejectsBadIDStoresSiblings(t *testing.T) {
	fake, _ := withTestEnv(t)
	payload := encodePayload(t,
		share.Entry{ID: "../evil", SecretB64: b64("x")},
		share.Entry{ID: "good", SecretB64: b64("y")},
	)
	if err := runCLIWithStdin(t, payload, "receive", "--stdin"); err != nil {
		t.Fatal(err) // bad id is "skipped", not "failed"
	}
	if _, err := fake.Get("../evil"); err == nil {
		t.Fatal("path-traversal id stored")
	}
	if got, _ := fake.Get("good"); string(got) != "y" {
		t.Fatalf("sibling not stored: %q", got)
	}
}

func TestReceiveRequiresStdinFlag(t *testing.T) {
	withTestEnv(t)
	if err := runCLIWithStdin(t, []byte("{}"), "receive"); err == nil {
		t.Fatal("receive without --stdin accepted")
	}
}

func TestReceiveRollbackOnMetaFailure(t *testing.T) {
	fake, home := withTestEnv(t)
	// Make the home dir read-only so WriteMeta fails after backend.Set.
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(home, 0o700) })

	payload := encodePayload(t, share.Entry{ID: "jira", SecretB64: b64("tok")})
	if err := runCLIWithStdin(t, payload, "receive", "--stdin"); err == nil {
		t.Fatal("expected failure exit")
	}
	if _, err := fake.Get("jira"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("orphaned secret left in backend: %v", err)
	}
}

func TestReceiveLockedKeychainSpools(t *testing.T) {
	fake, home := withTestEnv(t)
	errLocked := errors.New("keychain locked")
	fake.FailSet = errLocked
	prev := isLockedKeychainErr
	isLockedKeychainErr = func(err error) bool { return errors.Is(err, errLocked) }
	t.Cleanup(func() { isLockedKeychainErr = prev })

	payload := encodePayload(t,
		share.Entry{ID: "a", SecretB64: b64("va")},
		share.Entry{ID: "b", SecretB64: b64("vb")},
	)
	if err := runCLIWithStdin(t, payload, "receive", "--stdin"); err != nil {
		t.Fatalf("spooled receive should exit 0: %v", err)
	}
	// Nothing stored, blob exists.
	if _, err := fake.Get("a"); err == nil {
		t.Fatal("entry stored despite locked keychain")
	}
	blobs, err := filepath.Glob(filepath.Join(home, "inbox", "*.enc"))
	if err != nil || len(blobs) != 1 {
		t.Fatalf("blobs = %v, %v; want exactly 1", blobs, err)
	}
	// Blob at rest must not contain the plaintext secrets.
	raw, _ := os.ReadFile(blobs[0])
	if bytes.Contains(raw, []byte("va")) || bytes.Contains(raw, []byte(b64("va"))) {
		t.Fatal("spooled blob contains plaintext")
	}

	// Unlock and drain: both entries land, blob is deleted.
	fake.FailSet = nil
	if err := runCLI(t, "inbox", "import"); err != nil {
		t.Fatal(err)
	}
	if got, _ := fake.Get("a"); string(got) != "va" {
		t.Fatalf("a = %q", got)
	}
	if got, _ := fake.Get("b"); string(got) != "vb" {
		t.Fatalf("b = %q", got)
	}
	m, err := store.ReadMeta("a")
	if err != nil || m.SharedFrom != "macbook" {
		t.Fatalf("meta after import: %+v, %v", m, err)
	}
	blobs, _ = filepath.Glob(filepath.Join(home, "inbox", "*.enc"))
	if len(blobs) != 0 {
		t.Fatalf("blob not drained: %v", blobs)
	}
}

func TestInboxImportKeepsBlobWhenStillLocked(t *testing.T) {
	fake, home := withTestEnv(t)
	errLocked := errors.New("keychain locked")
	fake.FailSet = errLocked
	prev := isLockedKeychainErr
	isLockedKeychainErr = func(err error) bool { return errors.Is(err, errLocked) }
	t.Cleanup(func() { isLockedKeychainErr = prev })

	payload := encodePayload(t, share.Entry{ID: "a", SecretB64: b64("va")})
	if err := runCLIWithStdin(t, payload, "receive", "--stdin"); err != nil {
		t.Fatal(err)
	}
	// Import while still locked: blob must survive.
	if err := runCLI(t, "inbox", "import"); err != nil {
		t.Fatal(err)
	}
	blobs, _ := filepath.Glob(filepath.Join(home, "inbox", "*.enc"))
	if len(blobs) != 1 {
		t.Fatalf("blob lost while keychain locked: %v", blobs)
	}
}
