package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func newTestFileStore(t *testing.T) *FileStore {
	t.Helper()
	t.Setenv("SCREDMGR_HOME", t.TempDir())
	return &FileStore{}
}

func TestFileStoreRoundTrip(t *testing.T) {
	s := newTestFileStore(t)
	secret := []byte("s3cret-value")
	if err := s.Set("jira", secret); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get("jira")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round trip mismatch: got %q", got)
	}
	ok, err := s.Exists("jira")
	if err != nil || !ok {
		t.Fatalf("Exists = %v, %v; want true, nil", ok, err)
	}
}

func TestFileStoreNotFound(t *testing.T) {
	s := newTestFileStore(t)
	if _, err := s.Get("missing"); err != ErrNotFound {
		t.Fatalf("Get missing: %v, want ErrNotFound", err)
	}
	if err := s.Delete("missing"); err != ErrNotFound {
		t.Fatalf("Delete missing: %v, want ErrNotFound", err)
	}
	if ok, _ := s.Exists("missing"); ok {
		t.Fatal("Exists(missing) = true")
	}
}

func TestFileStoreOverwriteAndDelete(t *testing.T) {
	s := newTestFileStore(t)
	if err := s.Set("x", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("x", []byte("two")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("x")
	if err != nil || string(got) != "two" {
		t.Fatalf("Get after overwrite = %q, %v", got, err)
	}
	if err := s.Delete("x"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("x"); err != ErrNotFound {
		t.Fatalf("Get after delete: %v, want ErrNotFound", err)
	}
}

func TestFileStorePermsAndLayout(t *testing.T) {
	s := newTestFileStore(t)
	if err := s.Set("work/jira", []byte("v")); err != nil {
		t.Fatal(err)
	}
	home := os.Getenv("SCREDMGR_HOME")

	keyInfo, err := os.Stat(filepath.Join(home, "store.key"))
	if err != nil {
		t.Fatalf("store.key missing: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("store.key perm = %o, want 600", perm)
	}
	encInfo, err := os.Stat(filepath.Join(home, ".secrets", "work", "jira.enc"))
	if err != nil {
		t.Fatalf("ciphertext missing: %v", err)
	}
	if perm := encInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("ciphertext perm = %o, want 600", perm)
	}

	// Ciphertext at rest must not contain the plaintext.
	blob, _ := os.ReadFile(filepath.Join(home, ".secrets", "work", "jira.enc"))
	if bytes.Contains(blob, []byte("v")) && len(blob) < 16 {
		t.Fatal("ciphertext suspiciously small")
	}

	// .secrets is a dot-dir: ListIDs must not see ciphertext files.
	ids, err := ListIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("ListIDs sees ciphertext entries: %v", ids)
	}

	// Delete prunes the empty namespace dir under .secrets.
	if err := s.Delete("work/jira"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".secrets", "work")); !os.IsNotExist(err) {
		t.Fatalf("namespace dir not pruned: %v", err)
	}
}

func TestFileStoreTamperAndSwapRejected(t *testing.T) {
	s := newTestFileStore(t)
	if err := s.Set("a", []byte("secret-a")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("b", []byte("secret-b")); err != nil {
		t.Fatal(err)
	}
	home := os.Getenv("SCREDMGR_HOME")
	aPath := filepath.Join(home, ".secrets", "a.enc")
	bPath := filepath.Join(home, ".secrets", "b.enc")

	// Swapping ciphertext files between ids must fail (id is GCM AAD).
	aBlob, _ := os.ReadFile(aPath)
	if err := os.WriteFile(bPath, aBlob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("b"); err == nil {
		t.Fatal("swapped ciphertext decrypted under wrong id")
	}

	// Bit-flip tamper must fail.
	aBlob[len(aBlob)-1] ^= 0xff
	if err := os.WriteFile(aPath, aBlob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("a"); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
}

func TestFileStoreRejectsBadID(t *testing.T) {
	s := newTestFileStore(t)
	if err := s.Set("../evil", []byte("x")); err == nil {
		t.Fatal("Set accepted path-traversal id")
	}
	if _, err := s.Get("../evil"); err == nil {
		t.Fatal("Get accepted path-traversal id")
	}
}
