package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SCREDMANAGER_HOME", dir)
	return dir
}

func TestWriteReadMetaRoundTrip(t *testing.T) {
	withTempHome(t)
	m := &Meta{Label: "Jira", EnvVar: "JIRA_TOKEN", CreatedAt: "2026-01-01T00:00:00Z", Storage: StorageKeychain}
	if err := WriteMeta("jira", m); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMeta("jira")
	if err != nil {
		t.Fatal(err)
	}
	if got.EnvVar != "JIRA_TOKEN" || got.Label != "Jira" || got.Storage != StorageKeychain {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestWriteMetaMode0600(t *testing.T) {
	dir := withTempHome(t)
	if err := WriteMeta("x", &Meta{Storage: StorageKeychain}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "x.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestWriteMetaAtomicNoPartialFiles(t *testing.T) {
	dir := withTempHome(t)
	// Simulate repeated writes; the visible file must always be complete JSON
	// and no temp files may linger (a kill -9 mid-write only ever leaves a
	// dot-prefixed temp file, never a corrupt x.json).
	for i := 0; i < 20; i++ {
		if err := WriteMeta("x", &Meta{Label: strings.Repeat("a", 4096), Storage: StorageKeychain}); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadMeta("x"); err != nil {
			t.Fatalf("iteration %d: visible file unreadable: %v", i, err)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
}

func TestListIDsExcludesManifest(t *testing.T) {
	withTempHome(t)
	_ = WriteMeta("a", &Meta{Storage: StorageKeychain})
	_ = WriteMeta("b", &Meta{Storage: StorageKeychain})
	dir, _ := HomeDir()
	_ = os.WriteFile(filepath.Join(dir, "services.json"), []byte("[]"), 0o600)
	ids, err := ListIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("ids = %v, want [a b]", ids)
	}
}

func TestValidateID(t *testing.T) {
	for _, ok := range []string{"jira", "custom:JIRA_TOKEN", "a-b_c.d"} {
		if err := ValidateID(ok); err != nil {
			t.Errorf("ValidateID(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "../etc/passwd", "a/b", "a b"} {
		if err := ValidateID(bad); err == nil {
			t.Errorf("ValidateID(%q) = nil, want error", bad)
		}
	}
}

func TestExpiresIn(t *testing.T) {
	now := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	m := &Meta{ExpiresAt: "2026-07-25T00:00:00Z"}
	d, ok := m.ExpiresIn(now)
	if !ok || d != 5*24*time.Hour {
		t.Fatalf("ExpiresIn = %v, %v", d, ok)
	}
	if _, ok := (&Meta{}).ExpiresIn(now); ok {
		t.Fatal("no expiry should return ok=false")
	}
}
