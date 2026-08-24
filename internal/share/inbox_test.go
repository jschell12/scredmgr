package share

import (
	"os"
	"path/filepath"
	"testing"
)

func withInboxEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SCREDMGR_HOME", dir)
	return dir
}

func testPayload() *Payload {
	return &Payload{
		Version: Version,
		From:    "macbook",
		SentAt:  "2026-08-24T12:00:00Z",
		Entries: []Entry{{ID: "jira", SecretB64: "c2VjcmV0"}},
	}
}

func TestInboxSpoolRoundTrip(t *testing.T) {
	home := withInboxEnv(t)
	path, err := Spool(testPayload())
	if err != nil {
		t.Fatal(err)
	}

	keyInfo, err := os.Stat(filepath.Join(home, "inbox.key"))
	if err != nil {
		t.Fatalf("inbox.key missing: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("inbox.key perm = %o, want 600", perm)
	}
	blobInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := blobInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("blob perm = %o, want 600", perm)
	}

	infos, err := ListSpooled()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].From != "macbook" || len(infos[0].IDs) != 1 || infos[0].IDs[0] != "jira" {
		t.Fatalf("ListSpooled = %+v", infos)
	}

	p, err := OpenSpooled(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Entries[0].SecretB64 != "c2VjcmV0" {
		t.Fatalf("payload = %+v", p)
	}

	if err := RemoveSpooled(path); err != nil {
		t.Fatal(err)
	}
	infos, _ = ListSpooled()
	if len(infos) != 0 {
		t.Fatalf("blob survived removal: %+v", infos)
	}
}

func TestInboxTamperedBlobRejected(t *testing.T) {
	withInboxEnv(t)
	path, err := Spool(testPayload())
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := os.ReadFile(path)
	blob[len(blob)-1] ^= 0xff
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSpooled(path); err == nil {
		t.Fatal("tampered blob decrypted")
	}
}

func TestInboxRenamedBlobRejected(t *testing.T) {
	withInboxEnv(t)
	path, err := Spool(testPayload())
	if err != nil {
		t.Fatal(err)
	}
	// Filename is GCM AAD: renaming a blob must break decryption.
	renamed := filepath.Join(filepath.Dir(path), "9999999999999999999-deadbeef.enc")
	if err := os.Rename(path, renamed); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSpooled(renamed); err == nil {
		t.Fatal("renamed blob decrypted despite AAD binding")
	}
}
