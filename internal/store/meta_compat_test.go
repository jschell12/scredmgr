package store

import (
	"os"
	"path/filepath"
	"testing"
)

// Legacy metadata files (written before the ssh/provider fields existed) must
// read cleanly with zero values for the new fields.
func TestReadMetaLegacyFormat(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SCREDMGR_HOME", dir)
	legacy := `{"label":"old","envVar":"OLD_TOKEN","createdAt":"2026-01-01T00:00:00Z","_storage":"keychain"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "old.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := ReadMeta("old")
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != "" || m.Fingerprint != "" || m.KeyPath != "" || m.SyncedFrom != "" {
		t.Fatalf("new fields not zero on legacy meta: %+v", m)
	}
	if m.Label != "old" || m.EnvVar != "OLD_TOKEN" || m.Storage != StorageKeychain {
		t.Fatalf("legacy fields mangled: %+v", m)
	}
}

func TestMetaRoundTripNewFields(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SCREDMGR_HOME", dir)
	in := &Meta{
		Kind:        "ssh",
		Fingerprint: "SHA256:abc",
		KeyPath:     "/home/x/.ssh/id_x",
		PublicKey:   "ssh-ed25519 AAAA x@host",
		SyncedFrom:  "homelab-vault",
		SyncedAt:    "2026-08-02T00:00:00Z",
		Storage:     StorageNone,
	}
	if err := WriteMeta("ssh:x", in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadMeta("ssh:x")
	if err != nil {
		t.Fatal(err)
	}
	if *out != *in {
		t.Fatalf("round trip mismatch:\n in: %+v\nout: %+v", in, out)
	}
}
