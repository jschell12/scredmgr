package store

import (
	"errors"
	"strings"
	"testing"
)

func TestMigrateHappyPath(t *testing.T) {
	withTempHome(t)
	fake := NewFakeStore()
	if err := WriteMeta("jira", &Meta{EnvVar: "JIRA_TOKEN", Token: "s3cret", Storage: StorageFile}); err != nil {
		t.Fatal(err)
	}

	m, err := LoadAndMigrate("jira", fake)
	if err != nil {
		t.Fatal(err)
	}
	if m.Token != "" || m.Storage != StorageKeychain {
		t.Fatalf("not migrated: %+v", m)
	}
	// Plaintext stripped on disk.
	onDisk, _ := ReadMeta("jira")
	if onDisk.Token != "" || onDisk.Storage != StorageKeychain {
		t.Fatalf("disk not migrated: %+v", onDisk)
	}
	// Secret is in the store.
	got, err := fake.Get("jira")
	if err != nil || string(got) != "s3cret" {
		t.Fatalf("keychain copy wrong: %q, %v", got, err)
	}
}

func TestMigratePreservesPlaintextOnStoreFailure(t *testing.T) {
	withTempHome(t)
	fake := NewFakeStore()
	fake.FailSet = errors.New("keychain locked")
	if err := WriteMeta("jira", &Meta{Token: "s3cret", Storage: StorageFile}); err != nil {
		t.Fatal(err)
	}

	_, err := LoadAndMigrate("jira", fake)
	if err == nil || !strings.Contains(err.Error(), "plaintext preserved") {
		t.Fatalf("err = %v, want plaintext-preserved failure", err)
	}
	// Never strip before a verified round-trip.
	onDisk, _ := ReadMeta("jira")
	if onDisk.Token != "s3cret" {
		t.Fatalf("plaintext lost: %+v", onDisk)
	}
	// GetSecret still serves the preserved plaintext.
	got, err := GetSecret("jira", fake)
	if err != nil || string(got) != "s3cret" {
		t.Fatalf("GetSecret = %q, %v; want preserved plaintext", got, err)
	}
}

func TestMigrateNoopWhenAlreadyKeychain(t *testing.T) {
	withTempHome(t)
	fake := NewFakeStore()
	_ = fake.Set("jira", []byte("k"))
	if err := WriteMeta("jira", &Meta{Storage: StorageKeychain}); err != nil {
		t.Fatal(err)
	}
	m, err := LoadAndMigrate("jira", fake)
	if err != nil {
		t.Fatal(err)
	}
	if m.Storage != StorageKeychain {
		t.Fatalf("storage = %s", m.Storage)
	}
	got, err := GetSecret("jira", fake)
	if err != nil || string(got) != "k" {
		t.Fatalf("GetSecret = %q, %v", got, err)
	}
}
