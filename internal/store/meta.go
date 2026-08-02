package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Storage provenance markers for Meta.Storage.
const (
	StorageKeychain = "keychain"
	StorageFile     = "file"
	StorageMixed    = "mixed"
	StorageNone     = "none" // no keychain item (e.g. ssh key without a stored passphrase)
)

// Meta is the non-secret metadata for one entry, stored as
// ~/.scredmanager/<id>.json with mode 0600.
type Meta struct {
	Label     string `json:"label,omitempty"`
	EnvVar    string `json:"envVar,omitempty"`
	CreatedAt string `json:"createdAt,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	Notes     string `json:"notes,omitempty"`

	// Kind marks the entry type: "" (token, the default) or "ssh".
	Kind string `json:"kind,omitempty"`
	// Fingerprint is the SHA256 fingerprint of an ssh key entry.
	Fingerprint string `json:"fingerprint,omitempty"`
	// KeyPath is the private key file path of an ssh key entry. The key file
	// itself never enters the keychain; only the passphrase does.
	KeyPath string `json:"keyPath,omitempty"`
	// PublicKey is the full public key line of an ssh key entry (safe to show).
	PublicKey string `json:"publicKey,omitempty"`

	// SyncedFrom / SyncedAt record pull provenance from a remote provider.
	SyncedFrom string `json:"syncedFrom,omitempty"`
	SyncedAt   string `json:"syncedAt,omitempty"`

	// Token holds a plaintext secret ONLY during the import-then-migrate
	// window (Storage == "file" or "mixed"). It is stripped after a verified
	// keychain round-trip. See migrate.go.
	Token string `json:"token,omitempty"`

	// Storage marks where the authoritative copy of the secret lives:
	// "keychain", "file", or "mixed".
	Storage string `json:"_storage"`
}

// HomeDir returns the scredmanager data directory, creating it 0700 if needed.
// SCREDMANAGER_HOME overrides the default ~/.scredmanager (used in tests).
func HomeDir() (string, error) {
	dir := os.Getenv("SCREDMANAGER_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".scredmanager")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func metaPath(id string) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	dir, err := HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, id+".json"), nil
}

// ReadMeta loads metadata for id. Returns os.ErrNotExist if absent.
func ReadMeta(id string) (*Meta, error) {
	p, err := metaPath(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if m.Storage == "" {
		m.Storage = StorageKeychain
	}
	return &m, nil
}

// WriteMeta persists metadata for id atomically with mode 0600:
// write to a temp file in the same directory, fsync, then rename.
func WriteMeta(id string, m *Meta) error {
	p, err := metaPath(id)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(p)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(p)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

// DeleteMeta removes the metadata file for id. Missing files are not an error.
func DeleteMeta(id string) error {
	p, err := metaPath(id)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ListIDs returns all entry ids (metadata files), excluding the manifest and
// provider config.
func ListIDs() ([]string, error) {
	dir, err := HomeDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if id == "services" || id == "providers" {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// ExpiresIn returns the time until expiry, or false if no expiry is set.
func (m *Meta) ExpiresIn(now time.Time) (time.Duration, bool) {
	if m.ExpiresAt == "" {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil {
		return 0, false
	}
	return t.Sub(now), true
}
