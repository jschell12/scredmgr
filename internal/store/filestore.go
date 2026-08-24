package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	storeKeyFile  = "store.key"
	secretsSubdir = ".secrets" // dot-dir: invisible to ListIDs
)

// FileStore stores secrets as AES-256-GCM ciphertext files under
// <HomeDir>/.secrets/<id>.enc, keyed by a machine-local random key at
// <HomeDir>/store.key (0600, created on demand). It is the platform backend
// on non-darwin systems, where no OS keychain integration exists yet.
//
// Threat model: protects secrets at rest against backup/copy leakage of the
// data directory contents. It does NOT protect against an attacker with
// access to the same user account (who can read the key file) — same as any
// file-based store without OS-level key escrow.
type FileStore struct{}

// NewFileStore returns the encrypted-file-backed store.
func NewFileStore() Store {
	return &FileStore{}
}

// loadOrCreateKeyFile returns the 32-byte AES key at path, generating it
// with O_EXCL semantics on first use so concurrent creators cannot clobber
// each other.
func loadOrCreateKeyFile(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, fmt.Errorf("%s: expected 32-byte key, got %d bytes", path, len(key))
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			// Lost a creation race; use the winner's key.
			return loadOrCreateKeyFile(path)
		}
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, err
	}
	return key, nil
}

func (s *FileStore) gcm() (cipher.AEAD, error) {
	dir, err := HomeDir()
	if err != nil {
		return nil, err
	}
	key, err := loadOrCreateKeyFile(filepath.Join(dir, storeKeyFile))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func secretPath(id string) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	dir, err := HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, secretsSubdir, id+".enc"), nil
}

func (s *FileStore) Set(id string, secret []byte) error {
	p, err := secretPath(id)
	if err != nil {
		return err
	}
	aead, err := s.gcm()
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	// The id as additional data binds the blob to its entry: a ciphertext
	// file copied over another id's path fails to open.
	blob := append(nonce, aead.Seal(nil, nonce, secret, []byte(id))...)

	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
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
	if _, err := tmp.Write(blob); err != nil {
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

func (s *FileStore) Get(id string) ([]byte, error) {
	p, err := secretPath(id)
	if err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	aead, err := s.gcm()
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize() {
		return nil, fmt.Errorf("%s: ciphertext too short", filepath.Base(p))
	}
	nonce, ct := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	secret, err := aead.Open(nil, nonce, ct, []byte(id))
	if err != nil {
		return nil, fmt.Errorf("%s: decrypt failed (wrong key or tampered file): %w", filepath.Base(p), err)
	}
	return secret, nil
}

func (s *FileStore) Delete(id string) error {
	p, err := secretPath(id)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	// Prune empty namespace dirs up to (not including) the .secrets root.
	home, err := HomeDir()
	if err != nil {
		return nil
	}
	root := filepath.Join(home, secretsSubdir)
	for dir := filepath.Dir(p); dir != root && strings.HasPrefix(dir, root+string(filepath.Separator)); dir = filepath.Dir(dir) {
		if err := os.Remove(dir); err != nil {
			break
		}
	}
	return nil
}

func (s *FileStore) Exists(id string) (bool, error) {
	p, err := secretPath(id)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

var _ Store = (*FileStore)(nil)
