// Package store provides the secret storage backends and metadata handling.
//
// Secrets live in the macOS Keychain; metadata lives in 0600 JSON files under
// the scredmanager home directory. Nothing secret is ever at rest in cleartext
// (outside the import-then-migrate window, see migrate.go).
package store

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
)

// ErrNotFound is returned when a secret does not exist in the store.
var ErrNotFound = errors.New("secret not found")

// Store is the secret storage interface. The darwin implementation is backed
// by the macOS Keychain; other platforms can be added later.
type Store interface {
	Set(id string, secret []byte) error
	Get(id string) ([]byte, error)
	Delete(id string) error
	Exists(id string) (bool, error)
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

// ValidateID rejects ids that are unsafe as filenames or keychain accounts.
func ValidateID(id string) error {
	if id == "" {
		return errors.New("id must not be empty")
	}
	if !idPattern.MatchString(id) {
		return fmt.Errorf("invalid id %q: only [A-Za-z0-9_.:-] allowed", id)
	}
	return nil
}

// FakeStore is an in-memory Store used by unit tests.
type FakeStore struct {
	mu      sync.Mutex
	secrets map[string][]byte

	// FailSet, when non-nil, is returned from Set to simulate keychain failures.
	FailSet error
}

// NewFakeStore returns an empty in-memory store.
func NewFakeStore() *FakeStore {
	return &FakeStore{secrets: make(map[string][]byte)}
}

func (f *FakeStore) Set(id string, secret []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailSet != nil {
		return f.FailSet
	}
	cp := make([]byte, len(secret))
	copy(cp, secret)
	f.secrets[id] = cp
	return nil
}

func (f *FakeStore) Get(id string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.secrets[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := make([]byte, len(s))
	copy(cp, s)
	return cp, nil
}

func (f *FakeStore) Delete(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.secrets[id]; !ok {
		return ErrNotFound
	}
	delete(f.secrets, id)
	return nil
}

func (f *FakeStore) Exists(id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.secrets[id]
	return ok, nil
}
