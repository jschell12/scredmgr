package store

import (
	"bytes"
	"fmt"
)

// LoadAndMigrate reads metadata for id and, if a plaintext token is present
// (Storage == "file" or "mixed"), migrates it into the keychain:
//
//  1. Write the plaintext token to the keychain.
//  2. Read it back and compare byte-for-byte.
//  3. Only after a verified round-trip, strip the plaintext from the JSON and
//     flip Storage to "keychain".
//
// If any step fails, the plaintext is left untouched so the secret is never
// lost. Never strip before a verified round-trip.
func LoadAndMigrate(id string, s Store) (*Meta, error) {
	m, err := ReadMeta(id)
	if err != nil {
		return nil, err
	}
	if m.Token == "" {
		return m, nil
	}

	plaintext := []byte(m.Token)
	if err := s.Set(id, plaintext); err != nil {
		return m, fmt.Errorf("migrate %s: keychain write failed (plaintext preserved): %w", id, err)
	}
	readback, err := s.Get(id)
	if err != nil {
		return m, fmt.Errorf("migrate %s: keychain read-back failed (plaintext preserved): %w", id, err)
	}
	if !bytes.Equal(plaintext, readback) {
		return m, fmt.Errorf("migrate %s: keychain round-trip mismatch (plaintext preserved)", id)
	}

	m.Token = ""
	m.Storage = StorageKeychain
	if err := WriteMeta(id, m); err != nil {
		return m, fmt.Errorf("migrate %s: metadata rewrite failed: %w", id, err)
	}
	return m, nil
}

// GetSecret returns the secret for id, running migration first if needed.
// If migration fails but the plaintext was preserved, the secret is still
// served — a locked keychain must not lock the user out of their own token.
func GetSecret(id string, s Store) ([]byte, error) {
	m, err := LoadAndMigrate(id, s)
	if m != nil && m.Token != "" {
		return []byte(m.Token), nil
	}
	if err != nil {
		return nil, err
	}
	return s.Get(id)
}
