//go:build darwin

package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	keychain "github.com/keybase/go-keychain"
)

const (
	keychainService = "scredmgr"
	accountPrefix   = "token/"

	// legacyKeychainService is the pre-rename service name. Entries under it
	// are copied (not moved) into keychainService by MigrateLegacy.
	legacyKeychainService = "scredmanager"
	migrationMarker       = ".migrated-keychain-scredmanager"
)

// KeychainStore stores secrets in the macOS Keychain via Security.framework,
// in-process — the secret never appears in ps argv.
type KeychainStore struct{}

// NewKeychainStore returns the platform keychain-backed store.
func NewKeychainStore() Store {
	return &KeychainStore{}
}

func newItem(id string) keychain.Item {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(keychainService)
	item.SetAccount(accountPrefix + id)
	return item
}

func (k *KeychainStore) Set(id string, secret []byte) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	item := newItem(id)
	item.SetLabel("scredmgr: " + id)
	item.SetData(secret)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)

	err := keychain.AddItem(item)
	if errors.Is(err, keychain.ErrorDuplicateItem) {
		update := keychain.NewItem()
		update.SetData(secret)
		return keychain.UpdateItem(newItem(id), update)
	}
	return err
}

func (k *KeychainStore) Get(id string) ([]byte, error) {
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	query := newItem(id)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)
	results, err := keychain.QueryItem(query)
	if errors.Is(err, keychain.ErrorItemNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, ErrNotFound
	}
	return results[0].Data, nil
}

func (k *KeychainStore) Delete(id string) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	err := keychain.DeleteItem(newItem(id))
	if errors.Is(err, keychain.ErrorItemNotFound) {
		return ErrNotFound
	}
	return err
}

func (k *KeychainStore) Exists(id string) (bool, error) {
	if err := ValidateID(id); err != nil {
		return false, err
	}
	query := newItem(id)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	results, err := keychain.QueryItem(query)
	if errors.Is(err, keychain.ErrorItemNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(results) > 0, nil
}

// legacyGet reads a secret from the pre-rename "scredmanager" keychain
// service. Returns ErrNotFound when the legacy service has no such item.
func legacyGet(id string) ([]byte, error) {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(legacyKeychainService)
	item.SetAccount(accountPrefix + id)
	item.SetMatchLimit(keychain.MatchLimitOne)
	item.SetReturnData(true)
	results, err := keychain.QueryItem(item)
	if errors.Is(err, keychain.ErrorItemNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, ErrNotFound
	}
	return results[0].Data, nil
}

// MigrateLegacy copies keychain entries from the pre-rename "scredmanager"
// service into "scredmgr". Legacy entries are left intact as a backup. The
// attempt runs once per data directory; a marker file short-circuits later
// calls so routine commands don't re-query (or re-prompt for) legacy items.
// Per-entry failures are reported on stderr but do not block the marker —
// delete the marker file to retry.
func MigrateLegacy() error {
	dir, err := HomeDir()
	if err != nil {
		return err
	}
	marker := filepath.Join(dir, migrationMarker)
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	ids, err := ListIDs()
	if err != nil {
		return err
	}
	ks := &KeychainStore{}
	migrated, failed := 0, 0
	for _, id := range ids {
		if ok, err := ks.Exists(id); err == nil && ok {
			continue // already present under the new service
		}
		secret, err := legacyGet(id)
		if errors.Is(err, ErrNotFound) {
			continue // no keychain item (e.g. ssh key without passphrase)
		}
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "scredmgr: migrate %s: read legacy entry: %v\n", id, err)
			continue
		}
		if err := ks.Set(id, secret); err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "scredmgr: migrate %s: %v\n", id, err)
			continue
		}
		migrated++
	}
	if migrated > 0 || failed > 0 {
		fmt.Fprintf(os.Stderr, "scredmgr: keychain migration from %q: %d copied, %d failed (legacy entries kept as backup)\n",
			legacyKeychainService, migrated, failed)
	}
	return os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
}
