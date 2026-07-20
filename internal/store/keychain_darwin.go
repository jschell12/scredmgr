//go:build darwin

package store

import (
	"errors"

	keychain "github.com/keybase/go-keychain"
)

const (
	keychainService = "scredmanager"
	accountPrefix   = "token/"
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
	item.SetLabel("scredmanager: " + id)
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
