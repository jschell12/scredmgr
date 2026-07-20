//go:build !darwin

package store

import "errors"

// NewKeychainStore is unsupported off macOS; the Store interface exists so
// other backends (libsecret, wincred) can be added later.
func NewKeychainStore() Store {
	return &unsupportedStore{}
}

type unsupportedStore struct{}

var errUnsupported = errors.New("scredmanager: keychain backend is only available on macOS")

func (*unsupportedStore) Set(string, []byte) error      { return errUnsupported }
func (*unsupportedStore) Get(string) ([]byte, error)    { return nil, errUnsupported }
func (*unsupportedStore) Delete(string) error           { return errUnsupported }
func (*unsupportedStore) Exists(string) (bool, error)   { return false, errUnsupported }
