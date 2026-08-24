//go:build darwin

package store

import (
	"errors"

	keychain "github.com/keybase/go-keychain"
)

// NewPlatformStore returns the default secret backend for this platform:
// the macOS Keychain.
func NewPlatformStore() Store {
	return NewKeychainStore()
}

// PlatformStorage is the Meta.Storage provenance value written for secrets
// stored via NewPlatformStore.
func PlatformStorage() string {
	return StorageKeychain
}

// IsLockedKeychainErr reports whether err means the keychain refused the
// operation because no interactive session is available to unlock it
// (errSecInteractionNotAllowed — e.g. over non-interactive ssh).
func IsLockedKeychainErr(err error) bool {
	return errors.Is(err, keychain.ErrorInteractionNotAllowed)
}
