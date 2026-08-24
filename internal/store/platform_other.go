//go:build !darwin

package store

// NewPlatformStore returns the default secret backend for this platform:
// the encrypted file store (no OS keychain integration off macOS).
func NewPlatformStore() Store {
	return NewFileStore()
}

// PlatformStorage is the Meta.Storage provenance value written for secrets
// stored via NewPlatformStore.
func PlatformStorage() string {
	return StorageEncFile
}

// IsLockedKeychainErr always reports false off macOS: the file store has no
// locked-session failure mode.
func IsLockedKeychainErr(error) bool {
	return false
}
