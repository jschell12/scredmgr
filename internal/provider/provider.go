// Package provider abstracts remote secret backends (Vault, 1Password, AWS
// Secrets Manager / Parameter Store, LastPass). The macOS Keychain remains the
// local canonical store; providers are explicit push/pull targets driven by
// the `sync` command. Every value fetched or pushed is registered with the
// redactor, and no secret ever rides on a subprocess argv or environment.
package provider

import (
	"context"
	"errors"
)

// ErrReadOnly is returned by Put/Delete on providers that are pull-only.
var ErrReadOnly = errors.New("provider is read-only")

// Provider is a remote secret backend. Ids are in local form (any remote
// prefix/folder already stripped by the implementation).
type Provider interface {
	Name() string
	// Check probes connectivity and auth. Errors must not contain secrets.
	Check(ctx context.Context) error
	List(ctx context.Context) ([]string, error)
	Get(ctx context.Context, id string) ([]byte, error)
	Put(ctx context.Context, id string, value []byte) error
	Delete(ctx context.Context, id string) error
	// Writable reports whether Put/Delete are supported (false: lastpass).
	Writable() bool
}
