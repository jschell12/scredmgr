//go:build darwin_integration

// Real-keychain round-trip tests. Run manually on macOS:
//
//	go test -tags darwin_integration ./internal/store/
package store

import (
	"bytes"
	"testing"
)

func TestKeychainRoundTrip(t *testing.T) {
	s := NewKeychainStore()
	const id = "scredmgr-integration-test"
	secret := []byte("integration-s3cret")

	if err := s.Set(id, secret); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Delete(id) })

	got, err := s.Get(id)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Get = %q, %v", got, err)
	}

	// Overwrite path (duplicate item → update).
	if err := s.Set(id, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get(id)
	if string(got) != "v2" {
		t.Fatalf("after update: %q", got)
	}

	ok, err := s.Exists(id)
	if err != nil || !ok {
		t.Fatalf("Exists = %v, %v", ok, err)
	}
	if err := s.Delete(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(id); err == nil {
		t.Fatal("Get after Delete should fail")
	}
}
