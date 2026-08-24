// Package share implements machine-to-machine secret transfer over ssh:
// the wire payload, VPN detection, ssh_config host discovery, and the
// encrypted inbox used when the receiver's keychain is locked.
//
// Transport discipline: the payload (which contains secret values) travels
// exclusively on the ssh child's stdin — never on argv and never in the
// environment.
package share

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the wire format version this binary writes and accepts.
const Version = 1

// maxPayloadBytes caps Decode input; secrets are small, so anything larger
// is malformed or hostile.
const maxPayloadBytes = 16 << 20

// Entry is one secret plus the non-secret metadata worth carrying across.
type Entry struct {
	ID        string `json:"id"`
	SecretB64 string `json:"secretB64"`
	Label     string `json:"label,omitempty"`
	EnvVar    string `json:"envVar,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	Notes     string `json:"notes,omitempty"`
	Kind      string `json:"kind,omitempty"`
}

// Payload is the versioned wire format piped to `scredmgr receive --stdin`.
type Payload struct {
	Version int     `json:"version"`
	From    string  `json:"from"`
	SentAt  string  `json:"sentAt"`
	Entries []Entry `json:"entries"`
}

// Encode serializes the payload.
func (p *Payload) Encode() ([]byte, error) {
	if len(p.Entries) == 0 {
		return nil, errors.New("payload has no entries")
	}
	return json.Marshal(p)
}

// Decode parses and validates a payload from r, enforcing the version and a
// size cap.
func Decode(r io.Reader) (*Payload, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxPayloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPayloadBytes {
		return nil, fmt.Errorf("payload exceeds %d byte cap", maxPayloadBytes)
	}
	var p Payload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	if p.Version != Version {
		return nil, fmt.Errorf("unsupported payload version %d (this binary speaks %d — update scredmgr on both machines)", p.Version, Version)
	}
	if len(p.Entries) == 0 {
		return nil, errors.New("payload has no entries")
	}
	for i, e := range p.Entries {
		if e.ID == "" {
			return nil, fmt.Errorf("entry %d has no id", i)
		}
	}
	return &p, nil
}
