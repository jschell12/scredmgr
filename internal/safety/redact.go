package safety

import (
	"strings"
	"sync"
)

// Redactor scrubs known secret values out of strings before they reach logs
// or error output. Every code path that touches a secret registers it here.
type Redactor struct {
	mu      sync.Mutex
	secrets []string
}

var Default = &Redactor{}

// Track registers a secret value for redaction.
func (r *Redactor) Track(secret []byte) {
	if len(secret) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secrets = append(r.secrets, string(secret))
}

// Redact replaces any tracked secret occurring in s with "***".
func (r *Redactor) Redact(s string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sec := range r.secrets {
		s = strings.ReplaceAll(s, sec, "***")
	}
	return s
}

// Track registers a secret with the default redactor.
func Track(secret []byte) { Default.Track(secret) }

// Redact scrubs s with the default redactor.
func Redact(s string) string { return Default.Redact(s) }
