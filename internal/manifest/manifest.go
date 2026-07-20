// Package manifest handles the user-editable services manifest
// (~/.scredmanager/services.json) and auth-header construction.
package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jschell12/scredmanager/internal/store"
)

// Service describes one named service in services.json.
type Service struct {
	ID         string `json:"id"`
	EnvVar     string `json:"envVar,omitempty"`
	BaseURL    string `json:"baseUrl,omitempty"`
	CheckPath  string `json:"checkPath,omitempty"`
	AuthHeader string `json:"authHeader,omitempty"`
	ExpiryDays int    `json:"expiryDays,omitempty"`
	TokenPage  string `json:"tokenPage,omitempty"`

	// TokenPattern is an optional regex a clipboard-captured token must match
	// (e.g. "^ghp_[A-Za-z0-9]{36}$").
	TokenPattern string `json:"tokenPattern,omitempty"`

	// DeviceFlow enables the OAuth device-code grant for `login`.
	DeviceFlow *DeviceFlow `json:"deviceFlow,omitempty"`
}

// DeviceFlow configures RFC 8628 device authorization for a service.
// URLs default to GitHub's endpoints when omitted.
type DeviceFlow struct {
	ClientID      string `json:"clientId"`
	Scope         string `json:"scope,omitempty"`
	DeviceAuthURL string `json:"deviceAuthUrl,omitempty"`
	TokenURL      string `json:"tokenUrl,omitempty"`
}

// Load reads the manifest. A missing file yields an empty manifest.
func Load() ([]Service, error) {
	dir, err := store.HomeDir()
	if err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "services.json")
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var services []Service
	if err := json.Unmarshal(data, &services); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	return services, nil
}

// Find returns the service with the given id, or nil.
func Find(services []Service, id string) *Service {
	for i := range services {
		if services[i].ID == id {
			return &services[i]
		}
	}
	return nil
}

// FindByEnvVar returns the service whose envVar matches, or nil.
func FindByEnvVar(services []Service, envVar string) *Service {
	for i := range services {
		if services[i].EnvVar != "" && services[i].EnvVar == envVar {
			return &services[i]
		}
	}
	return nil
}
