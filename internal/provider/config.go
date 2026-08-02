package provider

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jschell12/scredmanager/internal/store"
)

// Config is one entry in ~/.scredmanager/providers.json.
type Config struct {
	Name string `json:"name"`
	Type string `json:"type"` // vault | 1password | aws-sm | aws-ps | lastpass

	Vault    *VaultCfg    `json:"vault,omitempty"`
	Op       *OpCfg       `json:"op,omitempty"`
	AWS      *AWSCfg      `json:"aws,omitempty"`
	Lastpass *LastpassCfg `json:"lastpass,omitempty"`
}

// VaultCfg configures a HashiCorp Vault KV v2 backend.
type VaultCfg struct {
	Addr       string `json:"addr"`
	Mount      string `json:"mount"`                // KV v2 mount, e.g. "secret"
	PathPrefix string `json:"pathPrefix,omitempty"` // e.g. "scredmanager/"
	// TokenRef names a scredmanager keychain entry holding the Vault token.
	// Fallback: VAULT_TOKEN environment variable.
	TokenRef string `json:"tokenRef,omitempty"`
}

// OpCfg configures the 1Password `op` CLI backend.
type OpCfg struct {
	Vault      string `json:"vault"`
	Account    string `json:"account,omitempty"`
	ItemPrefix string `json:"itemPrefix,omitempty"`
}

// AWSCfg configures the `aws` CLI backends (aws-sm, aws-ps).
type AWSCfg struct {
	Region  string `json:"region,omitempty"`
	Profile string `json:"profile,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
}

// LastpassCfg configures the pull-only `lpass` CLI backend.
type LastpassCfg struct {
	Folder string `json:"folder"`
}

type configFile struct {
	Providers []Config `json:"providers"`
}

// LoadConfigs reads ~/.scredmanager/providers.json. A missing file yields an
// empty list; a group/world-readable file is refused.
func LoadConfigs() ([]Config, error) {
	dir, err := store.HomeDir()
	if err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "providers.json")
	info, err := os.Stat(p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be 0600 (is %o)", p, info.Mode().Perm())
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var f configFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	return f.Providers, nil
}

// FindConfig returns the named provider config, or an error listing options.
func FindConfig(configs []Config, name string) (*Config, error) {
	for i := range configs {
		if configs[i].Name == name {
			return &configs[i], nil
		}
	}
	if len(configs) == 0 {
		return nil, fmt.Errorf("no providers configured (create ~/.scredmanager/providers.json)")
	}
	names := make([]string, len(configs))
	for i, c := range configs {
		names[i] = c.Name
	}
	return nil, fmt.Errorf("unknown provider %q (configured: %v)", name, names)
}

// Open instantiates the provider for cfg. The keychain store is passed in so
// providers can resolve their own credentials (e.g. Vault tokenRef) and tests
// can inject a FakeStore.
func Open(cfg Config, secrets store.Store) (Provider, error) {
	switch cfg.Type {
	case "vault":
		if cfg.Vault == nil {
			return nil, fmt.Errorf("provider %s: missing vault config", cfg.Name)
		}
		return NewVault(cfg.Name, *cfg.Vault, secrets), nil
	case "1password":
		if cfg.Op == nil {
			return nil, fmt.Errorf("provider %s: missing op config", cfg.Name)
		}
		return NewOp(cfg.Name, *cfg.Op, ExecRunner), nil
	default:
		return nil, fmt.Errorf("provider %s: unsupported type %q", cfg.Name, cfg.Type)
	}
}
