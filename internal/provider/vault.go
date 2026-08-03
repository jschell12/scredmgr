package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jschell12/scredmanager/internal/safety"
	"github.com/jschell12/scredmanager/internal/store"
)

// Vault talks to a HashiCorp Vault KV v2 mount via the stdlib HTTP client.
// The secret value lives under the "value" key of each KV entry.
type Vault struct {
	name    string
	cfg     VaultCfg
	secrets store.Store
	client  *http.Client
}

// NewVault returns a Vault provider. The token is resolved lazily on first use
// from cfg.TokenRef (a scredmanager keychain entry) or $VAULT_TOKEN. A private
// CA for the Vault endpoint comes from cfg.CACert or $VAULT_CACERT (a PEM
// file, same convention as the vault CLI).
func NewVault(name string, cfg VaultCfg, secrets store.Store) *Vault {
	client := &http.Client{Timeout: 15 * time.Second}
	caPath := cfg.CACert
	if caPath == "" {
		caPath = os.Getenv("VAULT_CACERT")
	}
	if caPath != "" {
		if pem, err := os.ReadFile(caPath); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				client.Transport = &http.Transport{
					TLSClientConfig: &tls.Config{RootCAs: pool},
				}
			}
		}
		// Unreadable/invalid CA files fall through to the system pool; the
		// TLS handshake error from do() then names the real problem.
	}
	return &Vault{
		name:    name,
		cfg:     cfg,
		secrets: secrets,
		client:  client,
	}
}

func (v *Vault) Name() string   { return v.name }
func (v *Vault) Writable() bool { return true }

func (v *Vault) token() (string, error) {
	if v.cfg.TokenRef != "" {
		tok, err := v.secrets.Get(v.cfg.TokenRef)
		if err != nil {
			return "", fmt.Errorf("vault token from keychain entry %q: %w", v.cfg.TokenRef, err)
		}
		safety.Track(tok)
		return string(tok), nil
	}
	if tok := os.Getenv("VAULT_TOKEN"); tok != "" {
		safety.Track([]byte(tok))
		return tok, nil
	}
	return "", errors.New("no vault token: set tokenRef in providers.json or VAULT_TOKEN")
}

func (v *Vault) url(kind, id string) string {
	base := strings.TrimRight(v.cfg.Addr, "/")
	return fmt.Sprintf("%s/v1/%s/%s/%s%s", base, v.cfg.Mount, kind, v.cfg.PathPrefix, id)
}

// do issues one authenticated request and returns the response body for 2xx.
func (v *Vault) do(ctx context.Context, method, url string, body []byte) ([]byte, int, error) {
	tok, err := v.token()
	if err != nil {
		return nil, 0, err
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Vault-Token", tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("vault %s: %s", method, safety.Redact(err.Error()))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return data, resp.StatusCode, fmt.Errorf("vault %s %s: HTTP %d: %s",
			method, safety.Redact(url), resp.StatusCode, safety.Redact(vaultErrors(data)))
	}
	return data, resp.StatusCode, nil
}

func vaultErrors(body []byte) string {
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &e) == nil && len(e.Errors) > 0 {
		return strings.Join(e.Errors, "; ")
	}
	return strings.TrimSpace(string(body))
}

// Check verifies the token against auth/token/lookup-self and probes that the
// mount answers KV v2-style list requests.
func (v *Vault) Check(ctx context.Context) error {
	base := strings.TrimRight(v.cfg.Addr, "/")
	if _, _, err := v.do(ctx, http.MethodGet, base+"/v1/auth/token/lookup-self", nil); err != nil {
		return err
	}
	// 404 on an empty prefix is fine; 403/405 suggests a KV v1 mount or policy gap.
	_, status, err := v.do(ctx, "LIST", v.url("metadata", ""), nil)
	if err != nil && status != http.StatusNotFound {
		return fmt.Errorf("%w (hint: mount %q must be KV v2 and the token needs list on %s%s)",
			err, v.cfg.Mount, v.cfg.Mount, "/metadata/"+v.cfg.PathPrefix)
	}
	return nil
}

func (v *Vault) List(ctx context.Context) ([]string, error) {
	data, status, err := v.do(ctx, "LIST", v.url("metadata", ""), nil)
	if status == http.StatusNotFound {
		return nil, nil // empty prefix
	}
	if err != nil {
		return nil, err
	}
	var out struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("vault list: parse: %w", err)
	}
	var ids []string
	for _, k := range out.Data.Keys {
		if strings.HasSuffix(k, "/") {
			continue // nested paths are unsupported; single level only
		}
		ids = append(ids, k)
	}
	return ids, nil
}

func (v *Vault) Get(ctx context.Context, id string) ([]byte, error) {
	data, _, err := v.do(ctx, http.MethodGet, v.url("data", id), nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("vault get %s: parse: %w", id, err)
	}
	val, ok := out.Data.Data["value"]
	if !ok {
		return nil, fmt.Errorf("vault get %s: no \"value\" key in secret", id)
	}
	secret := []byte(val)
	safety.Track(secret)
	return secret, nil
}

func (v *Vault) Put(ctx context.Context, id string, value []byte) error {
	safety.Track(value)
	body, err := json.Marshal(map[string]any{"data": map[string]string{"value": string(value)}})
	if err != nil {
		return err
	}
	_, _, err = v.do(ctx, http.MethodPost, v.url("data", id), body)
	return err
}

func (v *Vault) Delete(ctx context.Context, id string) error {
	// metadata delete removes all versions, not just the latest.
	_, _, err := v.do(ctx, http.MethodDelete, v.url("metadata", id), nil)
	return err
}
