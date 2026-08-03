package provider

import (
	"context"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jschell12/scredmanager/internal/store"
)

// startTLSVault serves the fake KV v2 API over TLS with a self-signed cert
// and returns the server plus a PEM file holding its certificate.
func startTLSVault(t *testing.T, token string) (*httptest.Server, string) {
	t.Helper()
	f := &fakeVaultServer{data: map[string]string{}, token: token}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: srv.Certificate().Raw,
	})
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, caPath
}

func tlsVault(t *testing.T, srvURL, caCert, token string) *Vault {
	t.Helper()
	fake := store.NewFakeStore()
	fake.Set("vault-token", []byte(token))
	return NewVault("tls-vault", VaultCfg{
		Addr: srvURL, Mount: "secret", PathPrefix: "sm/",
		TokenRef: "vault-token", CACert: caCert,
	}, fake)
}

func TestVaultPrivateCAViaConfig(t *testing.T) {
	srv, caPath := startTLSVault(t, "tok")
	v := tlsVault(t, srv.URL, caPath, "tok")
	if err := v.Check(context.Background()); err != nil {
		t.Fatalf("check with caCert: %v", err)
	}
	if err := v.Put(context.Background(), "x", []byte("v")); err != nil {
		t.Fatalf("put over TLS: %v", err)
	}
}

func TestVaultPrivateCAViaEnv(t *testing.T) {
	srv, caPath := startTLSVault(t, "tok")
	t.Setenv("VAULT_CACERT", caPath)
	v := tlsVault(t, srv.URL, "", "tok") // no caCert in config
	if err := v.Check(context.Background()); err != nil {
		t.Fatalf("check with VAULT_CACERT: %v", err)
	}
}

func TestVaultUntrustedCAFails(t *testing.T) {
	srv, _ := startTLSVault(t, "tok")
	t.Setenv("VAULT_CACERT", "")
	v := tlsVault(t, srv.URL, "", "tok")
	if err := v.Check(context.Background()); err == nil {
		t.Fatal("self-signed server must fail without a configured CA")
	}
}
