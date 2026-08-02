package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jschell12/scredmanager/internal/store"
)

// fakeVaultServer implements enough of the KV v2 API for the provider.
type fakeVaultServer struct {
	mu      sync.Mutex
	data    map[string]string // path (after prefix) -> value
	token   string
	lastReq *http.Request
}

func newFakeVault(token string) (*fakeVaultServer, *httptest.Server) {
	f := &fakeVaultServer{data: map[string]string{}, token: token}
	return f, httptest.NewServer(f)
}

func (f *fakeVaultServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastReq = r

	if r.Header.Get("X-Vault-Token") != f.token {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
		return
	}
	if r.URL.Path == "/v1/auth/token/lookup-self" {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "x"}})
		return
	}

	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/secret/metadata/") && (r.Method == "LIST" || r.URL.Query().Get("list") == "true"):
		var keys []string
		for k := range f.data {
			keys = append(keys, k)
		}
		if len(keys) == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})
	case strings.HasPrefix(r.URL.Path, "/v1/secret/metadata/") && r.Method == http.MethodDelete:
		key := strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata/sm/")
		delete(f.data, key)
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(r.URL.Path, "/v1/secret/data/") && r.Method == http.MethodGet:
		key := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/sm/")
		val, ok := f.data[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]string{"value": val}}})
	case strings.HasPrefix(r.URL.Path, "/v1/secret/data/") && r.Method == http.MethodPost:
		key := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/sm/")
		var body struct {
			Data map[string]string `json:"data"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		f.data[key] = body.Data["value"]
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": 1}})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newTestVault(t *testing.T, srvURL, tokenRef, token string) *Vault {
	t.Helper()
	fake := store.NewFakeStore()
	if tokenRef != "" {
		fake.Set(tokenRef, []byte(token))
	}
	return NewVault("test-vault", VaultCfg{
		Addr: srvURL, Mount: "secret", PathPrefix: "sm/", TokenRef: tokenRef,
	}, fake)
}

func TestVaultRoundTrip(t *testing.T) {
	f, srv := newFakeVault("tok123")
	defer srv.Close()
	v := newTestVault(t, srv.URL, "vault-token", "tok123")
	ctx := context.Background()

	if err := v.Check(ctx); err != nil {
		t.Fatalf("check: %v", err)
	}
	if err := v.Put(ctx, "github", []byte("s3cr3t")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if f.data["github"] != "s3cr3t" {
		t.Fatalf("server state: %v", f.data)
	}
	got, err := v.Get(ctx, "github")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != "s3cr3t" {
		t.Fatalf("got %q", got)
	}
	ids, err := v.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(ids) != 1 || ids[0] != "github" {
		t.Fatalf("list: %v", ids)
	}
	if err := v.Delete(ctx, "github"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(f.data) != 0 {
		t.Fatalf("delete left state: %v", f.data)
	}
}

func TestVaultTokenFromKeychainRef(t *testing.T) {
	_, srv := newFakeVault("right-token")
	defer srv.Close()

	// wrong token in keychain -> 403 surfaces as error, no panic
	v := newTestVault(t, srv.URL, "vault-token", "wrong-token")
	if err := v.Check(context.Background()); err == nil {
		t.Fatal("expected auth failure with wrong token")
	}

	// missing tokenRef entry and no VAULT_TOKEN -> clear error
	t.Setenv("VAULT_TOKEN", "")
	v2 := NewVault("v", VaultCfg{Addr: srv.URL, Mount: "secret"}, store.NewFakeStore())
	if _, err := v2.Get(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "no vault token") {
		t.Fatalf("expected token error, got %v", err)
	}
}

func TestVaultListSkipsNested(t *testing.T) {
	f, srv := newFakeVault("t")
	defer srv.Close()
	f.data["flat"] = "v"
	f.data["nested/"] = "dir-marker"
	v := newTestVault(t, srv.URL, "vault-token", "t")
	ids, err := v.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "flat" {
		t.Fatalf("nested path not skipped: %v", ids)
	}
}
