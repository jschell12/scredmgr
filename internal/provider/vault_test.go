package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jschell12/scredmgr/internal/store"
)

// fakeVaultServer implements enough of the KV v2 API for the provider.
type fakeVaultServer struct {
	mu      sync.Mutex
	data    map[string]string // path (after prefix) -> value
	meta    map[string]string // path (after prefix) -> raw metadata response body
	token   string
	lastReq *http.Request
}

func newFakeVault(token string) (*fakeVaultServer, *httptest.Server) {
	f := &fakeVaultServer{data: map[string]string{}, meta: map[string]string{}, token: token}
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
		// KV v2 LIST semantics: immediate children of the directory, with
		// sub-directories suffixed "/". Unknown or empty directory: 404.
		dir := strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata/sm/")
		seen := map[string]bool{}
		var keys []string
		for k := range f.data {
			if !strings.HasPrefix(k, dir) {
				continue
			}
			rest := strings.TrimPrefix(k, dir)
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				rest = rest[:i+1]
			}
			if !seen[rest] {
				seen[rest] = true
				keys = append(keys, rest)
			}
		}
		if len(keys) == 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})
	case strings.HasPrefix(r.URL.Path, "/v1/secret/metadata/") && r.Method == http.MethodGet:
		key := strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata/sm/")
		meta, ok := f.meta[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
			return
		}
		w.Write([]byte(meta))
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

func TestVaultListRecursesIntoPaths(t *testing.T) {
	f, srv := newFakeVault("t")
	defer srv.Close()
	// Put writes path-qualified ids as nested keys; List must return them.
	f.data["flat"] = "v"
	f.data["custom:KEY"] = "v"
	f.data["work/jira"] = "v"
	f.data["work/github"] = "v"
	f.data["a/b/c/d/e"] = "too-deep"
	v := newTestVault(t, srv.URL, "vault-token", "t")
	if err := v.Put(context.Background(), "proj/NEW_KEY", []byte("v")); err != nil {
		t.Fatal(err)
	}
	ids, err := v.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(ids)
	want := []string{"custom:KEY", "flat", "proj/NEW_KEY", "work/github", "work/jira"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("list = %v, want %v", ids, want)
	}
}

// metadataFixture is the shape of a real KV v2 metadata read, captured
// 2026-10-19 from `vault server -dev` (2.0.3) after a create then an update;
// ids, times and client ids are as captured. Fields this code does not read
// (last_updated_by, client_id) are kept so the fixture stays a real response.
const metadataFixture = `{"request_id":"c733d64b-e243-96e0-039d-886ba3c47073","lease_id":"","renewable":false,"lease_duration":0,"data":{"cas_required":false,"created_time":"2026-10-19T17:01:38.656605Z","current_version":2,"custom_metadata":null,"delete_version_after":"0s","last_updated_by":{"actor":"token","operation":"update","client_id":"rwPB+fpMrWfATB0Dge7A+Lc/iWASUM+cq6aHDAzKcUM="},"max_versions":0,"oldest_version":0,"updated_time":"2026-10-19T17:01:38.94357Z","versions":{"1":{"created_by":{"actor":"token","operation":"create","client_id":"0DHqvq2D77kL2/JTPSZkTMJbkFVmUu0TzMi0jiXcFy8="},"created_time":"2026-10-19T17:01:38.656605Z","deleted_by":null,"deletion_time":"","destroyed":false},"2":{"created_by":{"actor":"token","operation":"update","client_id":"rwPB+fpMrWfATB0Dge7A+Lc/iWASUM+cq6aHDAzKcUM="},"created_time":"2026-10-19T17:01:38.94357Z","deleted_by":null,"deletion_time":"","destroyed":false}}},"wrap_info":null,"warnings":null,"auth":null,"mount_type":"kv"}`

func TestVaultUpdatedAt(t *testing.T) {
	f, srv := newFakeVault("t")
	defer srv.Close()
	v := newTestVault(t, srv.URL, "vault-token", "t")
	ctx := context.Background()

	f.meta["custom:EXISTING"] = metadataFixture
	got, err := v.UpdatedAt(ctx, "custom:EXISTING")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := time.Parse(time.RFC3339Nano, "2026-10-19T17:01:38.94357Z")
	if !got.Equal(want) {
		t.Fatalf("UpdatedAt = %v, want current version 2's created_time %v", got, want)
	}

	// Current version soft-deleted (deletion_time in the past).
	f.meta["gone"] = strings.Replace(metadataFixture,
		`"created_time":"2026-10-19T17:01:38.94357Z","deleted_by":null,"deletion_time":""`,
		`"created_time":"2026-10-19T17:01:38.94357Z","deleted_by":null,"deletion_time":"2026-10-19T17:05:00Z"`, 1)
	if _, err := v.UpdatedAt(ctx, "gone"); !errors.Is(err, ErrNoCurrentValue) {
		t.Fatalf("deleted current version: err = %v, want ErrNoCurrentValue", err)
	}

	// deletion_time in the future (delete_version_after) is not deleted yet.
	f.meta["later"] = strings.Replace(metadataFixture,
		`"deleted_by":null,"deletion_time":"","destroyed":false}}}`,
		`"deleted_by":null,"deletion_time":"2999-01-01T00:00:00Z","destroyed":false}}}`, 1)
	if f.meta["later"] == metadataFixture || f.meta["gone"] == metadataFixture {
		t.Fatal("fixture edit did not apply; the deletion cases test nothing")
	}
	if _, err := v.UpdatedAt(ctx, "later"); err != nil {
		t.Fatalf("future deletion_time: %v", err)
	}

	if _, err := v.UpdatedAt(ctx, "missing"); err == nil {
		t.Fatal("missing entry: want error")
	}
}
