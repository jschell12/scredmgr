package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jschell12/scredmanager/internal/store"
)

func writeConfig(t *testing.T, content string, mode os.FileMode) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SCREDMANAGER_HOME", dir)
	if err := os.WriteFile(filepath.Join(dir, "providers.json"), []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigs(t *testing.T) {
	writeConfig(t, `{"providers":[
		{"name":"hv","type":"vault","vault":{"addr":"https://v:8200","mount":"secret","pathPrefix":"sm/","tokenRef":"vault-token"}},
		{"name":"lp","type":"lastpass","lastpass":{"folder":"sm"}}
	]}`, 0o600)
	configs, err := LoadConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 2 || configs[0].Name != "hv" || configs[0].Vault.Mount != "secret" {
		t.Fatalf("bad parse: %+v", configs)
	}
}

func TestLoadConfigsMissingFile(t *testing.T) {
	t.Setenv("SCREDMANAGER_HOME", t.TempDir())
	configs, err := LoadConfigs()
	if err != nil || configs != nil {
		t.Fatalf("missing file should yield nil, nil: %v %v", configs, err)
	}
}

func TestLoadConfigsRejectsLoosePerms(t *testing.T) {
	writeConfig(t, `{"providers":[]}`, 0o644)
	if _, err := LoadConfigs(); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("expected 0600 enforcement, got %v", err)
	}
}

func TestLoadConfigsBadJSON(t *testing.T) {
	writeConfig(t, `{`, 0o600)
	if _, err := LoadConfigs(); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestFindConfig(t *testing.T) {
	configs := []Config{{Name: "a"}, {Name: "b"}}
	if c, err := FindConfig(configs, "b"); err != nil || c.Name != "b" {
		t.Fatalf("find: %v %v", c, err)
	}
	if _, err := FindConfig(configs, "zzz"); err == nil || !strings.Contains(err.Error(), "a") {
		t.Fatalf("expected error listing options, got %v", err)
	}
	if _, err := FindConfig(nil, "x"); err == nil || !strings.Contains(err.Error(), "no providers configured") {
		t.Fatalf("expected no-providers hint, got %v", err)
	}
}

func TestOpenUnknownType(t *testing.T) {
	if _, err := Open(Config{Name: "x", Type: "carrier-pigeon"}, store.NewFakeStore()); err == nil {
		t.Fatal("expected unsupported-type error")
	}
	if _, err := Open(Config{Name: "x", Type: "vault"}, store.NewFakeStore()); err == nil {
		t.Fatal("expected missing vault config error")
	}
}
