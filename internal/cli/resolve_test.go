package cli

import (
	"testing"

	"github.com/jschell12/scredmanager/internal/store"
)

func seedEntry(t *testing.T, s store.Store, id, envVar, secret string) {
	t.Helper()
	if err := s.Set(id, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteMeta(id, &store.Meta{EnvVar: envVar, Storage: store.StorageKeychain}); err != nil {
		t.Fatal(err)
	}
}

func pairsToMap(pairs []envPair) map[string]string {
	out := make(map[string]string)
	for _, p := range pairs {
		out[p.EnvVar] = string(p.Secret)
	}
	return out
}

func TestResolveEnvRootOnly(t *testing.T) {
	t.Setenv("SCREDMANAGER_HOME", t.TempDir())
	s := store.NewFakeStore()
	seedEntry(t, s, "jira", "JIRA_TOKEN", "personal")
	seedEntry(t, s, "work/jira", "JIRA_TOKEN", "svc-account")

	pairs, _, err := resolveEnv("", nil, s)
	if err != nil {
		t.Fatal(err)
	}
	got := pairsToMap(pairs)
	if len(got) != 1 || got["JIRA_TOKEN"] != "personal" {
		t.Fatalf("root resolution = %v, want JIRA_TOKEN=personal only", got)
	}
}

func TestResolveEnvOverlay(t *testing.T) {
	t.Setenv("SCREDMANAGER_HOME", t.TempDir())
	s := store.NewFakeStore()
	seedEntry(t, s, "jira", "JIRA_TOKEN", "personal")
	seedEntry(t, s, "github", "GITHUB_TOKEN", "gh-personal")
	seedEntry(t, s, "work/jira", "JIRA_TOKEN", "svc-account")
	seedEntry(t, s, "other/jira", "JIRA_TOKEN", "other-account")

	pairs, _, err := resolveEnv("work", nil, s)
	if err != nil {
		t.Fatal(err)
	}
	got := pairsToMap(pairs)
	want := map[string]string{"JIRA_TOKEN": "svc-account", "GITHUB_TOKEN": "gh-personal"}
	if len(got) != len(want) {
		t.Fatalf("overlay resolution = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// The winning pair must report the overlay id.
	for _, p := range pairs {
		if p.EnvVar == "JIRA_TOKEN" && p.ID != "work/jira" {
			t.Errorf("JIRA_TOKEN resolved from %q, want work/jira", p.ID)
		}
	}
}

func TestResolveEnvOnlyFilter(t *testing.T) {
	t.Setenv("SCREDMANAGER_HOME", t.TempDir())
	s := store.NewFakeStore()
	seedEntry(t, s, "jira", "JIRA_TOKEN", "personal")
	seedEntry(t, s, "github", "GITHUB_TOKEN", "gh-personal")
	seedEntry(t, s, "work/jira", "JIRA_TOKEN", "svc-account")

	pairs, matched, err := resolveEnv("work", map[string]bool{"work/jira": true}, s)
	if err != nil {
		t.Fatal(err)
	}
	got := pairsToMap(pairs)
	if len(got) != 1 || got["JIRA_TOKEN"] != "svc-account" {
		t.Fatalf("only-filter resolution = %v, want JIRA_TOKEN=svc-account only", got)
	}
	if matched != 1 {
		t.Errorf("matched = %d, want 1", matched)
	}
}

func TestResolveEnvRejectsBadPath(t *testing.T) {
	t.Setenv("SCREDMANAGER_HOME", t.TempDir())
	if _, _, err := resolveEnv("../etc", nil, store.NewFakeStore()); err == nil {
		t.Fatal("resolveEnv accepted a traversal path")
	}
}
