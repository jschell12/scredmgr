package store

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestValidateIDPaths(t *testing.T) {
	valid := []string{"jira", "work/jira", "a/b/c", "svc-bot/ATLASSIAN_TOKEN", "x.y:z"}
	for _, id := range valid {
		if err := ValidateID(id); err != nil {
			t.Errorf("ValidateID(%q) = %v, want nil", id, err)
		}
	}
	invalid := []string{"", "/jira", "jira/", "a//b", "a/../b", "..", ".", "work/..", "a b", "a/b c"}
	for _, id := range invalid {
		if err := ValidateID(id); err == nil {
			t.Errorf("ValidateID(%q) = nil, want error", id)
		}
	}
}

func TestBasenameAndPathOf(t *testing.T) {
	cases := []struct{ id, base, path string }{
		{"jira", "jira", ""},
		{"work/jira", "jira", "work"},
		{"a/b/c", "c", "a/b"},
	}
	for _, c := range cases {
		if got := Basename(c.id); got != c.base {
			t.Errorf("Basename(%q) = %q, want %q", c.id, got, c.base)
		}
		if got := PathOf(c.id); got != c.path {
			t.Errorf("PathOf(%q) = %q, want %q", c.id, got, c.path)
		}
	}
}

func TestNestedMetaRoundTripAndList(t *testing.T) {
	dir := withTempHome(t)

	for _, id := range []string{"jira", "work/jira", "work/github", "services", "providers"} {
		if err := WriteMeta(id, &Meta{EnvVar: "X", Storage: StorageKeychain}); err != nil {
			t.Fatal(err)
		}
	}

	// Nested file exists with a 0700 parent dir.
	fi, err := os.Stat(filepath.Join(dir, "work"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("namespace dir mode = %o, want 700", fi.Mode().Perm())
	}
	m, err := ReadMeta("work/jira")
	if err != nil || m.EnvVar != "X" {
		t.Fatalf("ReadMeta(work/jira) = %+v, %v", m, err)
	}

	ids, err := ListIDs()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(ids)
	want := []string{"jira", "work/github", "work/jira"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("ListIDs = %v, want %v", ids, want)
	}
}

func TestDeleteMetaPrunesEmptyNamespaceDirs(t *testing.T) {
	dir := withTempHome(t)
	if err := WriteMeta("a/b/c", &Meta{Storage: StorageKeychain}); err != nil {
		t.Fatal(err)
	}
	if err := WriteMeta("a/other", &Meta{Storage: StorageKeychain}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteMeta("a/b/c"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a", "b")); !os.IsNotExist(err) {
		t.Errorf("empty dir a/b not pruned: %v", err)
	}
	// a/ still holds a/other and must survive.
	if _, err := os.Stat(filepath.Join(dir, "a", "other.json")); err != nil {
		t.Errorf("sibling entry lost: %v", err)
	}
	if err := DeleteMeta("a/other"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a")); !os.IsNotExist(err) {
		t.Errorf("empty dir a not pruned: %v", err)
	}
	// Home dir itself must survive.
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("home dir removed: %v", err)
	}
}
