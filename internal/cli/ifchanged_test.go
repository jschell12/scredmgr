package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jschell12/scredmgr/internal/store"
)

// runSet runs `scredmgr set` with value on stdin (set reads os.Stdin
// directly) and returns what it printed to stdout.
func runSet(t *testing.T, value string, args ...string) (string, error) {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(inW, value); err != nil {
		t.Fatal(err)
	}
	inW.Close()
	return captureStdout(t, inR, func() error {
		return runCLI(t, append([]string{"set"}, args...)...)
	})
}

func captureStdout(t *testing.T, stdin *os.File, fn func() error) (string, error) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prevIn, prevOut := os.Stdin, os.Stdout
	if stdin != nil {
		os.Stdin = stdin
	}
	os.Stdout = outW
	runErr := fn()
	os.Stdin, os.Stdout = prevIn, prevOut
	outW.Close()
	out, _ := io.ReadAll(outR)
	return string(out), runErr
}

func TestSetIfChangedSkipsIdenticalValue(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "proj/API_KEY", "same-value", &store.Meta{EnvVar: "API_KEY", Storage: store.StorageKeychain, CreatedAt: "2026-01-01T00:00:00Z"})
	before := fake.SetCalls()

	out, err := runSet(t, "same-value\n", "proj/API_KEY", "--env-var", "API_KEY", "--from-stdin", "--if-changed")
	if err != nil {
		t.Fatal(err)
	}
	if fake.SetCalls() != before {
		t.Fatalf("Set called %d times for an unchanged value, want 0", fake.SetCalls()-before)
	}
	if !strings.HasPrefix(out, "unchanged proj/API_KEY") {
		t.Fatalf("stdout = %q, want an unchanged line", out)
	}
	if strings.Contains(out, "same-value") {
		t.Fatal("stdout contains the secret value")
	}
	m, err := store.ReadMeta("proj/API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if m.CreatedAt != "2026-01-01T00:00:00Z" {
		t.Fatalf("metadata rewritten for an unchanged entry: CreatedAt = %q", m.CreatedAt)
	}
}

func TestSetIfChangedWritesChangedValue(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "proj/API_KEY", "old-value", nil)

	out, err := runSet(t, "new-value", "proj/API_KEY", "--from-stdin", "--if-changed")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := fake.Get("proj/API_KEY"); string(got) != "new-value" {
		t.Fatal("changed value was not stored")
	}
	if !strings.HasPrefix(out, "stored proj/API_KEY") {
		t.Fatalf("stdout = %q, want a stored line", out)
	}
}

func TestSetIfChangedWritesNewEntry(t *testing.T) {
	fake, _ := withTestEnv(t)
	if _, err := runSet(t, "fresh", "proj/NEW", "--env-var", "NEW", "--from-stdin", "--if-changed"); err != nil {
		t.Fatal(err)
	}
	if got, _ := fake.Get("proj/NEW"); string(got) != "fresh" {
		t.Fatal("new entry was not stored")
	}
	if m, err := store.ReadMeta("proj/NEW"); err != nil || m.EnvVar != "NEW" {
		t.Fatalf("meta = %+v, %v", m, err)
	}
}

// A read that fails must count as "changed": the write goes ahead.
func TestSetIfChangedReadFailureWrites(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "proj/API_KEY", "same-value", nil)
	fake.FailGet = errors.New("keychain locked")
	before := fake.SetCalls()

	if _, err := runSet(t, "same-value", "proj/API_KEY", "--from-stdin", "--if-changed"); err != nil {
		t.Fatal(err)
	}
	if fake.SetCalls() != before+1 {
		t.Fatalf("Set calls = %d, want one write after a failed read", fake.SetCalls()-before)
	}
}

func TestSetIfChangedRefreshesEnvVarWithoutWrite(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "proj/API_KEY", "v", &store.Meta{EnvVar: "OLD_NAME", Storage: store.StorageKeychain})
	before := fake.SetCalls()

	if _, err := runSet(t, "v", "proj/API_KEY", "--env-var", "API_KEY", "--from-stdin", "--if-changed"); err != nil {
		t.Fatal(err)
	}
	if fake.SetCalls() != before {
		t.Fatal("keychain written for a metadata-only change")
	}
	if m, _ := store.ReadMeta("proj/API_KEY"); m.EnvVar != "API_KEY" {
		t.Fatalf("envVar = %q, want API_KEY", m.EnvVar)
	}
}

// Without the flag, set keeps its old behaviour and always writes.
func TestSetWithoutIfChangedAlwaysWrites(t *testing.T) {
	fake, _ := withTestEnv(t)
	addLocal(t, fake, "proj/API_KEY", "same-value", nil)
	before := fake.SetCalls()
	if _, err := runSet(t, "same-value", "proj/API_KEY", "--from-stdin"); err != nil {
		t.Fatal(err)
	}
	if fake.SetCalls() != before+1 {
		t.Fatal("plain set skipped the write")
	}
}

func TestImportIfChanged(t *testing.T) {
	fake, home := withTestEnv(t)
	addLocal(t, fake, "custom:SAME", "keep", &store.Meta{EnvVar: "SAME", Storage: store.StorageKeychain})
	addLocal(t, fake, "custom:CHANGED", "old", &store.Meta{EnvVar: "CHANGED", Storage: store.StorageKeychain})
	f := filepath.Join(home, "secrets.env")
	if err := os.WriteFile(f, []byte("export SAME=keep\nexport CHANGED=new\nexport ADDED=added\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := fake.SetCalls()

	out, err := captureStdout(t, nil, func() error { return runCLI(t, "import", f, "--if-changed") })
	if err != nil {
		t.Fatal(err)
	}
	if n := fake.SetCalls() - before; n != 2 {
		t.Fatalf("Set calls = %d, want 2 (changed + added)", n)
	}
	for id, want := range map[string]string{"custom:SAME": "keep", "custom:CHANGED": "new", "custom:ADDED": "added"} {
		if got, _ := fake.Get(id); string(got) != want {
			t.Fatalf("%s holds the wrong value", id)
		}
	}
	if !strings.Contains(out, "unchanged custom:SAME") || !strings.Contains(out, "imported custom:CHANGED") {
		t.Fatalf("stdout missing per-entry lines: %q", out)
	}
	for _, v := range []string{"keep", "new", "added"} {
		if strings.Contains(out, "="+v) || strings.Contains(out, " "+v+"\n") {
			t.Fatal("stdout contains a secret value")
		}
	}
}

func TestImportIfChangedReadFailureWrites(t *testing.T) {
	fake, home := withTestEnv(t)
	addLocal(t, fake, "custom:SAME", "keep", nil)
	fake.FailGet = errors.New("keychain locked")
	f := filepath.Join(home, "secrets.env")
	if err := os.WriteFile(f, []byte("export SAME=keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := fake.SetCalls()
	if _, err := captureStdout(t, nil, func() error { return runCLI(t, "import", f, "--if-changed") }); err != nil {
		t.Fatal(err)
	}
	if fake.SetCalls() != before+1 {
		t.Fatal("a failed read skipped the write")
	}
}
