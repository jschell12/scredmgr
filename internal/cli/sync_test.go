package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jschell12/scredmanager/internal/provider"
	"github.com/jschell12/scredmanager/internal/store"
)

// fakeProvider is an in-memory provider.Provider for sync tests.
type fakeProvider struct {
	name     string
	data     map[string][]byte
	writable bool
	failPut  map[string]error
	failGet  map[string]error
	getCalls int
	putCalls int
}

func (f *fakeProvider) Name() string                { return f.name }
func (f *fakeProvider) Check(context.Context) error { return nil }
func (f *fakeProvider) Writable() bool              { return f.writable }
func (f *fakeProvider) Delete(_ context.Context, id string) error {
	delete(f.data, id)
	return nil
}

func (f *fakeProvider) List(context.Context) ([]string, error) {
	var ids []string
	for k := range f.data {
		ids = append(ids, k)
	}
	return ids, nil
}

func (f *fakeProvider) Get(_ context.Context, id string) ([]byte, error) {
	f.getCalls++
	if err := f.failGet[id]; err != nil {
		return nil, err
	}
	v, ok := f.data[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (f *fakeProvider) Put(_ context.Context, id string, value []byte) error {
	f.putCalls++
	if err := f.failPut[id]; err != nil {
		return err
	}
	f.data[id] = value
	return nil
}

// withFakeProvider installs a providers.json entry named "fake" and swaps
// openProvider to return fp.
func withFakeProvider(t *testing.T, home string, fp *fakeProvider) {
	t.Helper()
	cfg := `{"providers":[{"name":"fake","type":"vault","vault":{"addr":"http://x","mount":"secret"}}]}`
	if err := os.WriteFile(filepath.Join(home, "providers.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := openProvider
	openProvider = func(cfg provider.Config, _ store.Store) (provider.Provider, error) {
		if cfg.Name != "fake" {
			return nil, fmt.Errorf("unexpected provider %q", cfg.Name)
		}
		return fp, nil
	}
	t.Cleanup(func() { openProvider = prev })
}

func addLocal(t *testing.T, fake *store.FakeStore, id, val string, m *store.Meta) {
	t.Helper()
	if m == nil {
		m = &store.Meta{Storage: store.StorageKeychain}
	}
	if m.Storage == store.StorageKeychain {
		if err := fake.Set(id, []byte(val)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.WriteMeta(id, m); err != nil {
		t.Fatal(err)
	}
}

func TestSyncPush(t *testing.T) {
	fake, home := withTestEnv(t)
	fp := &fakeProvider{name: "fake", data: map[string][]byte{}, writable: true}
	withFakeProvider(t, home, fp)

	addLocal(t, fake, "GITHUB_TOKEN", "gh-secret", nil)
	addLocal(t, fake, "ssh:mykey", "passphrase", &store.Meta{Kind: "ssh", Storage: store.StorageKeychain})
	addLocal(t, fake, "legacy", "", &store.Meta{Storage: store.StorageFile})

	if err := runCLI(t, "sync", "fake", "--push"); err != nil {
		t.Fatal(err)
	}
	if string(fp.data["GITHUB_TOKEN"]) != "gh-secret" {
		t.Fatalf("token not pushed: %v", fp.data)
	}
	if _, ok := fp.data["ssh:mykey"]; ok {
		t.Fatal("ssh entry pushed without --only")
	}
	if _, ok := fp.data["legacy"]; ok {
		t.Fatal("file-storage entry pushed")
	}

	// ssh entry pushes when explicitly named in --only
	if err := runCLI(t, "sync", "fake", "--push", "--only", "ssh:mykey"); err != nil {
		t.Fatal(err)
	}
	if string(fp.data["ssh:mykey"]) != "passphrase" {
		t.Fatal("ssh entry not pushed via --only")
	}
}

func TestSyncPushDryRunFetchesNothing(t *testing.T) {
	fake, home := withTestEnv(t)
	fp := &fakeProvider{name: "fake", data: map[string][]byte{}, writable: true}
	withFakeProvider(t, home, fp)
	addLocal(t, fake, "A", "v", nil)

	if err := runCLI(t, "sync", "fake", "--push", "--dry-run"); err != nil {
		t.Fatal(err)
	}
	if fp.putCalls != 0 || len(fp.data) != 0 {
		t.Fatalf("dry-run transferred data: puts=%d data=%v", fp.putCalls, fp.data)
	}
}

func TestSyncPushReadOnlyRefused(t *testing.T) {
	_, home := withTestEnv(t)
	fp := &fakeProvider{name: "fake", data: map[string][]byte{}, writable: false}
	withFakeProvider(t, home, fp)
	if err := runCLI(t, "sync", "fake", "--push"); err == nil {
		t.Fatal("push to read-only provider not refused")
	}
}

func TestSyncPushPartialFailure(t *testing.T) {
	fake, home := withTestEnv(t)
	fp := &fakeProvider{
		name: "fake", data: map[string][]byte{}, writable: true,
		failPut: map[string]error{"BAD": errors.New("remote boom")},
	}
	withFakeProvider(t, home, fp)
	addLocal(t, fake, "BAD", "v1", nil)
	addLocal(t, fake, "GOOD", "v2", nil)

	err := runCLI(t, "sync", "fake", "--push")
	if err == nil {
		t.Fatal("expected failure exit")
	}
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != exitError {
		t.Fatalf("expected exitCodeError(1), got %v", err)
	}
	if string(fp.data["GOOD"]) != "v2" {
		t.Fatal("good entry should still push despite sibling failure")
	}
}

func TestSyncPull(t *testing.T) {
	fake, home := withTestEnv(t)
	fp := &fakeProvider{name: "fake", writable: true, data: map[string][]byte{
		"REMOTE_TOKEN": []byte("r-secret"),
		"bad/id":       []byte("nope"),
	}}
	withFakeProvider(t, home, fp)

	if err := runCLI(t, "sync", "fake", "--pull"); err != nil {
		t.Fatal(err)
	}
	got, err := fake.Get("REMOTE_TOKEN")
	if err != nil || string(got) != "r-secret" {
		t.Fatalf("pull: %v %q", err, got)
	}
	m, err := store.ReadMeta("REMOTE_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if m.SyncedFrom != "fake" || m.SyncedAt == "" || m.Storage != store.StorageKeychain {
		t.Fatalf("bad meta: %+v", m)
	}
	// invalid remote id must not land locally
	if _, err := fake.Get("bad/id"); err == nil {
		t.Fatal("invalid id pulled into store")
	}
}

func TestSyncPullSkipsExistingUnlessOverwrite(t *testing.T) {
	fake, home := withTestEnv(t)
	fp := &fakeProvider{name: "fake", writable: true, data: map[string][]byte{
		"X": []byte("remote"),
	}}
	withFakeProvider(t, home, fp)
	addLocal(t, fake, "X", "local", nil)

	if err := runCLI(t, "sync", "fake", "--pull"); err != nil {
		t.Fatal(err)
	}
	got, _ := fake.Get("X")
	if string(got) != "local" {
		t.Fatalf("existing entry overwritten without --overwrite: %q", got)
	}

	if err := runCLI(t, "sync", "fake", "--pull", "--overwrite"); err != nil {
		t.Fatal(err)
	}
	got, _ = fake.Get("X")
	if string(got) != "remote" {
		t.Fatalf("--overwrite did not replace: %q", got)
	}
}

func TestSyncPullDryRunFetchesNothing(t *testing.T) {
	fake, home := withTestEnv(t)
	fp := &fakeProvider{name: "fake", writable: true, data: map[string][]byte{
		"Y": []byte("v"),
	}}
	withFakeProvider(t, home, fp)

	if err := runCLI(t, "sync", "fake", "--pull", "--dry-run"); err != nil {
		t.Fatal(err)
	}
	if fp.getCalls != 0 {
		t.Fatalf("dry-run fetched values: %d gets", fp.getCalls)
	}
	if _, err := fake.Get("Y"); err == nil {
		t.Fatal("dry-run wrote to store")
	}
}

func TestSyncPullRollbackOnMetaFailure(t *testing.T) {
	fake, home := withTestEnv(t)
	fp := &fakeProvider{name: "fake", writable: true, data: map[string][]byte{
		"Z": []byte("v"),
	}}
	withFakeProvider(t, home, fp)

	// Make meta writes fail by pointing home at a read-only dir after setup.
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(home, 0o700) })

	err := runCLI(t, "sync", "fake", "--pull")
	if err == nil {
		t.Fatal("expected failure")
	}
	if _, gerr := fake.Get("Z"); gerr == nil {
		t.Fatal("keychain orphan left after meta-write failure")
	}
}

func TestSyncDirectionRequired(t *testing.T) {
	_, home := withTestEnv(t)
	withFakeProvider(t, home, &fakeProvider{name: "fake", data: map[string][]byte{}})
	if err := runCLI(t, "sync", "fake"); err == nil {
		t.Fatal("expected error with no direction")
	}
	if err := runCLI(t, "sync", "fake", "--push", "--pull"); err == nil {
		t.Fatal("expected error with both directions")
	}
}

func TestSyncOnlyFilter(t *testing.T) {
	fake, home := withTestEnv(t)
	fp := &fakeProvider{name: "fake", data: map[string][]byte{}, writable: true}
	withFakeProvider(t, home, fp)
	addLocal(t, fake, "KEEP", "k", nil)
	addLocal(t, fake, "SKIP", "s", nil)

	if err := runCLI(t, "sync", "fake", "--push", "--only", "KEEP"); err != nil {
		t.Fatal(err)
	}
	if _, ok := fp.data["SKIP"]; ok {
		t.Fatal("--only did not filter")
	}
	if string(fp.data["KEEP"]) != "k" {
		t.Fatal("--only entry not pushed")
	}
}

func TestSyncUnknownProvider(t *testing.T) {
	_, home := withTestEnv(t)
	withFakeProvider(t, home, &fakeProvider{name: "fake", data: map[string][]byte{}})
	if err := runCLI(t, "sync", "nope", "--push"); err == nil {
		t.Fatal("expected unknown-provider error")
	}
}
