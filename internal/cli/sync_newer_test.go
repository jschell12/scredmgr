package cli

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jschell12/scredmgr/internal/provider"
	"github.com/jschell12/scredmgr/internal/store"
)

// timedProvider adds provider.Timestamped to fakeProvider: times holds the
// write time of each remote entry's current value.
type timedProvider struct {
	*fakeProvider
	times     map[string]time.Time
	deleted   map[string]bool
	metaCalls map[string]int
}

func (p *timedProvider) UpdatedAt(_ context.Context, id string) (time.Time, error) {
	p.metaCalls[id]++
	if p.deleted[id] {
		return time.Time{}, provider.ErrNoCurrentValue
	}
	t, ok := p.times[id]
	if !ok {
		return time.Time{}, errors.New("not found")
	}
	return t, nil
}

func newTimed(data map[string][]byte, times map[string]time.Time) *timedProvider {
	return &timedProvider{
		fakeProvider: &fakeProvider{name: "fake", writable: true, data: data},
		times:        times,
		deleted:      map[string]bool{},
		metaCalls:    map[string]int{},
	}
}

func withTimedProvider(t *testing.T, home string, tp *timedProvider) {
	t.Helper()
	withFakeProvider(t, home, tp.fakeProvider)
	openProvider = func(cfg provider.Config, _ store.Store) (provider.Provider, error) {
		return tp, nil
	}
}

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestPullNewerReplacesOlderLocal(t *testing.T) {
	fake, home := withTestEnv(t)
	tp := newTimed(
		map[string][]byte{"custom:TOKEN": []byte("pasted-on-phone")},
		map[string]time.Time{"custom:TOKEN": ts("2026-10-19T12:00:00Z")},
	)
	withTimedProvider(t, home, tp)
	// Set locally an hour before the remote write, with an env var to keep.
	addLocal(t, fake, "custom:TOKEN", "old-local", &store.Meta{
		Storage: store.StorageKeychain, CreatedAt: "2026-10-19T11:00:00Z", EnvVar: "TOKEN",
	})

	if err := runCLI(t, "sync", "fake", "--pull", "--newer"); err != nil {
		t.Fatal(err)
	}
	got, _ := fake.Get("custom:TOKEN")
	if string(got) != "pasted-on-phone" {
		t.Fatalf("newer remote not pulled: %q", got)
	}
	m, _ := store.ReadMeta("custom:TOKEN")
	if m.SyncedFrom != "fake" || m.EnvVar != "TOKEN" {
		t.Fatalf("meta after pull: %+v", m)
	}
}

func TestPullNewerKeepsNewerLocal(t *testing.T) {
	fake, home := withTestEnv(t)
	tp := newTimed(
		map[string][]byte{"custom:TOKEN": []byte("stale-remote")},
		map[string]time.Time{"custom:TOKEN": ts("2026-10-19T12:00:00Z")},
	)
	withTimedProvider(t, home, tp)
	// Rotated locally one second after the remote copy was written.
	addLocal(t, fake, "custom:TOKEN", "rotated-locally", &store.Meta{
		Storage: store.StorageKeychain, CreatedAt: "2026-10-19T12:00:01Z",
	})

	if err := runCLI(t, "sync", "fake", "--pull", "--newer"); err != nil {
		t.Fatal(err)
	}
	got, _ := fake.Get("custom:TOKEN")
	if string(got) != "rotated-locally" {
		t.Fatalf("newer local value overwritten: %q", got)
	}
	if tp.getCalls != 0 {
		t.Fatalf("value fetched for a kept-local entry: %d gets", tp.getCalls)
	}
	res := pullResults(t, "--newer")
	if res["custom:TOKEN"] != "kept-local" {
		t.Fatalf("want kept-local reported, got %q", res["custom:TOKEN"])
	}
}

func TestPullNewerSameInstantKeepsLocal(t *testing.T) {
	// Boundary: equal timestamps are not "newer"; local wins.
	fake, home := withTestEnv(t)
	tp := newTimed(
		map[string][]byte{"custom:TOKEN": []byte("remote")},
		map[string]time.Time{"custom:TOKEN": ts("2026-10-19T12:00:00Z")},
	)
	withTimedProvider(t, home, tp)
	addLocal(t, fake, "custom:TOKEN", "local", &store.Meta{
		Storage: store.StorageKeychain, CreatedAt: "2026-10-19T12:00:00Z",
	})
	if err := runCLI(t, "sync", "fake", "--pull", "--newer"); err != nil {
		t.Fatal(err)
	}
	if got, _ := fake.Get("custom:TOKEN"); string(got) != "local" {
		t.Fatalf("equal-time remote overwrote local: %q", got)
	}
}

func TestPullNewerUnchangedAfterOwnPull(t *testing.T) {
	fake, home := withTestEnv(t)
	tp := newTimed(
		map[string][]byte{"proj/KEY": []byte("v1")},
		map[string]time.Time{"proj/KEY": ts("2026-10-19T12:00:00Z")},
	)
	withTimedProvider(t, home, tp)
	addLocal(t, fake, "proj/KEY", "v1", &store.Meta{
		Storage: store.StorageKeychain, CreatedAt: "2026-10-19T12:00:30Z",
		SyncedFrom: "fake", SyncedAt: "2026-10-19T12:00:30Z",
	})
	if res := pullResults(t, "--newer"); res["proj/KEY"] != "unchanged" {
		t.Fatalf("want unchanged, got %q", res["proj/KEY"])
	}
	if tp.getCalls != 0 {
		t.Fatalf("steady state fetched a value: %d gets", tp.getCalls)
	}
}

func TestPullNewerSteadyStateSurvivesSkewAndSamesecond(t *testing.T) {
	// Pulled in the same second the remote was written (local stamps are
	// second precision), on a machine whose clock runs behind the provider.
	// The local times both read as older than the remote write; RemoteAt
	// must still make the next run a no-op rather than a fetch every run.
	fake, home := withTestEnv(t)
	written := time.Date(2026, 10, 19, 12, 0, 5, 800_000_000, time.UTC)
	tp := newTimed(
		map[string][]byte{"custom:TOKEN": []byte("phone")},
		map[string]time.Time{"custom:TOKEN": written},
	)
	withTimedProvider(t, home, tp)
	addLocal(t, fake, "custom:TOKEN", "phone", &store.Meta{
		Storage: store.StorageKeychain, CreatedAt: "2026-10-19T12:00:03Z",
		SyncedFrom: "fake", SyncedAt: "2026-10-19T12:00:03Z",
		RemoteAt: written.Format(time.RFC3339Nano),
	})
	if res := pullResults(t, "--newer"); res["custom:TOKEN"] != "unchanged" {
		t.Fatalf("want unchanged, got %q", res["custom:TOKEN"])
	}
	if tp.getCalls != 0 {
		t.Fatalf("steady state fetched a value: %d gets", tp.getCalls)
	}
	// One nanosecond later remotely is a new write and must be considered.
	tp.times["custom:TOKEN"] = written.Add(time.Nanosecond)
	tp.data["custom:TOKEN"] = []byte("phone-2")
	if res := pullResults(t, "--newer"); res["custom:TOKEN"] != "pulled" {
		t.Fatalf("newer remote after RemoteAt: want pulled, got %q", res["custom:TOKEN"])
	}
	m, _ := store.ReadMeta("custom:TOKEN")
	if m.RemoteAt != written.Add(time.Nanosecond).Format(time.RFC3339Nano) {
		t.Fatalf("RemoteAt not advanced: %q", m.RemoteAt)
	}
}

func TestPullNewerSameValueRecordsProvenanceOnly(t *testing.T) {
	// Local set, then pushed: the remote copy is newer but identical.
	fake, home := withTestEnv(t)
	tp := newTimed(
		map[string][]byte{"custom:TOKEN": []byte("same")},
		map[string]time.Time{"custom:TOKEN": ts("2026-10-19T12:00:00Z")},
	)
	withTimedProvider(t, home, tp)
	addLocal(t, fake, "custom:TOKEN", "same", &store.Meta{
		Storage: store.StorageKeychain, CreatedAt: "2026-10-19T11:59:00Z", Label: "keep me",
	})
	if res := pullResults(t, "--newer"); res["custom:TOKEN"] != "unchanged" {
		t.Fatalf("want unchanged, got %q", res["custom:TOKEN"])
	}
	m, _ := store.ReadMeta("custom:TOKEN")
	if m.SyncedFrom != "fake" || m.SyncedAt == "" || m.RemoteAt == "" || m.CreatedAt != "2026-10-19T11:59:00Z" || m.Label != "keep me" {
		t.Fatalf("provenance not recorded or meta clobbered: %+v", m)
	}
	// Second run: now current, no value fetched.
	tp.getCalls = 0
	if res := pullResults(t, "--newer"); res["custom:TOKEN"] != "unchanged" {
		t.Fatalf("second run: %q", res["custom:TOKEN"])
	}
	if tp.getCalls != 0 {
		t.Fatalf("second run fetched a value: %d", tp.getCalls)
	}
}

func TestPullNewerKeepsLocalWithoutTimestamp(t *testing.T) {
	fake, home := withTestEnv(t)
	tp := newTimed(
		map[string][]byte{"custom:OLD": []byte("remote")},
		map[string]time.Time{"custom:OLD": ts("2026-10-19T12:00:00Z")},
	)
	withTimedProvider(t, home, tp)
	addLocal(t, fake, "custom:OLD", "local", nil) // no createdAt at all
	if res := pullResults(t, "--newer"); res["custom:OLD"] != "kept-local" {
		t.Fatalf("want kept-local, got %q", res["custom:OLD"])
	}
	if got, _ := fake.Get("custom:OLD"); string(got) != "local" {
		t.Fatalf("untimestamped local overwritten: %q", got)
	}
}

func TestPullSinceSkipsOlderAbsentEntries(t *testing.T) {
	// The resurrection case: an entry deleted locally on purpose still sits
	// in the remote from an old push. Only entries written after --since land.
	fake, home := withTestEnv(t)
	tp := newTimed(
		map[string][]byte{
			"custom:DELETED_ON_PURPOSE": []byte("redacted"),
			"custom:NEW_FROM_PHONE":     []byte("fresh"),
		},
		map[string]time.Time{
			"custom:DELETED_ON_PURPOSE": ts("2026-08-02T12:00:00Z"),
			"custom:NEW_FROM_PHONE":     ts("2026-10-19T12:00:00Z"),
		},
	)
	withTimedProvider(t, home, tp)
	if err := runCLI(t, "sync", "fake", "--pull", "--newer", "--since", "2026-10-19T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.Get("custom:DELETED_ON_PURPOSE"); err == nil {
		t.Fatal("entry written before --since was resurrected")
	}
	if got, _ := fake.Get("custom:NEW_FROM_PHONE"); string(got) != "fresh" {
		t.Fatalf("entry written after --since not pulled: %q", got)
	}
}

func TestPullIncludeNeverTouchesOtherIDs(t *testing.T) {
	fake, home := withTestEnv(t)
	tp := newTimed(
		map[string][]byte{
			"vault-token":  []byte("must-not-move"),
			"custom:A":     []byte("a"),
			"proj/B":       []byte("b"),
			"proj/deep/C":  []byte("c"),
			"ROOT_NOCOLON": []byte("r"),
		},
		map[string]time.Time{
			"vault-token": ts("2026-10-19T12:00:00Z"), "custom:A": ts("2026-10-19T12:00:00Z"),
			"proj/B": ts("2026-10-19T12:00:00Z"), "proj/deep/C": ts("2026-10-19T12:00:00Z"),
			"ROOT_NOCOLON": ts("2026-10-19T12:00:00Z"),
		},
	)
	withTimedProvider(t, home, tp)
	if err := runCLI(t, "sync", "fake", "--pull", "--newer", "--include", "custom:*,*/*"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"vault-token", "proj/deep/C", "ROOT_NOCOLON"} {
		if _, err := fake.Get(id); err == nil {
			t.Fatalf("%s pulled despite --include", id)
		}
		if tp.metaCalls[id] != 0 {
			t.Fatalf("%s metadata read despite --include", id)
		}
	}
	for _, id := range []string{"custom:A", "proj/B"} {
		if _, err := fake.Get(id); err != nil {
			t.Fatalf("%s not pulled: %v", id, err)
		}
	}
}

func TestPullNewerSkipsDeletedRemote(t *testing.T) {
	fake, home := withTestEnv(t)
	tp := newTimed(map[string][]byte{"custom:X": []byte("v")}, map[string]time.Time{})
	tp.deleted["custom:X"] = true
	withTimedProvider(t, home, tp)
	if res := pullResults(t, "--newer"); res["custom:X"] != "skipped" {
		t.Fatalf("want skipped, got %q", res["custom:X"])
	}
	if _, err := fake.Get("custom:X"); err == nil {
		t.Fatal("deleted remote version pulled")
	}
}

func TestPullNewerMetaFailureKeepsExistingSecret(t *testing.T) {
	fake, home := withTestEnv(t)
	tp := newTimed(
		map[string][]byte{"custom:TOKEN": []byte("new")},
		map[string]time.Time{"custom:TOKEN": ts("2026-10-19T12:00:00Z")},
	)
	withTimedProvider(t, home, tp)
	addLocal(t, fake, "custom:TOKEN", "old", &store.Meta{
		Storage: store.StorageKeychain, CreatedAt: "2026-10-19T11:00:00Z",
	})
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(home, 0o700) })
	if err := runCLI(t, "sync", "fake", "--pull", "--newer"); err == nil {
		t.Fatal("expected failure")
	}
	if _, err := fake.Get("custom:TOKEN"); err != nil {
		t.Fatal("existing entry deleted after a meta-write failure")
	}
}

func TestPullNewerFlagErrors(t *testing.T) {
	_, home := withTestEnv(t)
	withTimedProvider(t, home, newTimed(map[string][]byte{}, map[string]time.Time{}))
	for _, args := range [][]string{
		{"--pull", "--newer", "--overwrite"},
		{"--push", "--newer"},
		{"--push", "--since", "2026-10-19T00:00:00Z"},
		{"--pull", "--since", "yesterday"},
		{"--pull", "--include", "[bad"},
	} {
		if err := runCLI(t, append([]string{"sync", "fake"}, args...)...); err == nil {
			t.Fatalf("%v: expected an error", args)
		}
	}
}

func TestPullNewerNeedsTimestampedProvider(t *testing.T) {
	_, home := withTestEnv(t)
	withFakeProvider(t, home, &fakeProvider{name: "fake", data: map[string][]byte{"A": []byte("v")}})
	err := runCLI(t, "sync", "fake", "--pull", "--newer")
	if err == nil || !strings.Contains(err.Error(), "cannot report write times") {
		t.Fatalf("want unsupported-provider error, got %v", err)
	}
}

// pullResults runs a --json pull and returns id -> action.
func pullResults(t *testing.T, extra ...string) map[string]string {
	t.Helper()
	cfg, err := provider.LoadConfigs()
	if err != nil {
		t.Fatal(err)
	}
	p, err := openProvider(cfg[0], backend)
	if err != nil {
		t.Fatal(err)
	}
	o := pullOpts{}
	for _, a := range extra {
		if a == "--newer" {
			o.newer = true
		}
	}
	results, err := syncPull(context.Background(), p, idFilter{}, o)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range results {
		out[r.ID] = r.Action
	}
	return out
}
