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
	for _, mode := range []string{"--newer", "--create-only"} {
		if res := pullResults(t, mode); res["custom:X"] != "skipped" {
			t.Fatalf("%s: want skipped, got %q", mode, res["custom:X"])
		}
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

// pullResults runs a pull through syncPull and returns id -> action.
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
		switch a {
		case "--newer":
			o.newer = true
		case "--create-only":
			o.createOnly = true
		case "--dry-run":
			o.dryRun = true
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

func TestPullCreateOnlyHoldsExisting(t *testing.T) {
	fake, home := withTestEnv(t)
	tp := newTimed(
		map[string][]byte{"custom:HAVE": []byte("remote-newer"), "custom:NEW": []byte("fresh")},
		map[string]time.Time{"custom:HAVE": ts("2026-10-19T12:00:00Z"), "custom:NEW": ts("2026-10-19T12:00:00Z")},
	)
	withTimedProvider(t, home, tp)
	addLocal(t, fake, "custom:HAVE", "local", &store.Meta{Storage: store.StorageKeychain, CreatedAt: "2026-10-01T00:00:00Z"})
	res := pullResults(t, "--create-only")
	if res["custom:HAVE"] != "held" || res["custom:NEW"] != "pulled" {
		t.Fatalf("results = %v", res)
	}
	if got, _ := fake.Get("custom:HAVE"); string(got) != "local" {
		t.Fatalf("create-only replaced an existing entry: %q", got)
	}
	if tp.metaCalls["custom:HAVE"] != 0 || tp.getCalls != 1 {
		t.Fatalf("held entry was read remotely: meta=%d gets=%d", tp.metaCalls["custom:HAVE"], tp.getCalls)
	}
	if err := runCLI(t, "sync", "fake", "--pull", "--create-only", "--newer"); err == nil {
		t.Fatal("--create-only with --newer: want an error")
	}
}

func TestTombstoneBlocksResurrectionInEveryMode(t *testing.T) {
	removedAt := time.Date(2026, 10, 19, 12, 0, 0, 500, time.UTC)
	for _, mode := range [][]string{{}, {"--newer"}, {"--create-only"}} {
		fake, home := withTestEnv(t)
		tp := newTimed(
			map[string][]byte{"custom:OLD": []byte("stale"), "custom:SAME": []byte("stale"), "custom:LATER": []byte("new")},
			map[string]time.Time{
				"custom:OLD":   removedAt.Add(-time.Hour),
				"custom:SAME":  removedAt, // boundary: written at the removal instant
				"custom:LATER": removedAt.Add(time.Nanosecond),
			},
		)
		withTimedProvider(t, home, tp)
		for _, id := range []string{"custom:OLD", "custom:SAME", "custom:LATER"} {
			if err := store.RecordTombstone(id, removedAt); err != nil {
				t.Fatal(err)
			}
		}
		res := pullResults(t, mode...)
		if res["custom:OLD"] != "skipped" || res["custom:SAME"] != "skipped" || res["custom:LATER"] != "pulled" {
			t.Fatalf("mode %v: results = %v", mode, res)
		}
		if _, err := fake.Get("custom:OLD"); err == nil {
			t.Fatalf("mode %v: tombstoned id recreated", mode)
		}
	}
}

func TestRmRecordsTombstone(t *testing.T) {
	fake, home := withTestEnv(t)
	tp := newTimed(map[string][]byte{"custom:GONE": []byte("stale")}, map[string]time.Time{"custom:GONE": ts("2026-10-19T12:00:00Z")})
	withTimedProvider(t, home, tp)
	addLocal(t, fake, "custom:GONE", "v", &store.Meta{Storage: store.StorageKeychain, CreatedAt: "2026-10-01T00:00:00Z"})
	if err := runCLI(t, "rm", "custom:GONE"); err != nil {
		t.Fatal(err)
	}
	at, ok, err := store.Tombstone("custom:GONE")
	if err != nil || !ok || time.Since(at) > time.Minute {
		t.Fatalf("tombstone = %v %v %v", at, ok, err)
	}
	if res := pullResults(t); res["custom:GONE"] != "skipped" {
		t.Fatalf("plain pull after rm: %q", res["custom:GONE"])
	}
	ids, _ := store.ListIDs()
	for _, id := range ids {
		if strings.Contains(id, "tombstone") {
			t.Fatalf("tombstone file listed as an entry: %v", ids)
		}
	}
}

func TestProviderTokenRefNeverSyncs(t *testing.T) {
	fake, home := withTestEnv(t)
	fp := &fakeProvider{name: "fake", writable: true, data: map[string][]byte{"vault-token": []byte("remote-copy"), "custom:A": []byte("a")}}
	withFakeProvider(t, home, fp)
	cfg := `{"providers":[{"name":"fake","type":"vault","vault":{"addr":"http://x","mount":"secret","tokenRef":"vault-token"}}]}`
	if err := os.WriteFile(home+"/providers.json", []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	addLocal(t, fake, "vault-token", "local-token", nil)
	for _, args := range [][]string{
		{"--pull", "--overwrite", "--include", "*"},
		{"--pull", "--overwrite", "--only", "vault-token"},
		{"--push", "--include", "*"},
		{"--push", "--only", "vault-token"},
	} {
		fp.data["vault-token"] = []byte("remote-copy")
		if err := runCLI(t, append([]string{"sync", "fake"}, args...)...); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if got, _ := fake.Get("vault-token"); string(got) != "local-token" {
			t.Fatalf("%v: local token replaced: %q", args, got)
		}
		if string(fp.data["vault-token"]) != "remote-copy" {
			t.Fatalf("%v: token pushed to its own provider", args)
		}
	}
	if got, _ := fake.Get("custom:A"); string(got) != "a" {
		t.Fatal("ordinary id not pulled alongside")
	}
}

func TestPullNewerReplacePreservesEntryFields(t *testing.T) {
	fake, home := withTestEnv(t)
	tp := newTimed(map[string][]byte{"ssh:deploy": []byte("new-pass")}, map[string]time.Time{"ssh:deploy": ts("2026-10-19T12:00:00Z")})
	withTimedProvider(t, home, tp)
	addLocal(t, fake, "ssh:deploy", "old-pass", &store.Meta{
		Storage: store.StorageKeychain, CreatedAt: "2026-10-01T00:00:00Z",
		Kind: "ssh", KeyPath: "/k/deploy", Fingerprint: "SHA256:x", PublicKey: "ssh-ed25519 AAAA",
		ExpiresAt: "2027-01-01T00:00:00Z", Label: "L", EnvVar: "E",
	})
	if res := pullResults(t, "--newer"); res["ssh:deploy"] != "pulled" {
		t.Fatalf("got %v", res)
	}
	m, _ := store.ReadMeta("ssh:deploy")
	if m.Kind != "ssh" || m.KeyPath != "/k/deploy" || m.Fingerprint != "SHA256:x" || m.PublicKey != "ssh-ed25519 AAAA" ||
		m.ExpiresAt != "2027-01-01T00:00:00Z" || m.Label != "L" || m.EnvVar != "E" {
		t.Fatalf("fields lost on replace: %+v", m)
	}
}

func TestLocalStampsHaveNanoseconds(t *testing.T) {
	fake, home := withTestEnv(t)
	_ = fake
	tp := newTimed(map[string][]byte{"custom:N": []byte("v")}, map[string]time.Time{"custom:N": ts("2026-10-19T12:00:00Z")})
	withTimedProvider(t, home, tp)
	pullResults(t)
	m, _ := store.ReadMeta("custom:N")
	for _, s := range []string{m.CreatedAt, m.SyncedAt} {
		if _, err := time.Parse(time.RFC3339Nano, s); err != nil || !strings.Contains(s, ".") {
			t.Fatalf("stamp %q lacks sub-second precision", s)
		}
	}
	// set, login, ssh, import and receive all stamp through store.Stamp.
	if s := store.Stamp(time.Date(2026, 10, 19, 12, 0, 0, 123456789, time.UTC)); s != "2026-10-19T12:00:00.123456789Z" {
		t.Fatalf("Stamp = %q", s)
	}
}

func TestDryRunMatchesRealRun(t *testing.T) {
	fake, home := withTestEnv(t)
	removedAt := ts("2026-10-19T12:00:00Z")
	tp := newTimed(
		map[string][]byte{"custom:STEADY": []byte("v"), "custom:LOCALNEW": []byte("r"), "custom:TOMB": []byte("r"), "custom:FRESH": []byte("f")},
		map[string]time.Time{
			"custom:STEADY": ts("2026-10-19T11:00:00.5Z"), "custom:LOCALNEW": ts("2026-10-19T11:00:00Z"),
			"custom:TOMB": ts("2026-10-19T11:00:00Z"), "custom:FRESH": ts("2026-10-19T13:00:00Z"),
		},
	)
	withTimedProvider(t, home, tp)
	addLocal(t, fake, "custom:STEADY", "v", &store.Meta{Storage: store.StorageKeychain, CreatedAt: "2026-10-19T11:00:00Z",
		SyncedFrom: "fake", SyncedAt: "2026-10-19T11:00:00Z", RemoteAt: "2026-10-19T11:00:00.5Z"})
	addLocal(t, fake, "custom:LOCALNEW", "l", &store.Meta{Storage: store.StorageKeychain, CreatedAt: "2026-10-19T11:30:00Z"})
	if err := store.RecordTombstone("custom:TOMB", removedAt); err != nil {
		t.Fatal(err)
	}
	dry := pullResults(t, "--newer", "--dry-run")
	if tp.getCalls != 0 {
		t.Fatalf("dry-run fetched values: %d", tp.getCalls)
	}
	real := pullResults(t, "--newer")
	for id, want := range real {
		got := dry[id]
		if want == "pulled" {
			want = "would-pull"
		}
		if got != want {
			t.Fatalf("%s: dry-run %q, real run %q", id, got, real[id])
		}
	}
	if dry["custom:STEADY"] != "unchanged" {
		t.Fatalf("steady entry under dry-run: %q", dry["custom:STEADY"])
	}
}

func TestPushRecordsRemoteAtSoDryRunSeesUnchanged(t *testing.T) {
	fake, home := withTestEnv(t)
	tp := newTimed(map[string][]byte{}, map[string]time.Time{})
	withTimedProvider(t, home, tp)
	addLocal(t, fake, "custom:P", "v", &store.Meta{Storage: store.StorageKeychain, CreatedAt: "2026-10-19T11:00:00Z"})
	// The fake records a write time when the value is put.
	tp.times["custom:P"] = ts("2026-10-19T12:00:00Z")
	if err := runCLI(t, "sync", "fake", "--push", "--only", "custom:P"); err != nil {
		t.Fatal(err)
	}
	if res := pullResults(t, "--newer", "--dry-run"); res["custom:P"] != "unchanged" {
		t.Fatalf("after push, dry-run --newer = %q", res["custom:P"])
	}
}
