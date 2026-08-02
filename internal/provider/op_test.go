package provider

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// call records one Runner invocation.
type call struct {
	name  string
	args  []string
	stdin []byte
}

// fakeRunner scripts stdout/err responses keyed by the joined argv.
type fakeRunner struct {
	calls []call
	// respond maps a substring of the joined argv to (stdout, err).
	stdout map[string][]byte
	errs   map[string]error
}

func (f *fakeRunner) run(_ context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	f.calls = append(f.calls, call{name: name, args: args, stdin: stdin})
	joined := strings.Join(args, " ")
	for sub, err := range f.errs {
		if strings.Contains(joined, sub) {
			return nil, err
		}
	}
	for sub, out := range f.stdout {
		if strings.Contains(joined, sub) {
			return out, nil
		}
	}
	return nil, nil
}

// assertNoSecretOnArgv fails if any recorded call carries the secret on argv.
func assertNoSecretOnArgv(t *testing.T, f *fakeRunner, secret string) {
	t.Helper()
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c.args, " "), secret) {
			t.Fatalf("secret leaked on argv: %s %v", c.name, c.args)
		}
	}
}

func newTestOp(f *fakeRunner) *Op {
	return NewOp("op-test", OpCfg{Vault: "Private", ItemPrefix: "sm/"}, f.run)
}

func TestOpPutStdinOnly(t *testing.T) {
	f := &fakeRunner{}
	o := newTestOp(f)
	secret := "sup3r-s3cret-value"
	if err := o.Put(context.Background(), "github", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	assertNoSecretOnArgv(t, f, secret)

	if len(f.calls) != 2 {
		t.Fatalf("want delete+create, got %d calls: %+v", len(f.calls), f.calls)
	}
	del, create := f.calls[0], f.calls[1]
	if !strings.Contains(strings.Join(del.args, " "), "item delete sm/github") {
		t.Fatalf("first call not delete: %v", del.args)
	}
	joined := strings.Join(create.args, " ")
	if !strings.Contains(joined, "item create") || !strings.Contains(joined, "--vault Private") {
		t.Fatalf("second call not create: %v", create.args)
	}
	if !strings.Contains(string(create.stdin), secret) {
		t.Fatal("secret not in create stdin payload")
	}
	if !strings.Contains(string(create.stdin), `"title":"sm/github"`) {
		t.Fatalf("bad item title in payload: %s", create.stdin)
	}
}

func TestOpPutCreateFails(t *testing.T) {
	f := &fakeRunner{errs: map[string]error{"item create": errors.New("boom")}}
	if err := newTestOp(f).Put(context.Background(), "x", []byte("v")); err == nil {
		t.Fatal("create failure not surfaced")
	}
}

func TestOpGet(t *testing.T) {
	f := &fakeRunner{stdout: map[string][]byte{"item get": []byte("tok-abc\n")}}
	got, err := newTestOp(f).Get(context.Background(), "github")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "tok-abc" {
		t.Fatalf("got %q", got)
	}
	joined := strings.Join(f.calls[0].args, " ")
	for _, want := range []string{"item get sm/github", "--fields label=password", "--reveal"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("argv missing %q: %v", want, f.calls[0].args)
		}
	}
}

func TestOpGetEmpty(t *testing.T) {
	f := &fakeRunner{stdout: map[string][]byte{"item get": []byte("\n")}}
	if _, err := newTestOp(f).Get(context.Background(), "x"); err == nil {
		t.Fatal("empty field not an error")
	}
}

func TestOpListFiltersPrefix(t *testing.T) {
	f := &fakeRunner{stdout: map[string][]byte{
		"item list": []byte(`[{"title":"sm/github"},{"title":"sm/jira"},{"title":"unrelated"}]`),
	}}
	ids, err := newTestOp(f).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "github" || ids[1] != "jira" {
		t.Fatalf("ids: %v", ids)
	}
}

func TestOpCheckAndAccountFlag(t *testing.T) {
	f := &fakeRunner{}
	o := NewOp("t", OpCfg{Vault: "V", Account: "my.1password.com"}, f.run)
	if err := o.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls[0].args, " ")
	if !strings.Contains(joined, "whoami") || !strings.Contains(joined, "--account my.1password.com") {
		t.Fatalf("argv: %v", f.calls[0].args)
	}

	f2 := &fakeRunner{errs: map[string]error{"whoami": errors.New("not signed in")}}
	if err := NewOp("t", OpCfg{Vault: "V"}, f2.run).Check(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "op signin") {
		t.Fatalf("expected signin hint, got %v", err)
	}
}

func TestOpDelete(t *testing.T) {
	f := &fakeRunner{}
	if err := newTestOp(f).Delete(context.Background(), "github"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.calls[0].args, " "), "item delete sm/github --vault Private") {
		t.Fatalf("argv: %v", f.calls[0].args)
	}
}
