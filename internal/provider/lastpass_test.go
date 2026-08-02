package provider

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func newTestLP(f *fakeRunner) *Lastpass {
	return NewLastpass("lp-test", LastpassCfg{Folder: "scredmanager"}, f.run)
}

func TestLastpassReadOnly(t *testing.T) {
	lp := newTestLP(&fakeRunner{})
	if lp.Writable() {
		t.Fatal("lastpass must not be writable")
	}
	if err := lp.Put(context.Background(), "x", []byte("v")); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("put: %v", err)
	}
	if err := lp.Delete(context.Background(), "x"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("delete: %v", err)
	}
}

func TestLastpassGet(t *testing.T) {
	f := &fakeRunner{stdout: map[string][]byte{"show": []byte("break-glass-pw\n")}}
	got, err := newTestLP(f).Get(context.Background(), "github")
	if err != nil || string(got) != "break-glass-pw" {
		t.Fatalf("get: %v %q", err, got)
	}
	joined := strings.Join(f.calls[0].args, " ")
	if !strings.Contains(joined, "show --password scredmanager/github") {
		t.Fatalf("argv: %v", f.calls[0].args)
	}
}

func TestLastpassGetEmpty(t *testing.T) {
	f := &fakeRunner{stdout: map[string][]byte{"show": []byte("\n")}}
	if _, err := newTestLP(f).Get(context.Background(), "x"); err == nil {
		t.Fatal("empty password not an error")
	}
}

func TestLastpassList(t *testing.T) {
	f := &fakeRunner{stdout: map[string][]byte{"ls": []byte(
		"scredmanager/github\nscredmanager/vault-unseal\nscredmanager\nother/entry\n\n")}}
	ids, err := newTestLP(f).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "github" || ids[1] != "vault-unseal" {
		t.Fatalf("ids: %v", ids)
	}
	joined := strings.Join(f.calls[0].args, " ")
	if !strings.Contains(joined, "ls --format %an scredmanager") {
		t.Fatalf("argv: %v", f.calls[0].args)
	}
}

func TestLastpassCheck(t *testing.T) {
	f := &fakeRunner{}
	if err := newTestLP(f).Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.calls[0].args, " "), "status") {
		t.Fatalf("argv: %v", f.calls[0].args)
	}
	f2 := &fakeRunner{errs: map[string]error{"status": errors.New("not logged in")}}
	if err := newTestLP(f2).Check(context.Background()); err == nil || !strings.Contains(err.Error(), "lpass login") {
		t.Fatalf("expected login hint, got %v", err)
	}
}
