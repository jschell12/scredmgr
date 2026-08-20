package provider

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func newTestSM(f *fakeRunner) *AWSSM {
	return NewAWSSM("sm-test", AWSCfg{Region: "us-east-1", Profile: "personal", Prefix: "scredmgr/"}, f.run)
}

func newTestPS(f *fakeRunner) *AWSPS {
	return NewAWSPS("ps-test", AWSCfg{Region: "us-east-1", Prefix: "/scredmgr/"}, f.run)
}

func TestAWSSMPutStdinOnly(t *testing.T) {
	f := &fakeRunner{}
	secret := "sm-sup3r-secret"
	if err := newTestSM(f).Put(context.Background(), "github", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	assertNoSecretOnArgv(t, f, secret)
	if len(f.calls) != 1 {
		t.Fatalf("want 1 create call, got %d", len(f.calls))
	}
	joined := strings.Join(f.calls[0].args, " ")
	for _, want := range []string{"secretsmanager create-secret", "--cli-input-json file:///dev/stdin",
		"--region us-east-1", "--profile personal"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("argv missing %q: %v", want, f.calls[0].args)
		}
	}
	in := string(f.calls[0].stdin)
	if !strings.Contains(in, `"Name":"scredmgr/github"`) || !strings.Contains(in, secret) {
		t.Fatalf("bad stdin payload: %s", in)
	}
}

func TestAWSSMPutFallsBackToUpdate(t *testing.T) {
	f := &fakeRunner{errs: map[string]error{"create-secret": errors.New("An error occurred (ResourceExistsException)")}}
	secret := "sm-update-secret"
	if err := newTestSM(f).Put(context.Background(), "github", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	assertNoSecretOnArgv(t, f, secret)
	if len(f.calls) != 2 || !strings.Contains(strings.Join(f.calls[1].args, " "), "put-secret-value") {
		t.Fatalf("expected create then put-secret-value: %+v", f.calls)
	}
	if !strings.Contains(string(f.calls[1].stdin), `"SecretId":"scredmgr/github"`) {
		t.Fatalf("bad update payload: %s", f.calls[1].stdin)
	}
}

func TestAWSSMPutOtherErrorSurfaces(t *testing.T) {
	f := &fakeRunner{errs: map[string]error{"create-secret": errors.New("AccessDeniedException")}}
	if err := newTestSM(f).Put(context.Background(), "x", []byte("v")); err == nil {
		t.Fatal("non-exists create error must surface, not fall back")
	}
	if len(f.calls) != 1 {
		t.Fatalf("must not attempt update after access denied: %+v", f.calls)
	}
}

func TestAWSSMGetAndList(t *testing.T) {
	f := &fakeRunner{stdout: map[string][]byte{
		"get-secret-value": []byte("tok-xyz\n"),
		"list-secrets":     []byte(`["scredmgr/github","scredmgr/jira","scredmgr-other"]`),
	}}
	sm := newTestSM(f)
	got, err := sm.Get(context.Background(), "github")
	if err != nil || string(got) != "tok-xyz" {
		t.Fatalf("get: %v %q", err, got)
	}
	if !strings.Contains(strings.Join(f.calls[0].args, " "), "--secret-id scredmgr/github") {
		t.Fatalf("get argv: %v", f.calls[0].args)
	}
	ids, err := sm.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "github" || ids[1] != "jira" {
		t.Fatalf("list: %v", ids)
	}
}

func TestAWSSMDelete(t *testing.T) {
	f := &fakeRunner{}
	if err := newTestSM(f).Delete(context.Background(), "github"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls[0].args, " ")
	if !strings.Contains(joined, "delete-secret --secret-id scredmgr/github --force-delete-without-recovery") {
		t.Fatalf("argv: %v", f.calls[0].args)
	}
}

func TestAWSPSPutStdinOnly(t *testing.T) {
	f := &fakeRunner{}
	secret := "ps-sup3r-secret"
	if err := newTestPS(f).Put(context.Background(), "github", []byte(secret)); err != nil {
		t.Fatal(err)
	}
	assertNoSecretOnArgv(t, f, secret)
	joined := strings.Join(f.calls[0].args, " ")
	if !strings.Contains(joined, "ssm put-parameter --cli-input-json file:///dev/stdin") {
		t.Fatalf("argv: %v", f.calls[0].args)
	}
	in := string(f.calls[0].stdin)
	for _, want := range []string{`"Name":"/scredmgr/github"`, `"Type":"SecureString"`, `"Overwrite":true`, secret} {
		if !strings.Contains(in, want) {
			t.Fatalf("stdin payload missing %q: %s", want, in)
		}
	}
}

func TestAWSPSGetAndList(t *testing.T) {
	f := &fakeRunner{stdout: map[string][]byte{
		"get-parameter ":         []byte("val-123\n"),
		"get-parameters-by-path": []byte(`["/scredmgr/github","/scredmgr/jira"]`),
	}}
	ps := newTestPS(f)
	got, err := ps.Get(context.Background(), "github")
	if err != nil || string(got) != "val-123" {
		t.Fatalf("get: %v %q", err, got)
	}
	joined := strings.Join(f.calls[0].args, " ")
	if !strings.Contains(joined, "--name /scredmgr/github") || !strings.Contains(joined, "--with-decryption") {
		t.Fatalf("get argv: %v", f.calls[0].args)
	}
	ids, err := ps.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "github" || ids[1] != "jira" {
		t.Fatalf("list: %v", ids)
	}
	if !strings.Contains(strings.Join(f.calls[1].args, " "), "--path /scredmgr ") {
		t.Fatalf("list argv: %v", f.calls[1].args)
	}
}

func TestAWSPSDelete(t *testing.T) {
	f := &fakeRunner{}
	if err := newTestPS(f).Delete(context.Background(), "github"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.calls[0].args, " "), "delete-parameter --name /scredmgr/github") {
		t.Fatalf("argv: %v", f.calls[0].args)
	}
}

func TestAWSCheck(t *testing.T) {
	f := &fakeRunner{}
	if err := newTestSM(f).Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.calls[0].args, " "), "sts get-caller-identity") {
		t.Fatalf("argv: %v", f.calls[0].args)
	}
	f2 := &fakeRunner{errs: map[string]error{"get-caller-identity": errors.New("expired")}}
	if err := newTestPS(f2).Check(context.Background()); err == nil || !strings.Contains(err.Error(), "sso login") {
		t.Fatalf("expected sso hint, got %v", err)
	}
}
