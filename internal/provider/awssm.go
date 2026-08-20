package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jschell12/scredmgr/internal/safety"
)

// AWSSM stores secrets in AWS Secrets Manager as "<prefix><id>".
type AWSSM struct {
	name string
	awsCLI
}

// NewAWSSM returns a Secrets Manager provider backed by run.
func NewAWSSM(name string, cfg AWSCfg, run Runner) *AWSSM {
	return &AWSSM{name: name, awsCLI: awsCLI{cfg: cfg, run: run}}
}

func (s *AWSSM) Name() string   { return s.name }
func (s *AWSSM) Writable() bool { return true }

func (s *AWSSM) secretID(id string) string { return s.cfg.Prefix + id }

func (s *AWSSM) Check(ctx context.Context) error { return s.check(ctx) }

func (s *AWSSM) List(ctx context.Context) ([]string, error) {
	args := s.args("secretsmanager", "list-secrets",
		"--query", "SecretList[].Name", "--output", "json")
	if s.cfg.Prefix != "" {
		args = append(args, "--filters", "Key=name,Values="+s.cfg.Prefix)
	}
	out, err := s.run(ctx, "aws", args, nil)
	if err != nil {
		return nil, err
	}
	var names []string
	if err := json.Unmarshal(out, &names); err != nil {
		return nil, fmt.Errorf("aws-sm list: parse: %w", err)
	}
	var ids []string
	for _, n := range names {
		if !strings.HasPrefix(n, s.cfg.Prefix) {
			continue // name filter matches substrings; keep exact-prefix only
		}
		ids = append(ids, strings.TrimPrefix(n, s.cfg.Prefix))
	}
	return ids, nil
}

func (s *AWSSM) Get(ctx context.Context, id string) ([]byte, error) {
	out, err := s.run(ctx, "aws", s.args("secretsmanager", "get-secret-value",
		"--secret-id", s.secretID(id), "--query", "SecretString", "--output", "text"), nil)
	if err != nil {
		return nil, err
	}
	secret := bytes.TrimRight(out, "\n")
	safety.Track(secret)
	return secret, nil
}

// Put creates the secret, falling back to put-secret-value when it already
// exists. `--secret-string` would leak on argv, so both calls pipe their
// payload via --cli-input-json file:///dev/stdin.
func (s *AWSSM) Put(ctx context.Context, id string, value []byte) error {
	safety.Track(value)
	create, err := json.Marshal(map[string]string{
		"Name": s.secretID(id), "SecretString": string(value),
	})
	if err != nil {
		return err
	}
	_, cerr := s.run(ctx, "aws",
		s.args(append([]string{"secretsmanager", "create-secret"}, stdinJSON...)...), create)
	if cerr == nil {
		return nil
	}
	if !strings.Contains(cerr.Error(), "ResourceExistsException") {
		return fmt.Errorf("aws-sm put %s: %w", id, cerr)
	}
	update, err := json.Marshal(map[string]string{
		"SecretId": s.secretID(id), "SecretString": string(value),
	})
	if err != nil {
		return err
	}
	if _, err := s.run(ctx, "aws",
		s.args(append([]string{"secretsmanager", "put-secret-value"}, stdinJSON...)...), update); err != nil {
		return fmt.Errorf("aws-sm put %s: %w", id, err)
	}
	return nil
}

func (s *AWSSM) Delete(ctx context.Context, id string) error {
	_, err := s.run(ctx, "aws", s.args("secretsmanager", "delete-secret",
		"--secret-id", s.secretID(id), "--force-delete-without-recovery"), nil)
	return err
}
