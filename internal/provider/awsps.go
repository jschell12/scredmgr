package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jschell12/scredmgr/internal/safety"
)

// AWSPS stores secrets in AWS SSM Parameter Store as SecureString parameters
// named "<prefix><id>" (prefix conventionally "/scredmgr/").
type AWSPS struct {
	name string
	awsCLI
}

// NewAWSPS returns a Parameter Store provider backed by run.
func NewAWSPS(name string, cfg AWSCfg, run Runner) *AWSPS {
	return &AWSPS{name: name, awsCLI: awsCLI{cfg: cfg, run: run}}
}

func (p *AWSPS) Name() string   { return p.name }
func (p *AWSPS) Writable() bool { return true }

func (p *AWSPS) paramName(id string) string { return p.cfg.Prefix + id }

// path is the prefix as a parameter path (no trailing slash, "/" fallback).
func (p *AWSPS) path() string {
	pt := strings.TrimRight(p.cfg.Prefix, "/")
	if pt == "" {
		return "/"
	}
	return pt
}

func (p *AWSPS) Check(ctx context.Context) error { return p.check(ctx) }

func (p *AWSPS) List(ctx context.Context) ([]string, error) {
	// Non-recursive: single level only, matching the other providers.
	out, err := p.run(ctx, "aws", p.args("ssm", "get-parameters-by-path",
		"--path", p.path(), "--query", "Parameters[].Name", "--output", "json"), nil)
	if err != nil {
		return nil, err
	}
	var names []string
	if err := json.Unmarshal(out, &names); err != nil {
		return nil, fmt.Errorf("aws-ps list: parse: %w", err)
	}
	var ids []string
	for _, n := range names {
		ids = append(ids, strings.TrimPrefix(n, p.cfg.Prefix))
	}
	return ids, nil
}

func (p *AWSPS) Get(ctx context.Context, id string) ([]byte, error) {
	out, err := p.run(ctx, "aws", p.args("ssm", "get-parameter",
		"--name", p.paramName(id), "--with-decryption",
		"--query", "Parameter.Value", "--output", "text"), nil)
	if err != nil {
		return nil, err
	}
	secret := bytes.TrimRight(out, "\n")
	safety.Track(secret)
	return secret, nil
}

// Put writes a SecureString with Overwrite. The value would leak on argv via
// --value, so the payload is piped via --cli-input-json file:///dev/stdin.
func (p *AWSPS) Put(ctx context.Context, id string, value []byte) error {
	safety.Track(value)
	body, err := json.Marshal(map[string]any{
		"Name":      p.paramName(id),
		"Value":     string(value),
		"Type":      "SecureString",
		"Overwrite": true,
	})
	if err != nil {
		return err
	}
	if _, err := p.run(ctx, "aws",
		p.args(append([]string{"ssm", "put-parameter"}, stdinJSON...)...), body); err != nil {
		return fmt.Errorf("aws-ps put %s: %w", id, err)
	}
	return nil
}

func (p *AWSPS) Delete(ctx context.Context, id string) error {
	_, err := p.run(ctx, "aws", p.args("ssm", "delete-parameter", "--name", p.paramName(id)), nil)
	return err
}
