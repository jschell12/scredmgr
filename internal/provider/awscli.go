package provider

import (
	"context"
	"fmt"
)

// awsCLI is the shared plumbing for the aws-sm and aws-ps providers. Driving
// the `aws` CLI (instead of aws-sdk-go-v2) inherits profiles/SSO/region
// handling for free and matches the exec discipline used by the other
// CLI-backed providers.
//
// Secret values never ride on argv: writes go through
// `--cli-input-json file:///dev/stdin` with the payload piped on stdin, reads
// arrive on stdout.
type awsCLI struct {
	cfg AWSCfg
	run Runner
}

// args appends region/profile flags (when configured) to base args.
func (a *awsCLI) args(base ...string) []string {
	if a.cfg.Region != "" {
		base = append(base, "--region", a.cfg.Region)
	}
	if a.cfg.Profile != "" {
		base = append(base, "--profile", a.cfg.Profile)
	}
	return base
}

// check verifies credentials via STS.
func (a *awsCLI) check(ctx context.Context) error {
	if _, err := a.run(ctx, "aws", a.args("sts", "get-caller-identity", "--output", "json"), nil); err != nil {
		return fmt.Errorf("aws auth: %w (hint: check the profile/SSO session, e.g. `aws sso login`)", err)
	}
	return nil
}

// stdinJSON are the argv words that make the aws CLI read its request payload
// from stdin instead of flags.
var stdinJSON = []string{"--cli-input-json", "file:///dev/stdin"}
