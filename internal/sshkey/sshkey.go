// Package sshkey wraps ssh-keygen and ssh-add. Private keys stay as files
// (typically under ~/.ssh); scredmgr owns only the metadata ledger and,
// optionally, the passphrase in the keychain.
//
// Passphrases never touch argv or the environment. ssh-keygen and ssh-add are
// driven via SSH_ASKPASS + SSH_ASKPASS_REQUIRE=force (OpenSSH >= 8.4), with
// scredmgr re-exec'ing itself as the askpass helper: only the entry id
// rides in the environment; the passphrase travels keychain -> helper stdout
// -> the ssh tool's own pipe.
package sshkey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jschell12/scredmgr/internal/safety"
)

// AskpassIDEnv names the environment variable carrying the entry id (never the
// secret) to the re-exec'd askpass helper.
const AskpassIDEnv = "SCREDMGR_ASKPASS_ID"

// execCommand is swapped out in tests.
var execCommand = exec.CommandContext

// KeygenOptions configures one ssh-keygen invocation.
type KeygenOptions struct {
	Type    string // key type, e.g. "ed25519"
	KeyPath string // private key destination; ".pub" is written next to it
	Comment string
	// UseAskpass drives the passphrase via SSH_ASKPASS (extraEnv must carry
	// AskpassEnv). When false, the key is generated without a passphrase.
	UseAskpass bool
}

// Result describes a generated key.
type Result struct {
	KeyPath     string
	PublicKey   string // full public key line
	Fingerprint string // SHA256:...
}

// Keygen runs ssh-keygen. extraEnv is appended to the current environment.
func Keygen(ctx context.Context, opts KeygenOptions, extraEnv []string) (Result, error) {
	args := []string{"-q", "-t", opts.Type, "-f", opts.KeyPath, "-C", opts.Comment}
	if !opts.UseAskpass {
		args = append(args, "-N", "")
	}
	cmd := execCommand(ctx, "ssh-keygen", args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return Result{}, fmt.Errorf("ssh-keygen: %w: %s", err, safety.Redact(strings.TrimSpace(string(out))))
	}
	pub, err := os.ReadFile(opts.KeyPath + ".pub")
	if err != nil {
		return Result{}, err
	}
	fp, err := Fingerprint(ctx, opts.KeyPath+".pub")
	if err != nil {
		return Result{}, err
	}
	return Result{KeyPath: opts.KeyPath, PublicKey: strings.TrimSpace(string(pub)), Fingerprint: fp}, nil
}

// Fingerprint returns the SHA256 fingerprint of a public key file.
func Fingerprint(ctx context.Context, pubPath string) (string, error) {
	out, err := execCommand(ctx, "ssh-keygen", "-lf", pubPath).Output()
	if err != nil {
		return "", fmt.Errorf("ssh-keygen -lf %s: %w", pubPath, err)
	}
	return parseFingerprint(string(out))
}

func parseFingerprint(s string) (string, error) {
	fields := strings.Fields(s)
	if len(fields) < 2 || !strings.HasPrefix(fields[1], "SHA256:") {
		return "", fmt.Errorf("unexpected ssh-keygen -l output: %q", strings.TrimSpace(s))
	}
	return fields[1], nil
}

// AddToAgent registers a key with the ssh agent, storing the passphrase in the
// user's login keychain (--apple-use-keychain). extraEnv carries AskpassEnv
// when the key has a passphrase.
func AddToAgent(ctx context.Context, keyPath string, extraEnv []string) error {
	cmd := execCommand(ctx, "ssh-add", "--apple-use-keychain", keyPath)
	cmd.Env = append(os.Environ(), extraEnv...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ssh-add: %w: %s", err, safety.Redact(strings.TrimSpace(string(out))))
	}
	return nil
}

// AskpassEnv returns the environment entries that make ssh tools call this
// binary back as the askpass helper for the given entry id.
func AskpassEnv(id string) ([]string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return []string{
		"SSH_ASKPASS=" + exe,
		"SSH_ASKPASS_REQUIRE=force",
		AskpassIDEnv + "=" + id,
	}, nil
}

// RandomPassphrase returns n random bytes encoded as base64url (no padding).
func RandomPassphrase(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return []byte(base64.RawURLEncoding.EncodeToString(buf)), nil
}

var versionRe = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)

// CheckOpenSSHVersion fails when the installed OpenSSH predates 8.4, which
// introduced SSH_ASKPASS_REQUIRE (required for the passphrase mechanism).
func CheckOpenSSHVersion(ctx context.Context) error {
	out, _ := execCommand(ctx, "ssh", "-V").CombinedOutput() // ssh -V exits 0 but writes to stderr
	return checkVersionOutput(string(out))
}

func checkVersionOutput(s string) error {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return fmt.Errorf("cannot determine OpenSSH version from %q", strings.TrimSpace(s))
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	if major > 8 || (major == 8 && minor >= 4) {
		return nil
	}
	return fmt.Errorf("OpenSSH %d.%d is too old: passphrase handling needs SSH_ASKPASS_REQUIRE (OpenSSH >= 8.4)", major, minor)
}
