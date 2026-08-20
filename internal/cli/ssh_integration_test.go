//go:build darwin_integration

package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jschell12/scredmgr/internal/store"
)

// TestSSHKeygenPassphraseRoundTrip is the full e2e: build the real binary,
// generate a key with a random passphrase (stored in the REAL keychain), then
// prove the passphrase opens the key by running `ssh-keygen -yf` with the
// binary as SSH_ASKPASS. Cleans up keychain, metadata, and key files.
func TestSSHKeygenPassphraseRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dir := t.TempDir()
	t.Setenv("SCREDMGR_HOME", dir)

	bin := filepath.Join(dir, "scredmgr")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "../../cmd/scredmgr")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}

	name := fmt.Sprintf("itest-%d", time.Now().UnixNano())
	id := "ssh:" + name
	keyPath := filepath.Join(dir, "id_"+name)

	t.Cleanup(func() {
		rm := exec.Command(bin, "rm", id, "--files")
		rm.Env = os.Environ()
		rm.Run() // best effort
		store.NewKeychainStore().Delete(id)
	})

	gen := exec.CommandContext(ctx, bin, "ssh", "keygen", name,
		"--passphrase-random", "--file", keyPath, "--expiry-days", "1")
	gen.Env = os.Environ()
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("ssh keygen: %v: %s", err, out)
	}

	// The passphrase must open the private key via the askpass re-exec.
	verify := exec.CommandContext(ctx, "ssh-keygen", "-yf", keyPath)
	verify.Env = append(os.Environ(),
		"SSH_ASKPASS="+bin,
		"SSH_ASKPASS_REQUIRE=force",
		"SCREDMGR_ASKPASS_ID="+id,
	)
	out, err := verify.Output()
	if err != nil {
		t.Fatalf("ssh-keygen -yf with askpass: %v", err)
	}
	if !strings.HasPrefix(string(out), "ssh-ed25519 ") {
		t.Fatalf("unexpected pubkey output: %q", out)
	}

	// rm --files cleans everything.
	rm := exec.CommandContext(ctx, bin, "rm", id, "--files")
	rm.Env = os.Environ()
	if out, err := rm.CombinedOutput(); err != nil {
		t.Fatalf("rm --files: %v: %s", err, out)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("private key not removed")
	}
}
