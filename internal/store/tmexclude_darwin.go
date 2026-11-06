//go:build darwin

package store

import (
	"os"
	"os/exec"
	"path/filepath"
)

const tmExcludeMarker = "tm-excluded"

// tmExclude runs the actual exclusion. Tests swap it out through
// SetTimeMachineExcluder: `tmutil addexclusion` takes seconds per call on a
// CI runner, and every test with its own temp home pays it once.
var tmExclude = func(dir string) { _ = exec.Command("tmutil", "addexclusion", dir).Run() }

// excludeFromTimeMachine marks dir as excluded from Time Machine backups
// via tmutil. A marker file prevents repeated calls on subsequent runs.
func excludeFromTimeMachine(dir string) {
	marker := filepath.Join(dir, tmExcludeMarker)
	if _, err := os.Stat(marker); err == nil {
		return
	}
	tmExclude(dir)
	_ = os.WriteFile(marker, nil, 0o600)
}

// SetTimeMachineExcluder replaces the tmutil call (tests only; pass a no-op).
func SetTimeMachineExcluder(f func(dir string)) { tmExclude = f }
