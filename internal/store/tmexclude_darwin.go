//go:build darwin

package store

import (
	"os"
	"os/exec"
	"path/filepath"
)

const tmExcludeMarker = "tm-excluded"

// excludeFromTimeMachine marks dir as excluded from Time Machine backups
// via tmutil. A marker file prevents repeated calls on subsequent runs.
func excludeFromTimeMachine(dir string) {
	marker := filepath.Join(dir, tmExcludeMarker)
	if _, err := os.Stat(marker); err == nil {
		return
	}
	_ = exec.Command("tmutil", "addexclusion", dir).Run()
	_ = os.WriteFile(marker, nil, 0o600)
}
