// Package loginflow implements the guided token-mint flow (M6): open the
// provider's token page in the user's real browser, capture the fresh token
// via masked prompt, clipboard watch, or OAuth device-code flow — never
// headless-browser automation.
package loginflow

import (
	"os/exec"
	"runtime"
)

// OpenBrowser opens url in the user's default browser.
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("open", url)
	} else {
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
