package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

const launchdLabel = "com.jschell12.scredmgr.status"

// legacyLaunchdLabel is the pre-rename LaunchAgent label; install unloads and
// removes its plist so the old job doesn't linger alongside the new one.
const legacyLaunchdLabel = "com.jschell12.scredmanager.status"

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>status</string>
		<string>--quiet</string>
		<string>--notify</string>
	</array>
	<key>StartCalendarInterval</key>
	<dict>
		<key>Hour</key>
		<integer>9</integer>
		<key>Minute</key>
		<integer>30</integer>
	</dict>
	<key>StandardOutPath</key>
	<string>/tmp/%s.log</string>
	<key>StandardErrorPath</key>
	<string>/tmp/%s.log</string>
</dict>
</plist>
`

func plistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist"), nil
}

func newLaunchdCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "launchd",
		Short: "Manage the daily expiry-check LaunchAgent",
	}

	install := &cobra.Command{
		Use:   "install",
		Short: "Install a LaunchAgent that runs `status --quiet --notify` daily at 09:30",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			bin, err := os.Executable()
			if err != nil {
				return err
			}
			bin, err = filepath.EvalSymlinks(bin)
			if err != nil {
				return err
			}
			p, err := plistPath()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			content := fmt.Sprintf(plistTemplate, launchdLabel, bin, launchdLabel, launchdLabel)
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				return err
			}
			// Clean up the pre-rename agent if present (errors ignored).
			legacy := filepath.Join(filepath.Dir(p), legacyLaunchdLabel+".plist")
			if _, err := os.Stat(legacy); err == nil {
				_ = exec.Command("launchctl", "unload", legacy).Run()
				_ = os.Remove(legacy)
			}
			// Reload: unload any previous copy first (errors ignored — it may
			// simply not be loaded yet).
			_ = exec.Command("launchctl", "unload", p).Run()
			if out, err := exec.Command("launchctl", "load", "-w", p).CombinedOutput(); err != nil {
				return fmt.Errorf("launchctl load: %v: %s", err, out)
			}
			if jsonOut {
				emit(map[string]any{"plist": p, "label": launchdLabel, "binary": bin})
			} else {
				fmt.Printf("installed %s\n  plist:  %s\n  binary: %s\n  runs:   daily at 09:30\n", launchdLabel, p, bin)
			}
			return nil
		},
	}

	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Unload and remove the LaunchAgent",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := plistPath()
			if err != nil {
				return err
			}
			_ = exec.Command("launchctl", "unload", p).Run()
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return err
			}
			if jsonOut {
				emit(map[string]any{"removed": p})
			} else {
				fmt.Printf("removed %s\n", p)
			}
			return nil
		},
	}

	cmd.AddCommand(install, uninstall)
	return cmd
}
