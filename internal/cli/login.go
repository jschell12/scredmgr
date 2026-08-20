package cli

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmgr/internal/loginflow"
	"github.com/jschell12/scredmgr/internal/manifest"
	"github.com/jschell12/scredmgr/internal/safety"
	"github.com/jschell12/scredmgr/internal/store"
)

func newLoginCmd() *cobra.Command {
	var (
		useClipboard bool
		useDevice    bool
		usePrompt    bool
		timeout      time.Duration
	)
	cmd := &cobra.Command{
		Use:   "login <id>",
		Short: "Guided token mint: open the token page, capture, verify, store",
		Long: "Opens the service's tokenPage in your real browser, captures the freshly\n" +
			"minted token (masked prompt by default, --clipboard to watch the clipboard,\n" +
			"or the OAuth device-code flow when the manifest configures deviceFlow),\n" +
			"verifies it against checkPath (fail closed), and stores it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			services, err := manifest.Load()
			if err != nil {
				return err
			}
			svc := manifest.Find(services, id)
			if svc == nil {
				return fmt.Errorf("no service %q in services.json (login requires a manifest entry)", id)
			}

			mode := "prompt"
			switch {
			case useDevice:
				if svc.DeviceFlow == nil {
					return fmt.Errorf("service %q has no deviceFlow in services.json", id)
				}
				mode = "device"
			case useClipboard:
				mode = "clipboard"
			case usePrompt:
				mode = "prompt"
			case svc.DeviceFlow != nil:
				mode = "device"
			}

			var secret []byte
			switch mode {
			case "device":
				df := svc.DeviceFlow
				ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
				defer cancel()
				token, err := loginflow.RunDeviceFlow(ctx, loginflow.DeviceFlowConfig{
					ClientID:      df.ClientID,
					Scope:         df.Scope,
					DeviceAuthURL: df.DeviceAuthURL,
					TokenURL:      df.TokenURL,
				}, func(userCode, verificationURI string) {
					fmt.Fprintf(os.Stderr, "Enter code %s at %s\n", userCode, verificationURI)
					_ = loginflow.OpenBrowser(verificationURI)
				})
				if err != nil {
					return err
				}
				secret = []byte(token)

			case "clipboard":
				var pattern *regexp.Regexp
				if svc.TokenPattern != "" {
					pattern, err = regexp.Compile(svc.TokenPattern)
					if err != nil {
						return fmt.Errorf("tokenPattern for %s: %w", id, err)
					}
				}
				if svc.TokenPage != "" {
					fmt.Fprintf(os.Stderr, "Opening %s — mint a token and copy it.\n", svc.TokenPage)
					_ = loginflow.OpenBrowser(svc.TokenPage)
				}
				fmt.Fprintln(os.Stderr, "Watching the clipboard…")
				clip := loginflow.SystemClipboard{}
				ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
				defer cancel()
				token, err := loginflow.WaitForToken(ctx, clip, pattern, 500*time.Millisecond)
				if err != nil {
					return err
				}
				secret = []byte(token)
				// Do not leave the token on the clipboard.
				defer func() {
					if err := clip.Clear(); err == nil {
						fmt.Fprintln(os.Stderr, "clipboard cleared")
					}
				}()

			default: // prompt
				if svc.TokenPage != "" {
					fmt.Fprintf(os.Stderr, "Opening %s — mint a token, then paste it below.\n", svc.TokenPage)
					_ = loginflow.OpenBrowser(svc.TokenPage)
				}
				secret, err = safety.ReadMasked(fmt.Sprintf("Token for %s: ", id))
				if err != nil {
					return err
				}
			}

			if len(secret) == 0 {
				return fmt.Errorf("no token captured")
			}
			safety.Track(secret)

			// Fail closed: an unverifiable token is not stored.
			if svc.CheckPath != "" {
				if err := manifest.Verify(svc, string(secret)); err != nil {
					return fmt.Errorf("verification failed, token NOT stored: %w", err)
				}
			}

			now := time.Now()
			m := &store.Meta{
				EnvVar:    svc.EnvVar,
				CreatedAt: now.Format(time.RFC3339),
				Storage:   store.StorageKeychain,
			}
			if prev, err := store.ReadMeta(id); err == nil {
				m.Label = prev.Label
				m.Notes = prev.Notes
			}
			if svc.ExpiryDays > 0 {
				m.ExpiresAt = now.AddDate(0, 0, svc.ExpiryDays).Format(time.RFC3339)
			}
			if err := backend.Set(id, secret); err != nil {
				return err
			}
			if err := store.WriteMeta(id, m); err != nil {
				return err
			}

			if jsonOut {
				emit(map[string]any{"id": id, "mode": mode, "expiresAt": m.ExpiresAt, "verified": svc.CheckPath != ""})
			} else {
				fmt.Printf("stored %s (%s flow", id, mode)
				if m.ExpiresAt != "" {
					fmt.Printf(", expires %s", m.ExpiresAt[:10])
				}
				fmt.Println(")")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&useClipboard, "clipboard", false, "watch the clipboard for the minted token, then clear it")
	cmd.Flags().BoolVar(&useDevice, "device", false, "force the OAuth device-code flow")
	cmd.Flags().BoolVar(&usePrompt, "prompt", false, "force the masked prompt even if deviceFlow is configured")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "how long to wait for capture/approval")
	return cmd
}
