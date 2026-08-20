package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmgr/internal/manifest"
	"github.com/jschell12/scredmgr/internal/safety"
	"github.com/jschell12/scredmgr/internal/store"
)

func newCurlCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "curl <id> <url> [curl-args…]",
		Short: "Run curl with the service's auth header injected (host allowlisted)",
		Long: "Injects the auth header for <id> and execs curl. The header is passed via\n" +
			"curl's stdin config (-K -), never argv, so the secret is invisible to ps.\n" +
			"Hard behavior: refuses if the URL host is not the service's baseUrl host.",
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, rawURL, extra := args[0], args[1], args[2:]

			services, err := manifest.Load()
			if err != nil {
				return err
			}
			svc := manifest.Find(services, id)
			if svc == nil {
				return fmt.Errorf("no service %q in services.json (curl requires a manifest entry with baseUrl)", id)
			}
			ok, err := manifest.SameHost(svc, rawURL)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("refusing: %s is not on the %s baseUrl host (%s)", rawURL, id, svc.BaseURL)
			}

			secret, err := store.GetSecret(id, backend)
			if err != nil {
				return err
			}
			safety.Track(secret)
			name, value, err := manifest.BuildHeader(svc.AuthHeader, string(secret))
			if err != nil {
				return err
			}

			// -K - : read config (the auth header) from stdin — never argv.
			curlArgs := append([]string{"-K", "-", rawURL}, extra...)
			c := exec.Command("curl", curlArgs...)
			c.Stdin = strings.NewReader(fmt.Sprintf("header = %q\n", name+": "+value))
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			if err := c.Run(); err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					return &exitCodeError{code: ee.ExitCode(), err: fmt.Errorf("curl exited %d", ee.ExitCode())}
				}
				return err
			}
			return nil
		},
	}
	// Stop flag parsing at the first positional arg so trailing curl flags
	// (-s, -o, …) pass through untouched.
	cmd.Flags().SetInterspersed(false)
	return cmd
}
