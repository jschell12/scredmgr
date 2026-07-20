package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmanager/internal/safety"
	"github.com/jschell12/scredmanager/internal/store"
)

func newRunCmd() *cobra.Command {
	var only string
	cmd := &cobra.Command{
		Use:   "run [--only a,b] -- <cmd…>",
		Short: "Exec a child with secrets injected as env vars (replaces `source ~/.agentsecrets`)",
		Long: "Fetches every entry that has an envVar, injects them into the environment of\n" +
			"the child process, and execs it. The env exists only in the child — nothing\n" +
			"lands on disk and the parent shell sees nothing.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			childArgs := args
			if dash := cmd.ArgsLenAtDash(); dash >= 0 {
				childArgs = args[dash:]
			}
			if len(childArgs) == 0 {
				return errors.New("no command given; usage: scredmanager run -- <cmd…>")
			}

			var wanted map[string]bool
			if only != "" {
				wanted = make(map[string]bool)
				for _, id := range strings.Split(only, ",") {
					wanted[strings.TrimSpace(id)] = true
				}
			}

			ids, err := store.ListIDs()
			if err != nil {
				return err
			}
			env := os.Environ()
			injected := 0
			for _, id := range ids {
				if wanted != nil && !wanted[id] {
					continue
				}
				m, err := store.LoadAndMigrate(id, backend)
				if err != nil {
					return err
				}
				if m.EnvVar == "" {
					continue
				}
				secret, err := store.GetSecret(id, backend)
				if err != nil {
					return fmt.Errorf("fetch %s: %w", id, err)
				}
				safety.Track(secret)
				env = append(env, m.EnvVar+"="+string(secret))
				injected++
			}
			if wanted != nil && injected < len(wanted) {
				return fmt.Errorf("--only listed %d ids but only %d matched entries with an envVar", len(wanted), injected)
			}

			path, err := exec.LookPath(childArgs[0])
			if err != nil {
				return err
			}
			// Replace the process: the injected env lives only in the child.
			return syscall.Exec(path, childArgs, env)
		},
	}
	cmd.Flags().StringVar(&only, "only", "", "comma-separated ids to inject (default: all with an envVar)")
	cmd.Flags().SetInterspersed(false)
	return cmd
}
