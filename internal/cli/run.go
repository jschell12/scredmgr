package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

func newRunCmd() *cobra.Command {
	var (
		only string
		path string
	)
	cmd := &cobra.Command{
		Use:   "run [--path ns] [--only a,b] -- <cmd…>",
		Short: "Exec a child with secrets injected as env vars (replaces `source ~/.agentsecrets`)",
		Long: "Fetches every root entry that has an envVar, injects them into the environment\n" +
			"of the child process, and execs it. With --path, entries under that namespace\n" +
			"(e.g. work/jira) overlay the root entries, overriding any matching envVar.\n" +
			"The env exists only in the child — nothing lands on disk and the parent shell\n" +
			"sees nothing.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			childArgs := args
			if dash := cmd.ArgsLenAtDash(); dash >= 0 {
				childArgs = args[dash:]
			}
			if len(childArgs) == 0 {
				return errors.New("no command given; usage: scredmgr run -- <cmd…>")
			}

			var wanted map[string]bool
			if only != "" {
				wanted = make(map[string]bool)
				for _, id := range strings.Split(only, ",") {
					wanted[strings.TrimSpace(id)] = true
				}
			}

			pairs, matched, err := resolveEnv(path, wanted, backend)
			if err != nil {
				return err
			}
			if wanted != nil && matched < len(wanted) {
				return fmt.Errorf("--only listed %d ids but only %d matched entries with an envVar", len(wanted), matched)
			}

			env := os.Environ()
			for _, p := range pairs {
				env = append(env, p.EnvVar+"="+string(p.Secret))
			}

			binPath, err := exec.LookPath(childArgs[0])
			if err != nil {
				return err
			}
			// Replace the process: the injected env lives only in the child.
			return syscall.Exec(binPath, childArgs, env)
		},
	}
	cmd.Flags().StringVar(&only, "only", "", "comma-separated ids to inject (default: all with an envVar)")
	cmd.Flags().StringVar(&path, "path", "", "namespace whose entries overlay the root entries (e.g. work)")
	cmd.Flags().SetInterspersed(false)
	return cmd
}
