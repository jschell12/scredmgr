package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmgr/internal/provider"
)

func newProvidersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "providers",
		Short: "List configured remote providers (~/.scredmgr/providers.json)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			configs, err := provider.LoadConfigs()
			if err != nil {
				return err
			}
			if jsonOut {
				type info struct {
					Name string `json:"name"`
					Type string `json:"type"`
				}
				out := make([]info, len(configs))
				for i, c := range configs {
					out[i] = info{Name: c.Name, Type: c.Type}
				}
				emit(out)
				return nil
			}
			if len(configs) == 0 {
				fmt.Println("no providers configured")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tTYPE")
			for _, c := range configs {
				fmt.Fprintf(w, "%s\t%s\n", c.Name, c.Type)
			}
			return w.Flush()
		},
	}
	cmd.AddCommand(newProvidersCheckCmd())
	return cmd
}

func newProvidersCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <name>",
		Short: "Probe a provider's connectivity and auth",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configs, err := provider.LoadConfigs()
			if err != nil {
				return err
			}
			cfg, err := provider.FindConfig(configs, args[0])
			if err != nil {
				return err
			}
			p, err := openProvider(*cfg, backend)
			if err != nil {
				return err
			}
			if err := p.Check(cmd.Context()); err != nil {
				return err
			}
			if jsonOut {
				emit(map[string]any{"name": p.Name(), "ok": true, "writable": p.Writable()})
			} else {
				fmt.Printf("%s: ok (writable: %v)\n", p.Name(), p.Writable())
			}
			return nil
		},
	}
}
