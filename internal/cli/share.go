package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmgr/internal/safety"
	"github.com/jschell12/scredmgr/internal/share"
	"github.com/jschell12/scredmgr/internal/store"
)

// Swappable seams for tests.
var (
	shareRunner share.Runner = share.ExecCapture
	detectVPN                = share.DetectVPN
)

func newShareCmd() *cobra.Command {
	var (
		to        string
		only      string
		dryRun    bool
		overwrite bool
		ignoreVPN bool
		probe     bool
	)
	cmd := &cobra.Command{
		Use:   "share",
		Short: "Send secrets to another machine on the local network over ssh",
		Long: "Pipes selected entries to `scredmgr receive` on a peer via ssh (key-based\n" +
			"auth required; the payload rides on stdin, never argv). If a VPN is\n" +
			"active, share warns and asks for confirmation first — traffic to the\n" +
			"peer may route off-LAN. Hosts come from ~/.ssh/config (or --to).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// VPN gate: warn + confirm on a TTY, fail closed otherwise.
			if !ignoreVPN {
				info, derr := detectVPN(ctx, share.Runner(shareRunner))
				if derr != nil && !info.Active {
					fmt.Fprintf(os.Stderr, "scredmgr: vpn detection failed (proceeding): %s\n", safety.Redact(derr.Error()))
				}
				if info.Active {
					detail := info.Detail()
					if !safety.IsTTY(os.Stdin) {
						return fmt.Errorf("VPN active (%s); refusing to send secrets — disconnect the VPN or pass --ignore-vpn", detail)
					}
					fmt.Fprintf(os.Stderr, "VPN detected: %s\nTraffic to the peer may route off your local network.\n", detail)
					ok, err := confirmTTY("Send secrets over this network anyway? [y/N] ")
					if err != nil {
						return err
					}
					if !ok {
						return errors.New("aborted")
					}
				}
			}

			host := to
			if host == "" {
				var err error
				host, err = pickHost(ctx, probe)
				if err != nil {
					return err
				}
			}

			ids, err := selectEntryIDs(only)
			if err != nil {
				return err
			}

			results, payload, err := buildShare(ids, only != "", dryRun)
			if err != nil {
				return err
			}
			if dryRun {
				return emitShareSendResults(host, results, true)
			}
			if payload == nil || len(payload.Entries) == 0 {
				return emitShareSendResults(host, results, false)
			}

			data, err := payload.Encode()
			if err != nil {
				return err
			}
			safety.Track(data)

			sshArgs := []string{"-o", "BatchMode=yes", host, "scredmgr", "receive", "--stdin", "--json"}
			if overwrite {
				sshArgs = append(sshArgs, "--overwrite")
			}
			out, runErr := shareRunner(ctx, "ssh", sshArgs, data)
			remote, perr := parseRemoteEnvelope(out)
			if perr != nil {
				if runErr != nil {
					if strings.Contains(runErr.Error(), "command not found") {
						return fmt.Errorf("scredmgr is not installed (or not on PATH for non-interactive shells) on %s", host)
					}
					return fmt.Errorf("send to %s failed: %w", host, runErr)
				}
				return fmt.Errorf("unexpected response from %s: %w", host, perr)
			}
			for _, r := range remote {
				if r.Action == "stored" {
					r.Action = "sent"
				}
				if r.Action == "spooled" {
					r.Reason = "receiver keychain locked — run `scredmgr inbox import` there in a GUI session"
				}
				results = append(results, r)
			}
			return emitShareSendResults(host, results, false)
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "target host (ssh alias or hostname); skips the picker")
	cmd.Flags().StringVar(&only, "only", "", "comma-separated ids to send; skips the interactive selection")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the plan without reading or sending any secret")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "replace entries that already exist on the receiver")
	cmd.Flags().BoolVar(&ignoreVPN, "ignore-vpn", false, "skip the VPN warning/confirmation")
	cmd.Flags().BoolVar(&probe, "probe", false, "probe each ssh_config host for reachability in the picker")
	return cmd
}

// buildShare resolves the send plan and (unless dryRun) reads the secrets.
// explicitOnly relaxes the ssh-entry skip, mirroring sync --only semantics.
func buildShare(ids []string, explicitOnly, dryRun bool) ([]shareResult, *share.Payload, error) {
	hostname, _ := os.Hostname()
	payload := &share.Payload{
		Version: share.Version,
		From:    hostname,
		SentAt:  time.Now().Format(time.RFC3339),
	}
	var results []shareResult
	for _, id := range ids {
		m, err := store.ReadMeta(id)
		if err != nil {
			results = append(results, shareResult{ID: id, Action: "failed", Reason: err.Error()})
			continue
		}
		if m.Kind == "ssh" && !explicitOnly {
			results = append(results, shareResult{ID: id, Action: "skipped", Reason: "ssh entry (name it in --only to send its passphrase)"})
			continue
		}
		if m.Storage == store.StorageFile || m.Storage == store.StorageMixed {
			results = append(results, shareResult{ID: id, Action: "skipped", Reason: "not migrated to the secret backend yet"})
			continue
		}
		if !store.SecretInBackend(m) {
			results = append(results, shareResult{ID: id, Action: "skipped", Reason: "no stored secret"})
			continue
		}
		if dryRun {
			results = append(results, shareResult{ID: id, Action: "would-send"})
			continue
		}
		secret, err := backend.Get(id)
		if err != nil {
			results = append(results, shareResult{ID: id, Action: "failed", Reason: err.Error()})
			continue
		}
		safety.Track(secret)
		payload.Entries = append(payload.Entries, share.Entry{
			ID:        id,
			SecretB64: base64.StdEncoding.EncodeToString(secret),
			Label:     m.Label,
			EnvVar:    m.EnvVar,
			ExpiresAt: m.ExpiresAt,
			Notes:     m.Notes,
			Kind:      m.Kind,
		})
	}
	return results, payload, nil
}

// selectEntryIDs resolves --only or runs the interactive multi-select.
func selectEntryIDs(only string) ([]string, error) {
	if only != "" {
		var ids []string
		for _, id := range strings.Split(only, ",") {
			if id = strings.TrimSpace(id); id != "" {
				ids = append(ids, id)
			}
		}
		return ids, nil
	}
	if !safety.IsTTY(os.Stdin) {
		return nil, errors.New("no TTY for interactive selection; pass --only id,id2")
	}
	all, err := store.ListIDs()
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, errors.New("no entries to share")
	}
	sort.Strings(all)
	fmt.Fprintln(os.Stderr, "Entries:")
	for i, id := range all {
		fmt.Fprintf(os.Stderr, "  %2d) %s\n", i+1, id)
	}
	line, err := promptTTY("Select entries (e.g. 1,3 or all): ")
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(strings.TrimSpace(line), "all") {
		return all, nil
	}
	var ids []string
	for _, tok := range strings.Split(line, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		n, err := strconv.Atoi(tok)
		if err != nil || n < 1 || n > len(all) {
			return nil, fmt.Errorf("invalid selection %q", tok)
		}
		ids = append(ids, all[n-1])
	}
	if len(ids) == 0 {
		return nil, errors.New("nothing selected")
	}
	return ids, nil
}

// pickHost lists ~/.ssh/config hosts and prompts for a choice.
func pickHost(ctx context.Context, probe bool) (string, error) {
	if !safety.IsTTY(os.Stdin) {
		return "", errors.New("no TTY for the host picker; pass --to <host>")
	}
	path, err := share.DefaultSSHConfigPath()
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot read %s (%w); pass --to <host>", path, err)
	}
	defer f.Close()
	hosts := share.ParseSSHConfigHosts(f)
	if len(hosts) == 0 {
		return "", errors.New("no concrete Host entries in ~/.ssh/config; pass --to <host>")
	}
	fmt.Fprintln(os.Stderr, "Hosts (~/.ssh/config):")
	for i, h := range hosts {
		note := ""
		if probe {
			if share.ProbeHost(ctx, share.Runner(shareRunner), h) {
				note = "  [reachable]"
			} else {
				note = "  [no answer]"
			}
		}
		fmt.Fprintf(os.Stderr, "  %2d) %s%s\n", i+1, h, note)
	}
	line, err := promptTTY("Send to: ")
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(hosts) {
		return "", fmt.Errorf("invalid selection %q", strings.TrimSpace(line))
	}
	return hosts[n-1], nil
}

// parseRemoteEnvelope extracts per-entry results from the first --json
// envelope on the remote's stdout. (A failing remote prints its results
// envelope and then an error envelope; the first one carries the detail.)
func parseRemoteEnvelope(out []byte) ([]shareResult, error) {
	dec := json.NewDecoder(bytes.NewReader(out))
	var env struct {
		SchemaVersion int    `json:"schemaVersion"`
		OK            bool   `json:"ok"`
		Error         string `json:"error"`
		Data          struct {
			Results []shareResult `json:"results"`
		} `json:"data"`
	}
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("no JSON envelope in response: %w", err)
	}
	if env.Data.Results == nil && env.Error != "" {
		return nil, errors.New(env.Error)
	}
	return env.Data.Results, nil
}

func emitShareSendResults(host string, results []shareResult, dryRun bool) error {
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Action]++
	}
	if jsonOut {
		emit(map[string]any{
			"to":      host,
			"dryRun":  dryRun,
			"results": results,
			"sent":    counts["sent"],
			"skipped": counts["skipped"],
			"spooled": counts["spooled"],
			"failed":  counts["failed"],
		})
	} else {
		for _, r := range results {
			if r.Reason != "" {
				fmt.Printf("%-12s %s (%s)\n", r.Action, r.ID, r.Reason)
			} else {
				fmt.Printf("%-12s %s\n", r.Action, r.ID)
			}
		}
		if len(results) == 0 {
			fmt.Println("nothing to share")
		}
	}
	if failed := counts["failed"]; failed > 0 {
		return &exitCodeError{code: exitError, err: fmt.Errorf("%d item(s) failed", failed)}
	}
	return nil
}
