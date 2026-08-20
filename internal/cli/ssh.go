package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/jschell12/scredmgr/internal/safety"
	"github.com/jschell12/scredmgr/internal/sshkey"
	"github.com/jschell12/scredmgr/internal/store"
)

const sshIDPrefix = "ssh:"

func newSSHCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh",
		Short: "Manage SSH keys — files stay in ~/.ssh; scredmgr owns metadata + passphrase",
	}
	cmd.AddCommand(newSSHKeygenCmd(), newSSHShowCmd(), newSSHAddCmd())
	return cmd
}

func newSSHKeygenCmd() *cobra.Command {
	var (
		keyType    string
		keyFile    string
		comment    string
		passRandom bool
		passPrompt bool
		noPass     bool
		expiryDays int
		addAgent   bool
		force      bool
	)
	cmd := &cobra.Command{
		Use:   "keygen <name>",
		Short: "Generate an SSH key pair with a keychain-backed passphrase and rotation reminder",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := args[0]
			id := sshIDPrefix + name
			if err := store.ValidateID(id); err != nil {
				return err
			}

			modes := 0
			for _, b := range []bool{passRandom, passPrompt, noPass} {
				if b {
					modes++
				}
			}
			if modes != 1 {
				return errors.New("choose exactly one of --passphrase-random, --passphrase-prompt, --no-passphrase")
			}
			if keyType != "ed25519" {
				return fmt.Errorf("unsupported key type %q (only ed25519 in v1)", keyType)
			}
			if !noPass {
				if err := sshkey.CheckOpenSSHVersion(ctx); err != nil {
					return err
				}
			}

			if keyFile == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				keyFile = filepath.Join(home, ".ssh", "id_"+name)
			}
			if comment == "" {
				host, _ := os.Hostname()
				comment = name + "@" + host
			}

			if _, err := store.ReadMeta(id); err == nil && !force {
				return fmt.Errorf("entry %s already exists (use --force to replace)", id)
			}
			if _, err := os.Stat(keyFile); err == nil {
				if !force {
					return fmt.Errorf("key file %s already exists (use --force to overwrite)", keyFile)
				}
				// ssh-keygen prompts interactively on overwrite; remove first.
				for _, p := range []string{keyFile, keyFile + ".pub"} {
					if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
						return err
					}
				}
			}
			if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
				return err
			}

			var pass []byte
			var err error
			switch {
			case passRandom:
				pass, err = sshkey.RandomPassphrase(32)
			case passPrompt:
				pass, err = safety.ReadMasked(fmt.Sprintf("Passphrase for %s: ", id))
				if err == nil && len(pass) == 0 {
					err = errors.New("empty passphrase; use --no-passphrase to opt out explicitly")
				}
			}
			if err != nil {
				return err
			}

			var extraEnv []string
			if pass != nil {
				safety.Track(pass)
				// The passphrase must be in the keychain BEFORE keygen so the
				// askpass re-exec can read it.
				if err := backend.Set(id, pass); err != nil {
					return err
				}
				extraEnv, err = sshkey.AskpassEnv(id)
				if err != nil {
					backend.Delete(id)
					return err
				}
			}

			res, err := sshkey.Keygen(ctx, sshkey.KeygenOptions{
				Type:       keyType,
				KeyPath:    keyFile,
				Comment:    comment,
				UseAskpass: pass != nil,
			}, extraEnv)
			if err != nil {
				if pass != nil {
					backend.Delete(id) // roll back the orphaned passphrase
				}
				return err
			}

			now := time.Now()
			m := &store.Meta{
				Kind:        "ssh",
				KeyPath:     res.KeyPath,
				PublicKey:   res.PublicKey,
				Fingerprint: res.Fingerprint,
				CreatedAt:   now.Format(time.RFC3339),
				Storage:     store.StorageNone,
			}
			if pass != nil {
				m.Storage = store.StorageKeychain
			}
			if expiryDays > 0 {
				m.ExpiresAt = now.AddDate(0, 0, expiryDays).Format(time.RFC3339)
			}
			if err := store.WriteMeta(id, m); err != nil {
				return err
			}

			agentAdded := false
			if addAgent {
				if err := sshkey.AddToAgent(ctx, res.KeyPath, extraEnv); err != nil {
					return fmt.Errorf("key generated and stored, but ssh-add failed: %w", err)
				}
				agentAdded = true
			}

			if jsonOut {
				emit(map[string]any{
					"id":               id,
					"keyPath":          res.KeyPath,
					"publicKey":        res.PublicKey,
					"fingerprint":      res.Fingerprint,
					"passphraseStored": pass != nil,
					"agentAdded":       agentAdded,
					"expiresAt":        m.ExpiresAt,
				})
			} else {
				fmt.Printf("generated %s (%s)\n", id, res.Fingerprint)
				fmt.Printf("  key file:   %s\n", res.KeyPath)
				fmt.Printf("  public key: %s\n", res.PublicKey)
				if pass != nil {
					fmt.Println("  passphrase: stored in keychain")
				} else {
					fmt.Println("  passphrase: none")
				}
				if m.ExpiresAt != "" {
					fmt.Printf("  rotate by:  %s\n", m.ExpiresAt[:10])
				}
				if agentAdded {
					fmt.Println("  agent:      added (--apple-use-keychain)")
					fmt.Println("  hint: add `UseKeychain yes` under Host * in ~/.ssh/config to survive reboots")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&keyType, "type", "ed25519", "key type (only ed25519 in v1)")
	cmd.Flags().StringVar(&keyFile, "file", "", "private key path (default ~/.ssh/id_<name>)")
	cmd.Flags().StringVar(&comment, "comment", "", "key comment (default <name>@<hostname>)")
	cmd.Flags().BoolVar(&passRandom, "passphrase-random", false, "generate a random passphrase and store it in the keychain")
	cmd.Flags().BoolVar(&passPrompt, "passphrase-prompt", false, "prompt (masked) for a passphrase and store it in the keychain")
	cmd.Flags().BoolVar(&noPass, "no-passphrase", false, "generate the key without a passphrase")
	cmd.Flags().IntVar(&expiryDays, "expiry-days", 365, "days until rotation reminder (0 disables)")
	cmd.Flags().BoolVar(&addAgent, "add-agent", false, "register with ssh-agent (--apple-use-keychain)")
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing entry / key file")
	return cmd
}

// readSSHMeta loads and validates the metadata for ssh:<name>.
func readSSHMeta(name string) (string, *store.Meta, error) {
	id := sshIDPrefix + name
	m, err := store.ReadMeta(id)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil, &exitCodeError{code: exitMissing, err: fmt.Errorf("no such ssh entry %s", id)}
		}
		return "", nil, err
	}
	if m.Kind != "ssh" {
		return "", nil, fmt.Errorf("%s is not an ssh entry", id)
	}
	return id, m, nil
}

func newSSHShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show public key, fingerprint, and metadata (TTY-safe)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, m, err := readSSHMeta(args[0])
			if err != nil {
				return err
			}
			if jsonOut {
				emit(map[string]any{
					"id":               id,
					"keyPath":          m.KeyPath,
					"publicKey":        m.PublicKey,
					"fingerprint":      m.Fingerprint,
					"passphraseStored": m.Storage == store.StorageKeychain,
					"expiresAt":        m.ExpiresAt,
				})
				return nil
			}
			fmt.Printf("%s (%s)\n", id, m.Fingerprint)
			fmt.Printf("  key file:   %s\n", m.KeyPath)
			fmt.Printf("  public key: %s\n", m.PublicKey)
			fmt.Printf("  passphrase: %s\n", map[bool]string{true: "stored in keychain", false: "none"}[m.Storage == store.StorageKeychain])
			if m.ExpiresAt != "" {
				fmt.Printf("  rotate by:  %s\n", m.ExpiresAt[:10])
			}
			return nil
		},
	}
}

func newSSHAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <name>",
		Short: "(Re)register the key with ssh-agent using the stored passphrase",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			id, m, err := readSSHMeta(args[0])
			if err != nil {
				return err
			}
			var extraEnv []string
			if m.Storage == store.StorageKeychain {
				if err := sshkey.CheckOpenSSHVersion(ctx); err != nil {
					return err
				}
				extraEnv, err = sshkey.AskpassEnv(id)
				if err != nil {
					return err
				}
			}
			if err := sshkey.AddToAgent(ctx, m.KeyPath, extraEnv); err != nil {
				return err
			}
			if jsonOut {
				emit(map[string]any{"id": id, "agentAdded": true})
			} else {
				fmt.Printf("added %s to ssh-agent\n", id)
			}
			return nil
		},
	}
}
