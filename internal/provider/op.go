package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jschell12/scredmanager/internal/safety"
)

// Op stores secrets as 1Password items via the official `op` CLI (biometric
// auth handled by op itself). Each entry is a PASSWORD item titled
// "<itemPrefix><id>" whose password field holds the value.
//
// Secret values never touch argv: reads arrive on op's stdout, writes travel
// as item JSON on stdin. Updates are delete-then-create because `op item edit
// field=value` only accepts values on argv.
type Op struct {
	name string
	cfg  OpCfg
	run  Runner
}

// NewOp returns a 1Password provider backed by run (ExecRunner in production).
func NewOp(name string, cfg OpCfg, run Runner) *Op {
	return &Op{name: name, cfg: cfg, run: run}
}

func (o *Op) Name() string   { return o.name }
func (o *Op) Writable() bool { return true }

func (o *Op) title(id string) string { return o.cfg.ItemPrefix + id }

// args appends the account flag (if configured) to base args.
func (o *Op) args(base ...string) []string {
	if o.cfg.Account != "" {
		base = append(base, "--account", o.cfg.Account)
	}
	return base
}

func (o *Op) Check(ctx context.Context) error {
	if _, err := o.run(ctx, "op", o.args("whoami"), nil); err != nil {
		return fmt.Errorf("op auth: %w (hint: run `op signin` in a real terminal; biometric unlock needs a GUI session)", err)
	}
	return nil
}

func (o *Op) List(ctx context.Context) ([]string, error) {
	out, err := o.run(ctx, "op", o.args("item", "list", "--vault", o.cfg.Vault, "--format", "json"), nil)
	if err != nil {
		return nil, err
	}
	var items []struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, fmt.Errorf("op list: parse: %w", err)
	}
	var ids []string
	for _, it := range items {
		if !strings.HasPrefix(it.Title, o.cfg.ItemPrefix) {
			continue // not ours
		}
		ids = append(ids, strings.TrimPrefix(it.Title, o.cfg.ItemPrefix))
	}
	return ids, nil
}

func (o *Op) Get(ctx context.Context, id string) ([]byte, error) {
	out, err := o.run(ctx, "op", o.args("item", "get", o.title(id),
		"--vault", o.cfg.Vault, "--fields", "label=password", "--reveal"), nil)
	if err != nil {
		return nil, err
	}
	secret := bytes.TrimRight(out, "\n")
	if len(secret) == 0 {
		return nil, fmt.Errorf("op get %s: empty password field", id)
	}
	safety.Track(secret)
	return secret, nil
}

func (o *Op) Put(ctx context.Context, id string, value []byte) error {
	safety.Track(value)
	// Delete-then-create: `op item edit` puts values on argv, so it is off
	// limits. A failed delete is fine (item may not exist yet); create is the
	// call that must succeed.
	_, _ = o.run(ctx, "op", o.args("item", "delete", o.title(id), "--vault", o.cfg.Vault), nil)

	item, err := json.Marshal(map[string]any{
		"title":    o.title(id),
		"category": "PASSWORD",
		"fields": []map[string]string{{
			"id":      "password",
			"type":    "CONCEALED",
			"purpose": "PASSWORD",
			"label":   "password",
			"value":   string(value),
		}},
	})
	if err != nil {
		return err
	}
	// op reads the item template from stdin when piped.
	if _, err := o.run(ctx, "op", o.args("item", "create", "--vault", o.cfg.Vault, "-"), item); err != nil {
		return fmt.Errorf("op put %s: %w", id, err)
	}
	return nil
}

func (o *Op) Delete(ctx context.Context, id string) error {
	_, err := o.run(ctx, "op", o.args("item", "delete", o.title(id), "--vault", o.cfg.Vault), nil)
	return err
}
