package provider

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/jschell12/scredmanager/internal/safety"
)

// Lastpass is a pull-only provider over the `lpass` CLI. The upstream CLI is
// unmaintained, so it is deliberately kept out of the write path: Put and
// Delete return ErrReadOnly and sync --push is refused via Writable().
// Intended for break-glass recovery of secrets that already live in LastPass.
type Lastpass struct {
	name string
	cfg  LastpassCfg
	run  Runner
}

// NewLastpass returns a read-only LastPass provider backed by run.
func NewLastpass(name string, cfg LastpassCfg, run Runner) *Lastpass {
	return &Lastpass{name: name, cfg: cfg, run: run}
}

func (l *Lastpass) Name() string   { return l.name }
func (l *Lastpass) Writable() bool { return false }

func (l *Lastpass) entry(id string) string { return l.cfg.Folder + "/" + id }

func (l *Lastpass) Check(ctx context.Context) error {
	if _, err := l.run(ctx, "lpass", []string{"status"}, nil); err != nil {
		return fmt.Errorf("lpass auth: %w (hint: run `lpass login <email>`)", err)
	}
	return nil
}

func (l *Lastpass) List(ctx context.Context) ([]string, error) {
	// %an prints the full account name including the folder path.
	out, err := l.run(ctx, "lpass", []string{"ls", "--format", "%an", l.cfg.Folder}, nil)
	if err != nil {
		return nil, err
	}
	prefix := l.cfg.Folder + "/"
	var ids []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == l.cfg.Folder || strings.HasSuffix(line, "/") {
			continue // blank or the folder marker itself
		}
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		ids = append(ids, strings.TrimPrefix(line, prefix))
	}
	return ids, nil
}

func (l *Lastpass) Get(ctx context.Context, id string) ([]byte, error) {
	out, err := l.run(ctx, "lpass", []string{"show", "--password", l.entry(id)}, nil)
	if err != nil {
		return nil, err
	}
	secret := bytes.TrimRight(out, "\n")
	if len(secret) == 0 {
		return nil, fmt.Errorf("lpass get %s: empty password", id)
	}
	safety.Track(secret)
	return secret, nil
}

func (l *Lastpass) Put(context.Context, string, []byte) error {
	return fmt.Errorf("lastpass provider %s: %w", l.name, ErrReadOnly)
}

func (l *Lastpass) Delete(context.Context, string) error {
	return fmt.Errorf("lastpass provider %s: %w", l.name, ErrReadOnly)
}
