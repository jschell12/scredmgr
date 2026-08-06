package cli

import (
	"fmt"
	"sort"

	"github.com/jschell12/scredmanager/internal/safety"
	"github.com/jschell12/scredmanager/internal/store"
)

// envPair is one resolved entry ready for env injection.
type envPair struct {
	ID     string
	EnvVar string
	Secret []byte
}

// resolveEnv resolves which entries to inject for a namespace path.
//
// Root entries (ids without a path) form the base. When path is non-empty,
// entries directly under that path overlay the base, overriding any base
// entry that maps to the same EnvVar. With path == "", only root entries are
// injected. only, when non-nil, restricts resolution to the listed ids
// (matched against the full id, e.g. "work/jira").
//
// The returned matched count is the number of entries that passed the only
// filter and carry an EnvVar — before overlay collapsing — so callers can
// detect --only entries that matched nothing.
func resolveEnv(path string, only map[string]bool, s store.Store) (pairs []envPair, matched int, err error) {
	if path != "" {
		if err := store.ValidateID(path); err != nil {
			return nil, 0, fmt.Errorf("invalid path: %w", err)
		}
	}
	ids, err := store.ListIDs()
	if err != nil {
		return nil, 0, err
	}
	sort.Strings(ids)

	var base, overlay []string
	for _, id := range ids {
		switch store.PathOf(id) {
		case "":
			base = append(base, id)
		case path:
			if path != "" {
				overlay = append(overlay, id)
			}
		}
	}

	var order []string
	byVar := make(map[string]envPair)
	add := func(id string) error {
		if only != nil && !only[id] {
			return nil
		}
		m, err := store.LoadAndMigrate(id, s)
		if err != nil {
			return err
		}
		if m.EnvVar == "" {
			return nil
		}
		secret, err := store.GetSecret(id, s)
		if err != nil {
			return fmt.Errorf("fetch %s: %w", id, err)
		}
		safety.Track(secret)
		if _, seen := byVar[m.EnvVar]; !seen {
			order = append(order, m.EnvVar)
		}
		byVar[m.EnvVar] = envPair{ID: id, EnvVar: m.EnvVar, Secret: secret}
		matched++
		return nil
	}
	for _, id := range base {
		if err := add(id); err != nil {
			return nil, 0, err
		}
	}
	for _, id := range overlay {
		if err := add(id); err != nil {
			return nil, 0, err
		}
	}

	for _, v := range order {
		pairs = append(pairs, byVar[v])
	}
	return pairs, matched, nil
}
