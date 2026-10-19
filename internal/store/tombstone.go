package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Stamp formats a local metadata timestamp. Nanosecond precision, so a value
// written within the same second as a remote copy still orders correctly;
// time.Parse(time.RFC3339, ...) accepts it.
func Stamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// Tombstones record ids removed with `rm`, so a scheduled pull does not
// recreate them from an older remote copy. Stored as id -> RFC3339Nano in
// ~/.scredmgr/.tombstones.json (dot-prefixed: never listed as an entry).
const tombstoneFile = ".tombstones.json"

func tombstonePath() (string, error) {
	dir, err := HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, tombstoneFile), nil
}

func readTombstones() (map[string]string, error) {
	p, err := tombstonePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// RecordTombstone marks id as deleted locally at t (atomic write, 0600).
func RecordTombstone(id string, t time.Time) error {
	m, err := readTombstones()
	if err != nil {
		return err
	}
	m[id] = Stamp(t)
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	p, err := tombstonePath()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), tombstoneFile+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Tombstone returns when id was removed locally, if it was. An unreadable
// tombstone file is reported as an error so callers can fail closed.
func Tombstone(id string) (time.Time, bool, error) {
	m, err := readTombstones()
	if err != nil {
		return time.Time{}, false, err
	}
	s, ok := m[id]
	if !ok {
		return time.Time{}, false, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		// Present but unparseable: treat as "deleted just now", the safe side.
		return time.Now(), true, nil
	}
	return t, true, nil
}
