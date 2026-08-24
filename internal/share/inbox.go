package share

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jschell12/scredmgr/internal/store"
)

// The inbox spools payloads that could not be stored on arrival — typically
// because the receiver's login keychain is locked (non-interactive ssh).
// Blobs are AES-256-GCM sealed with a machine-local key so spooled secrets
// are never at rest in cleartext; `scredmgr inbox import` drains them from a
// GUI session where the keychain is unlockable.

const (
	inboxKeyFile = "inbox.key"
	inboxSubdir  = "inbox"
)

func inboxDir() (string, error) {
	home, err := store.HomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, inboxSubdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func inboxGCM() (cipher.AEAD, error) {
	home, err := store.HomeDir()
	if err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(filepath.Join(home, inboxKeyFile))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// loadOrCreateKey returns the 32-byte key at path, generating it O_EXCL 0600
// on first use.
func loadOrCreateKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, fmt.Errorf("%s: expected 32-byte key, got %d bytes", path, len(key))
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return loadOrCreateKey(path) // lost a creation race
		}
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, err
	}
	return key, nil
}

// Spool seals the payload into a new inbox blob and returns its path.
func Spool(p *Payload) (string, error) {
	data, err := p.Encode()
	if err != nil {
		return "", err
	}
	dir, err := inboxDir()
	if err != nil {
		return "", err
	}
	aead, err := inboxGCM()
	if err != nil {
		return "", err
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%d-%s.enc", time.Now().UnixNano(), hex.EncodeToString(suffix))
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	// The filename as AAD binds each blob to its own name.
	blob := append(nonce, aead.Seal(nil, nonce, data, []byte(name))...)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// SpoolInfo summarizes one spooled blob (ids are non-secret).
type SpoolInfo struct {
	Path   string   `json:"path"`
	From   string   `json:"from"`
	SentAt string   `json:"sentAt"`
	IDs    []string `json:"ids"`
}

// ListSpooled returns all inbox blobs, oldest first.
func ListSpooled() ([]SpoolInfo, error) {
	dir, err := inboxDir()
	if err != nil {
		return nil, err
	}
	names, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var infos []SpoolInfo
	for _, d := range names {
		if d.IsDir() || filepath.Ext(d.Name()) != ".enc" {
			continue
		}
		path := filepath.Join(dir, d.Name())
		p, err := OpenSpooled(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.Name(), err)
		}
		info := SpoolInfo{Path: path, From: p.From, SentAt: p.SentAt}
		for _, e := range p.Entries {
			info.IDs = append(info.IDs, e.ID)
		}
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Path < infos[j].Path })
	return infos, nil
}

// OpenSpooled decrypts and parses one inbox blob.
func OpenSpooled(path string) (*Payload, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	aead, err := inboxGCM()
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize() {
		return nil, fmt.Errorf("blob too short")
	}
	nonce, ct := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	data, err := aead.Open(nil, nonce, ct, []byte(filepath.Base(path)))
	if err != nil {
		return nil, fmt.Errorf("decrypt failed (wrong key or tampered blob): %w", err)
	}
	return Decode(bytes.NewReader(data))
}

// RemoveSpooled deletes a drained blob.
func RemoveSpooled(path string) error {
	return os.Remove(path)
}
