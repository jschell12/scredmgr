package loginflow

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClipboard struct {
	mu  sync.Mutex
	val string
}

func (f *fakeClipboard) Read() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.val, nil
}

func (f *fakeClipboard) Clear() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.val = ""
	return nil
}

func (f *fakeClipboard) set(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.val = v
}

func TestWaitForTokenRequiresChangeAndPattern(t *testing.T) {
	stale := "ghp_" + strings.Repeat("a", 36)
	fresh := "ghp_" + strings.Repeat("b", 36)
	clip := &fakeClipboard{val: stale}
	pattern := regexp.MustCompile(`^ghp_[A-Za-z0-9]{36}$`)

	go func() {
		time.Sleep(20 * time.Millisecond)
		clip.set("not-a-token") // must be skipped: fails pattern
		time.Sleep(20 * time.Millisecond)
		clip.set(fresh)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := WaitForToken(ctx, clip, pattern, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got != fresh {
		t.Fatalf("got %q", got)
	}
}

func TestWaitForTokenTimesOut(t *testing.T) {
	clip := &fakeClipboard{val: "unchanged"}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := WaitForToken(ctx, clip, nil, 5*time.Millisecond); err == nil {
		t.Fatal("want timeout error")
	}
}

func TestWaitForTokenNoPatternAcceptsAnyChange(t *testing.T) {
	clip := &fakeClipboard{val: ""}
	go func() {
		time.Sleep(15 * time.Millisecond)
		clip.set("  some-token \n")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := WaitForToken(ctx, clip, nil, 5*time.Millisecond)
	if err != nil || got != "some-token" {
		t.Fatalf("got %q, %v", got, err)
	}
}
