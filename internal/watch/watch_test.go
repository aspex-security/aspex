package watch_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aspex-security/aspex/internal/watch"
)

func TestWatchFiresOnContentChangeNotOnNoop(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "mcp.json")
	os.WriteFile(p, []byte(`{"a":1}`), 0o644)
	w := watch.New([]string{p}, 200*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 8)
	go w.Watch(ctx, func(path string) { got <- path })
	time.Sleep(150 * time.Millisecond) // let the watcher arm

	// Editor-style save: write via temp file and rename.
	tmp := p + ".tmp"
	os.WriteFile(tmp, []byte(`{"a":2}`), 0o644)
	os.Rename(tmp, p)
	select {
	case path := <-got:
		if path != p {
			t.Errorf("path = %s", path)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no change event after a rename-save")
	}
	// Deletion is a change too.
	os.Remove(p)
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("no event on deletion")
	}
}

func TestWatchDebouncesBursts(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.json")
	os.WriteFile(p, []byte("1"), 0o644)
	w := watch.New([]string{p}, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 64)
	go w.Watch(ctx, func(path string) { got <- path })
	time.Sleep(150 * time.Millisecond)
	for i := 0; i < 5; i++ {
		os.WriteFile(p, []byte{byte('a' + i)}, 0o644)
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(900 * time.Millisecond)
	if n := len(got); n == 0 || n > 2 {
		t.Errorf("5 rapid writes should yield 1 (at most 2) rescans, got %d", n)
	}
}
