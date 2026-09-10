package inspect

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/aspex-security/aspex/internal/discover"
)

func staticEntries(n int) []discover.ServerEntry {
	out := make([]discover.ServerEntry, n)
	for i := range out {
		out[i] = discover.ServerEntry{Name: fmt.Sprintf("srv-%02d", i), Client: "claude", Command: "npx", Args: []string{"-y", "pkg@1.0.0"}}
	}
	return out
}

func TestInspectAllPreservesOrder(t *testing.T) {
	entries := staticEntries(25)
	var started int32
	res := InspectAll(context.Background(), entries, Options{NoExec: true, Concurrency: 4}, func(string) { atomic.AddInt32(&started, 1) })
	if len(res) != len(entries) {
		t.Fatalf("len = %d, want %d", len(res), len(entries))
	}
	for i, s := range res {
		if s == nil {
			t.Fatalf("result %d is nil", i)
		}
		if s.Entry.Name != entries[i].Name {
			t.Errorf("result %d = %s, want %s (order not preserved)", i, s.Entry.Name, entries[i].Name)
		}
		if !s.StaticOnly {
			t.Errorf("%s: NoExec should yield StaticOnly", s.Entry.Name)
		}
	}
	if int(started) != len(entries) {
		t.Errorf("progress called %d times, want %d", started, len(entries))
	}
}

func TestInspectAllEmptyAndDefaults(t *testing.T) {
	if res := InspectAll(context.Background(), nil, Options{}, nil); len(res) != 0 {
		t.Fatal("empty input must return empty result")
	}
	// Concurrency 0 falls back to the default and must not deadlock on a tiny input.
	res := InspectAll(context.Background(), staticEntries(2), Options{NoExec: true}, nil)
	if len(res) != 2 {
		t.Fatal("default concurrency path failed")
	}
}
