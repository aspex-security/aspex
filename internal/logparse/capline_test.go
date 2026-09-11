package logparse

import (
	"bufio"
	"strings"
	"testing"
)

// A single log line without a newline must not grow memory without bound.
// readLineCapped returns a capped prefix and resumes at the next line.
func TestReadLineCappedBoundsHugeLines(t *testing.T) {
	huge := strings.Repeat("A", maxLogLine+5_000_000) // well over the cap, no newline inside
	input := huge + "\n" + `{"ok":true}` + "\n"
	r := bufio.NewReaderSize(strings.NewReader(input), 64*1024)

	line1, err := readLineCapped(r)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if len(line1) > maxLogLine+1 { // +1 for a possible trailing newline within the cap window
		t.Errorf("line was not capped: %d bytes", len(line1))
	}
	// Parsing continues: the next line is intact.
	line2, _ := readLineCapped(r)
	if strings.TrimSpace(line2) != `{"ok":true}` {
		t.Errorf("next line should be intact after a capped line, got %q", line2)
	}
}

func TestReadLineCappedNormalLines(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("a\nbb\n"), 64*1024)
	for _, want := range []string{"a\n", "bb\n"} {
		got, _ := readLineCapped(r)
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
}
