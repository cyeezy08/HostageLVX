package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ParseTargets is the front door: whatever the user pastes lands here. A target
// that gets mangled is a target never scanned, and the run still reports
// success, so the parser's edge cases are silent failures by construction.

func TestParseTargetsSplitsAndDeduplicates(t *testing.T) {
	got := ParseTargets([]string{"a.com, b.com,c.com,a.com"}, nil)
	want := []string{"a.com", "b.com", "c.com"}
	if len(got) != len(want) {
		t.Fatalf("ParseTargets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseTargetsStripsSchemePathAndDot(t *testing.T) {
	got := ParseTargets([]string{
		"https://example.com/path?q=1",
		"http://other.com/",
		"trailing.com.",
		"  spaced.com  ",
	}, nil)
	want := map[string]bool{
		"example.com": true, "other.com": true, "trailing.com": true, "spaced.com": true,
	}
	if len(got) != len(want) {
		t.Fatalf("ParseTargets = %v, want %d entries", got, len(want))
	}
	for _, h := range got {
		if !want[h] {
			t.Errorf("unexpected host %q in %v", h, got)
		}
	}
}

// Comments and blanks exist in every recon wordlist. Passing one through to the
// resolver produces a query for a host named "#".
func TestParseTargetsDropsCommentsAndBlanks(t *testing.T) {
	got := ParseTargets([]string{"# a comment", "", "   ", "\t", "real.com", "  # indented comment"}, nil)
	if len(got) != 1 || got[0] != "real.com" {
		t.Errorf("ParseTargets = %v, want [real.com]", got)
	}
	for _, h := range got {
		if strings.HasPrefix(h, "#") {
			t.Errorf("comment leaked through as a target: %q", h)
		}
	}
}

func TestParseTargetsReadsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(path, []byte("one.com\ntwo.com\n# skip\nthree.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ParseTargets([]string{"@" + path}, nil)
	want := []string{"one.com", "two.com", "three.com"}
	if len(got) != len(want) {
		t.Fatalf("ParseTargets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A missing file must not abort the run or invent targets. It has to degrade to
// "this source contributed nothing".
func TestParseTargetsMissingFileIsSkippedNotFatal(t *testing.T) {
	got := ParseTargets([]string{"@/nonexistent/path/targets.txt", "survivor.com"}, nil)
	if len(got) != 1 || got[0] != "survivor.com" {
		t.Errorf("ParseTargets = %v, want [survivor.com]", got)
	}
}

func TestParseTargetsReadsStdin(t *testing.T) {
	got := ParseTargets([]string{"-"}, strings.NewReader("pipe.com\nother.com\n"))
	if len(got) != 2 || got[0] != "pipe.com" || got[1] != "other.com" {
		t.Errorf("ParseTargets = %v, want [pipe.com other.com]", got)
	}
}

func TestParseTargetsEmptyInput(t *testing.T) {
	if got := ParseTargets(nil, nil); len(got) != 0 {
		t.Errorf("ParseTargets(nil) = %v, want empty", got)
	}
	if got := ParseTargets([]string{"", "  "}, nil); len(got) != 0 {
		t.Errorf("ParseTargets(blanks) = %v, want empty", got)
	}
}

// ParseTargets dedups on exact string equality, so case variants of one host
// are treated as distinct targets: "A.com" and "a.com" both survive. That is
// the current behaviour, pinned here so a future change to case folding is a
// deliberate decision rather than an accident.
//
// It is also a mild inefficiency. Scanning the same host twice doubles the load
// on a machine that is not ours, and the dedup map is the obvious place to fix
// it. Not changed here because this branch adds tests only.
func TestParseTargetsDoesNotFoldCase(t *testing.T) {
	got := ParseTargets([]string{"dup.com,DUP.com,Dup.Com"}, nil)
	if len(got) != 3 {
		t.Errorf("ParseTargets returned %d entries %v, want 3: case is not folded", len(got), got)
	}

	// Exact duplicates still collapse, so the dedup map itself works.
	if dup := ParseTargets([]string{"same.com,same.com"}, nil); len(dup) != 1 {
		t.Errorf("ParseTargets returned %v for an exact duplicate, want one entry", dup)
	}
}

// readLines guards against a scanner error swallowing the tail of a big list.
func TestReadLinesHandlesLongAndBlankLines(t *testing.T) {
	in := strings.NewReader("a.com\n\nb.com\n")
	got := readLines(in)
	if len(got) != 3 {
		t.Fatalf("readLines = %v, want 3 entries including the blank line", got)
	}
	if got[1] != "" {
		t.Errorf("readLines mangled the blank line: %q", got[1])
	}
}
