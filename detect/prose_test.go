/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestProse(t *testing.T) {
	fsys := textTree(map[string]string{
		"README.md": "# Project\n\nSome text.\nThis is licensed under the MIT License.\nMore text.\n",
		// Only the top level is read: a statement in a subdirectory describes
		// that subdirectory.
		"docs/README.md": "Licensed under the GPL.\n",
	})
	got := Prose(fsys)
	want := []ProseHint{{Path: "README.md", Line: 4, Excerpt: "This is licensed under the MIT License."}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Prose (-want, +got):\n%s", diff)
	}
}

// TestProseBoundsOneFile keeps a minified or generated README from deciding how
// large the result is.
func TestProseBoundsOneFile(t *testing.T) {
	var b strings.Builder
	for range maxProseHintsPerFile * 3 {
		b.WriteString("this file mentions a license\n")
	}
	b.WriteString("a very long line about the license " + strings.Repeat("x", maxProseExcerpt*2) + "\n")

	got := Prose(textTree(map[string]string{"NOTICE": b.String()}))
	if len(got) != maxProseHintsPerFile {
		t.Errorf("hints: got = %d, want the per-file cap of %d", len(got), maxProseHintsPerFile)
	}
	for _, h := range got {
		if len(h.Excerpt) > maxProseExcerpt+len("...") {
			t.Errorf("excerpt is %d bytes, want at most %d", len(h.Excerpt), maxProseExcerpt+len("..."))
		}
	}
}

func TestIsProseFile(t *testing.T) {
	for _, tt := range []struct {
		name string
		want bool
	}{
		{"README", true},
		{"README.md", true},
		{"COPYRIGHT", true},
		{"NOTICE", true},
		{"AUTHORS", true},
		{"COPYING.txt", true},
		{"CHANGELOG.md", false},
		{"main.go", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsProseFile(tt.name); got != tt.want {
				t.Errorf("IsProseFile(%q): got = %v, want = %v", tt.name, got, tt.want)
			}
		})
	}
}
