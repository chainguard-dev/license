/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"fmt"
	"strings"
	"testing"
)

const gplNotice = `/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
#include <stdio.h>
`

func TestCollectSourceHeadsRetainsNotices(t *testing.T) {
	fsys := textTree(map[string]string{
		"src/main.c":   gplNotice,
		"src/util.c":   gplNotice,
		"README.md":    "not a source file",
		"COPYING":      "the entire GPL text, which must never be sampled",
		"LICENSE":      "ditto",
		"src/data.bin": "\x00\x01\x02binary",
	})

	heads, total := Notices(fsys)
	if total != 2 {
		t.Errorf("notices read: got = %d, want = 2 (only the .c files)", total)
	}
	byPath := map[string]Notice{}
	for _, h := range heads {
		byPath[h.Path] = h
	}
	for _, p := range []string{"src/main.c", "src/util.c"} {
		if _, ok := byPath[p]; !ok {
			t.Errorf("missing %q in %v", p, byPath)
		}
	}
	if !strings.Contains(byPath["src/main.c"].Text, "any later version") {
		t.Error("the notice must survive into the head")
	}
}

// TestCollectSourceHeadsNeverSamplesLicenseFiles is the one that matters most:
// every copy of the GPL states "any later version" three times in its own body,
// so a sampled COPYING would report a later-version grant for every GPL project
// that exists.
func TestCollectSourceHeadsNeverSamplesLicenseFiles(t *testing.T) {
	fsys := textTree(map[string]string{
		"COPYING":    "GNU GENERAL PUBLIC LICENSE ... any later version ...",
		"LICENSE.c":  "a license file that looks like source",
		"COPYING.sh": "ditto",
		"src/real.c": gplNotice,
	})
	heads, _ := Notices(fsys)
	for _, h := range heads {
		if is, _ := IsLicenseFile(h.Path); is {
			t.Errorf("sampled a license file: %q", h.Path)
		}
	}
	if len(heads) != 1 || heads[0].Path != "src/real.c" {
		t.Errorf("heads: got = %v, want only src/real.c", heads)
	}
}

func TestCollectSourceHeadsSkipsExcludedTrees(t *testing.T) {
	fsys := textTree(map[string]string{
		"src/main.c":                gplNotice,
		"vendor/dep/dep.c":          gplNotice,
		"testdata/fixture.c":        gplNotice,
		"examples/demo/demo.c":      gplNotice,
		"third_party/other/other.c": gplNotice,
	})
	heads, total := Notices(fsys)
	if total != 1 {
		t.Errorf("notices read: got = %d, want = 1; a vendored or fixture notice is not this component's grant", total)
	}
	if len(heads) != 1 || heads[0].Path != "src/main.c" {
		t.Errorf("heads: got = %v, want only src/main.c", heads)
	}
}

// TestCollectSourceHeadsSkipsBuildOutput covers the workspace layout an audit is
// actually pointed at: melange stages the built tree beside the source it was
// built from. Everything a Python build installs into site-packages is a
// dependency's source carrying a dependency's notices, and the sample exists to
// establish this component's version grant.
func TestCollectSourceHeadsSkipsBuildOutput(t *testing.T) {
	fsys := textTree(map[string]string{
		"src/main.py": "# no notice here\n",
		"melange-out/py3-foo/usr/lib/python3.13/site-packages/dep/mod.py": gplNotice,
	})
	heads, total := Notices(fsys)
	if total != 1 {
		t.Errorf("candidates: got = %d, want = 1; the installed tree is not this component's source", total)
	}
	if len(heads) != 1 || heads[0].Path != "src/main.py" {
		t.Errorf("heads: got = %v, want only src/main.py", heads)
	}
}

// TestCollectSourceHeadsIsBoundedAndDeterministic pins the two properties the
// bundle depends on: it cannot grow without limit, and the same tree must yield
// the same bundle every time or content-addressing stops deduplicating.
func TestCollectSourceHeadsIsBoundedAndDeterministic(t *testing.T) {
	files := map[string]string{}
	for i := range 200 {
		files[fmt.Sprintf("src/f%03d.c", i)] = gplNotice
	}
	fsys := textTree(files)

	first, total := Notices(fsys)
	// The count reports notices read, so under the cap it equals the sample.
	// Reporting the 200 candidates instead would say evidence was read that
	// the cap means was never opened.
	if total != len(first) {
		t.Errorf("notices read: got = %d, want = %d, the size of the sample", total, len(first))
	}
	if len(first) > MaxNoticeFiles {
		t.Errorf("sample size: got = %d, want <= %d", len(first), MaxNoticeFiles)
	}
	if len(first) < 2 {
		t.Fatalf("sample too small to be useful: %d", len(first))
	}
	for range 3 {
		again, _ := Notices(fsys)
		if len(again) != len(first) {
			t.Fatalf("sample size varies between runs: %d vs %d", len(again), len(first))
		}
		for i := range first {
			if again[i].Path != first[i].Path {
				t.Fatalf("sample varies between runs at %d: %q vs %q", i, again[i].Path, first[i].Path)
			}
		}
	}
	// A stride rather than the first N, so a differently-licensed subtree is
	// represented instead of being alphabetically excluded.
	if first[len(first)-1].Path == "src/f001.c" {
		t.Error("sample looks like the first N rather than a spread")
	}
}

func TestCollectSourceHeadsTruncates(t *testing.T) {
	fsys := textTree(map[string]string{
		"src/big.c": gplNotice + strings.Repeat("x", MaxNoticeBytes*2),
	})
	heads, _ := Notices(fsys)
	if len(heads) != 1 {
		t.Fatalf("heads: got = %d, want = 1", len(heads))
	}
	if !heads[0].Truncated {
		t.Error("a file past the bound must be marked truncated")
	}
	if len(heads[0].Text) != MaxNoticeBytes {
		t.Errorf("content: got = %d bytes, want = %d", len(heads[0].Text), MaxNoticeBytes)
	}
}

func TestCollectSourceHeadsEmptyTree(t *testing.T) {
	heads, total := Notices(textTree(map[string]string{"README.md": "nothing here"}))
	if len(heads) != 0 || total != 0 {
		t.Errorf("got = %v,%d, want no heads", heads, total)
	}
}

// TestCollectSourceHeadsCountsOnlyWhatItRead pins the count to files that were
// actually read. Counting candidates instead lets a tree whose sources cannot
// be opened report that notices were checked and none granted later versions,
// which settles a GPL component as -only on no evidence at all.
func TestCollectSourceHeadsCountsOnlyWhatItRead(t *testing.T) {
	// main.c is listed but not in the map, so it is selected as a candidate and
	// fails at the read, where a permission-denied source file fails.
	fsys := unreadable{MapFS: textTree(map[string]string{"README.md": "not a source file"}), name: "main.c"}

	heads, total := Notices(fsys)
	if len(heads) != 0 {
		t.Errorf("heads: got = %v, want none; the only source file cannot be opened", heads)
	}
	if total != 0 {
		t.Errorf("notices read: got = %d, want = 0; the candidate was found but never read", total)
	}

	// The count is what Conclude reads, so state the consequence too.
	res := &Result{Files: []File{{Path: "COPYING", License: "GPL-2.0", Confidence: 1, SizeBytes: 100}}}
	if c := res.Conclude(GrantEvidence{Grants: Grants(nil, heads), Sampled: total}); c.GrantBasis != GrantUnknown {
		t.Errorf("GrantBasis: got = %q, want = %q; nothing was read, so the grant is unknown rather than absent", c.GrantBasis, GrantUnknown)
	}
}
