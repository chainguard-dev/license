/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"testing"

	"chainguard.dev/license/spdx"
)

// gplNoticeOrLater is coreutils' own header, verbatim: the wording GNU projects
// actually use, wrapped across lines with comment leaders exactly as it appears
// in source. A shorter paraphrase does not match - the classifier needs the
// whole notice including the warranty paragraph.
const gplNoticeOrLater = `/* cat -- concatenate files and print on the standard output.
   Copyright (C) 1988-2026 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */
`

// gplNoticeOnly is the same shape granting no later versions.
const gplNoticeOnly = `/* something -- does a thing.
   Copyright (C) 2026 Somebody.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */
`

func heads(pairs ...string) []Notice {
	var out []Notice
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, Notice{Path: pairs[i], Text: pairs[i+1]})
	}
	return out
}

func testClassifier(t *testing.T) Classifier {
	t.Helper()
	c, err := NewClassifier()
	if err != nil {
		t.Fatalf("license.NewClassifier: %v", err)
	}
	return c
}

// TestGrantsFromSPDXTag covers the modern convention. The classifier does not
// recognize these at all, so they are read directly.
func TestGrantsFromSPDXTag(t *testing.T) {
	got := Grants(testClassifier(t), heads(
		"src/a.c", "/* SPDX-License-Identifier: LGPL-2.1-or-later */\n#include <stdio.h>\n",
		"src/b.c", "/* SPDX-License-Identifier: LGPL-2.1-or-later */\n",
	))
	if len(got) != 1 {
		t.Fatalf("grants: got = %+v, want one", got)
	}
	if got[0].Expression != "LGPL-2.1-or-later" || got[0].Source != "spdx-tag" || got[0].Files != 2 {
		t.Errorf("got = %+v", got[0])
	}
}

// TestGrantsFromProseNotice covers the older convention, which the classifier
// matches but reports under the bare license name with the grant hidden in the
// variant.
func TestGrantsFromProseNotice(t *testing.T) {
	for _, tt := range []struct {
		name, notice, want string
	}{
		{name: "or later", notice: gplNoticeOrLater, want: "GPL-3.0-or-later"},
		{name: "only", notice: gplNoticeOnly, want: "GPL-2.0-only"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := Grants(testClassifier(t), heads("src/a.c", tt.notice))
			if len(got) != 1 {
				t.Fatalf("grants: got = %+v, want one", got)
			}
			if got[0].Expression != tt.want {
				t.Errorf("expression: got = %q, want = %q", got[0].Expression, tt.want)
			}
			if got[0].Source != "header" {
				t.Errorf("source: got = %q, want = header", got[0].Source)
			}
		})
	}
}

// TestGrantsReportsAMixedTree keeps a genuine finding from being averaged away.
func TestGrantsReportsAMixedTree(t *testing.T) {
	got := Grants(testClassifier(t), heads(
		"src/a.c", gplNoticeOrLater,
		"src/b.c", gplNoticeOnly,
	))
	if len(got) < 2 {
		t.Fatalf("grants: got = %+v, want both grants reported", got)
	}

	// The two notices name different licenses, and a grant only resolves the
	// license it names: letting a tree's GPL-3.0 notice settle the suffix of a
	// GPL-2.0 license file would turn a real disagreement into a confident
	// wrong answer. (Both grants stated for one license is the other case, and
	// TestGrantForMixed covers it.)
	for _, tt := range []struct{ base, want string }{
		{base: "GPL-2.0", want: "GPL-2.0-only"},
		{base: "GPL-3.0", want: "GPL-3.0-or-later"},
	} {
		expr, matched := GrantFor(spdx.Normalize(tt.base), got)
		if matched != 1 || expr != tt.want {
			t.Errorf("%s: got = %q from %d grants, want %q from exactly one", tt.base, expr, matched, tt.want)
		}
	}
}

// TestGrantsOrderPutsTheMostAgreedFirst pins the order Grants returns, which
// callers rely on to read the tree's prevailing grant off the front. Nothing
// else asserted it, and the ordering is easy to invert without a test noticing.
func TestGrantsOrderPutsTheMostAgreedFirst(t *testing.T) {
	got := Grants(testClassifier(t), heads(
		"src/a.c", gplNoticeOrLater,
		"src/b.c", gplNoticeOrLater,
		"src/c.c", gplNoticeOnly,
	))
	if len(got) != 2 {
		t.Fatalf("grants: got = %+v, want two", got)
	}
	if got[0].Files <= got[1].Files {
		t.Errorf("order: got = %d then %d files, want the most-agreed grant first", got[0].Files, got[1].Files)
	}
}

func TestGrantsFromNoNotice(t *testing.T) {
	got := Grants(testClassifier(t), heads("src/a.c", "#include <stdio.h>\nint main(void){return 0;}\n"))
	if len(got) != 0 {
		t.Errorf("grants: got = %+v, want none", got)
	}
}

// TestGrantForRequiresTheSameBaseLicense stops a tree's GPL notices from
// resolving the suffix of an unrelated LGPL license file.
func TestGrantForRequiresTheSameBaseLicense(t *testing.T) {
	grants := []Grant{{Expression: "GPL-3.0-or-later", Files: 8}}

	if expr, n := GrantFor(spdx.Normalize("GPL-3.0"), grants); n != 1 || expr != "GPL-3.0-or-later" {
		t.Errorf("same base: got = %q,%d, want GPL-3.0-or-later,1", expr, n)
	}
	if _, n := GrantFor(spdx.Normalize("LGPL-3.0"), grants); n != 0 {
		t.Errorf("different base: got %d matches, want 0", n)
	}
	if _, n := GrantFor(spdx.Normalize("MIT"), grants); n != 0 {
		t.Errorf("a license with no version grant must match nothing, got %d", n)
	}
}

func TestGrantForMixed(t *testing.T) {
	grants := []Grant{
		{Expression: "GPL-2.0-or-later", Files: 3},
		{Expression: "GPL-2.0-only", Files: 2},
	}
	if _, n := GrantFor(spdx.Normalize("GPL-2.0"), grants); n != 2 {
		t.Errorf("got %d matches, want 2 so the caller can escalate", n)
	}
}
