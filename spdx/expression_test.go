/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package spdx

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestIdentifiersIsTheExposureView pins the rule the whole set exists for:
// every OR branch contributes, because this package elects no branch, and a
// WITH form stays one identifier because the exception is what makes the terms
// bearable.
func TestIdentifiersIsTheExposureView(t *testing.T) {
	for _, tt := range []struct {
		expr string
		want []string
	}{
		{expr: "MIT", want: []string{"MIT"}},
		{expr: "MIT OR Apache-2.0", want: []string{"Apache-2.0", "MIT"}},
		{expr: "MPL-2.0 AND MIT", want: []string{"MIT", "MPL-2.0"}},
		{expr: "(MPL-2.0 AND MIT)", want: []string{"MIT", "MPL-2.0"}},
		{expr: "MIT OR (Apache-2.0 AND BSD-3-Clause)", want: []string{"Apache-2.0", "BSD-3-Clause", "MIT"}},
		{
			// One member, not two. Splitting it would report the GPL's
			// obligations without the exception that removes them.
			expr: "GPL-2.0-only WITH Classpath-exception-2.0",
			want: []string{"GPL-2.0-only WITH Classpath-exception-2.0"},
		},
		{
			expr: "EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0",
			want: []string{"EPL-2.0", "GPL-2.0-only WITH Classpath-exception-2.0"},
		},
		// The deprecated or-later shorthand is an identifier, not an operator.
		{expr: "GPL-2.0+", want: []string{"GPL-2.0+"}},
		// A LicenseRef is a legal operand, and one this module mints itself.
		{expr: "MIT OR LicenseRef-v1-0123456789abcdef", want: []string{"LicenseRef-v1-0123456789abcdef", "MIT"}},
		// Whole-identifier comparison: GPL-2.0 must not be found inside
		// LGPL-2.0.
		{expr: "LGPL-2.0-only", want: []string{"LGPL-2.0-only"}},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			e, err := Parse(tt.expr)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.expr, err)
			}
			if diff := cmp.Diff(tt.want, e.Identifiers()); diff != "" {
				t.Errorf("Identifiers (-want, +got):\n%s", diff)
			}
		})
	}
}

// TestSatisfies covers the evaluation naive substring matching gets wrong in
// the direction that matters: an OR is satisfied by any one branch, so
// "MIT OR GPL-3.0-only" is acceptable to a consumer that accepts MIT.
func TestSatisfies(t *testing.T) {
	accept := func(allowed ...string) func(string) bool {
		return func(id string) bool { return slices.Contains(allowed, id) }
	}

	for _, tt := range []struct {
		name   string
		expr   string
		accept func(string) bool
		want   bool
	}{
		{name: "a single accepted license", expr: "MIT", accept: accept("MIT"), want: true},
		{name: "a single rejected license", expr: "GPL-3.0-only", accept: accept("MIT"), want: false},
		{name: "either branch of a choice suffices", expr: "MIT OR GPL-3.0-only", accept: accept("MIT"), want: true},
		{name: "the other branch also suffices", expr: "GPL-3.0-only OR MIT", accept: accept("MIT"), want: true},
		{name: "a choice with no acceptable branch", expr: "GPL-3.0-only OR AGPL-3.0-only", accept: accept("MIT"), want: false},
		{name: "a conjunction needs every part", expr: "MIT AND GPL-3.0-only", accept: accept("MIT"), want: false},
		{name: "a conjunction fully accepted", expr: "MIT AND Apache-2.0", accept: accept("MIT", "Apache-2.0"), want: true},
		{
			// AND binds tighter than OR, so this is MIT or (both of the
			// others), and accepting MIT alone satisfies it.
			name:   "precedence: AND binds tighter than OR",
			expr:   "MIT OR Apache-2.0 AND GPL-3.0-only",
			accept: accept("MIT"),
			want:   true,
		},
		{
			// The same operands grouped the other way are not satisfied,
			// which is what the parentheses are for.
			name:   "grouping overrides precedence",
			expr:   "(MIT OR Apache-2.0) AND GPL-3.0-only",
			accept: accept("MIT"),
			want:   false,
		},
		{
			// The exception is part of what is being accepted, so a consumer
			// can accept a license only under one.
			name:   "an exception is part of the identifier",
			expr:   "GPL-2.0-only WITH Classpath-exception-2.0",
			accept: accept("GPL-2.0-only WITH Classpath-exception-2.0"),
			want:   true,
		},
		{
			name:   "the same license without its exception is a different thing",
			expr:   "GPL-2.0-only WITH Classpath-exception-2.0",
			accept: accept("GPL-2.0-only"),
			want:   false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, err := Parse(tt.expr)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.expr, err)
			}
			if got := e.Satisfies(tt.accept); got != tt.want {
				t.Errorf("Satisfies: got = %v, want = %v", got, tt.want)
			}
		})
	}
}

// TestStringRoundTrips verifies that rendering a parsed expression and parsing
// it again yields the same exposure set and the same evaluation, which is what
// makes String safe to store.
func TestStringRoundTrips(t *testing.T) {
	for _, expr := range []string{
		"MIT",
		"MIT OR Apache-2.0",
		"MIT AND Apache-2.0",
		"MIT OR Apache-2.0 AND BSD-3-Clause",
		"(MIT OR Apache-2.0) AND BSD-3-Clause",
		"GPL-2.0-only WITH Classpath-exception-2.0 OR EPL-2.0",
	} {
		t.Run(expr, func(t *testing.T) {
			first, err := Parse(expr)
			if err != nil {
				t.Fatalf("Parse(%q): %v", expr, err)
			}
			second, err := Parse(first.String())
			if err != nil {
				t.Fatalf("Parse(%q): %v", first.String(), err)
			}
			if diff := cmp.Diff(first.Identifiers(), second.Identifiers()); diff != "" {
				t.Errorf("identifiers changed across a round trip (-first, +second):\n%s", diff)
			}
			if first.String() != second.String() {
				t.Errorf("rendering is not stable: %q then %q", first.String(), second.String())
			}
		})
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, expr := range []string{
		"",
		"   ",
		"MIT OR",
		"OR MIT",
		"MIT AND AND Apache-2.0",
		"(MIT",
		"MIT)",
		"MIT WITH",
		"MIT WITH OR",
		"The Apache Software License, Version 2.0",
	} {
		t.Run(expr, func(t *testing.T) {
			if _, err := Parse(expr); err == nil {
				t.Errorf("Parse(%q): got nil error, want one", expr)
			}
		})
	}
}

// TestIdentifiersFallsBackForMetadata covers the reason the package-level
// function exists: declared metadata is frequently not an expression, and the
// identifiers it names are still worth comparing against what was detected.
func TestIdentifiersFallsBackForMetadata(t *testing.T) {
	for _, tt := range []struct {
		expr string
		want []string
	}{
		// Valid SPDX goes through the parser.
		{expr: "MIT OR Apache-2.0", want: []string{"Apache-2.0", "MIT"}},
		// Cargo's deprecated choice syntax. Left as one token it reads as a
		// single unknown identifier, and every crate using it looks like it
		// disagrees with itself.
		{expr: "MIT/Apache-2.0", want: []string{"Apache-2.0", "MIT"}},
		{expr: "MIT/Apache-2.0/BSD-3-Clause", want: []string{"Apache-2.0", "BSD-3-Clause", "MIT"}},
		// A comma-joined list is not an expression at all.
		{expr: "MIT, BSD-3-Clause", want: []string{"BSD-3-Clause", "MIT"}},
	} {
		t.Run(tt.expr, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, Identifiers(tt.expr)); diff != "" {
				t.Errorf("Identifiers (-want, +got):\n%s", diff)
			}
		})
	}
}

// TestIdentifiersKeepsTheExceptionWhole verifies the lenient path agrees with
// the parsed path on the one rule that is easy to get wrong.
func TestIdentifiersKeepsTheExceptionWhole(t *testing.T) {
	got := Identifiers("GPL-2.0-only WITH Classpath-exception-2.0")
	want := []string{"GPL-2.0-only WITH Classpath-exception-2.0"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Identifiers (-want, +got):\n%s", diff)
	}
}

// TestWithoutGrant covers the comparison a consumer cannot make honestly
// otherwise: a declaration that states a version grant is not in conflict with
// detection that structurally could not establish one.
func TestWithoutGrant(t *testing.T) {
	for _, tt := range []struct{ id, want string }{
		{id: "GPL-2.0-only", want: "GPL-2.0"},
		{id: "GPL-3.0-or-later", want: "GPL-3.0"},
		{id: "LGPL-2.1-only", want: "LGPL-2.1"},
		{id: "AGPL-3.0-or-later", want: "AGPL-3.0"},
		// No grant to remove.
		{id: "MIT", want: "MIT"},
		{id: "Apache-2.0", want: "Apache-2.0"},
		// An exception is not a grant: it changes what the license permits
		// rather than which versions of it apply, so it survives.
		{id: "GPL-2.0-only WITH Classpath-exception-2.0", want: "GPL-2.0 WITH Classpath-exception-2.0"},
		{id: "", want: ""},
	} {
		t.Run(tt.id, func(t *testing.T) {
			if got := WithoutGrant(tt.id); got != tt.want {
				t.Errorf("WithoutGrant(%q): got = %q, want = %q", tt.id, got, tt.want)
			}
		})
	}

	// The point of it: the two grants of one license compare equal once the
	// grant is set aside, and two different licenses still do not.
	if WithoutGrant("GPL-2.0-only") != WithoutGrant("GPL-2.0-or-later") {
		t.Error("the two grants of one license did not compare equal")
	}
	if WithoutGrant("GPL-2.0-only") == WithoutGrant("LGPL-2.0-only") {
		t.Error("GPL and LGPL compared equal")
	}
}
