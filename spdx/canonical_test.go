/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package spdx

import "testing"

func TestCanonicalize(t *testing.T) {
	for _, tt := range []struct {
		name string
		expr string
		want string
	}{
		{name: "slash becomes OR", expr: "MIT/Apache-2.0", want: "MIT OR Apache-2.0"},
		{name: "spaced slash", expr: "MIT / Apache-2.0", want: "MIT OR Apache-2.0"},
		{name: "three way", expr: "MIT/Apache-2.0/Zlib", want: "MIT OR Apache-2.0 OR Zlib"},
		{name: "already valid", expr: "MIT OR Apache-2.0", want: "MIT OR Apache-2.0"},
		{name: "conjunction untouched", expr: "MPL-2.0 AND MIT", want: "MPL-2.0 AND MIT"},
		{name: "empty", expr: "", want: ""},
		// A stray slash says nothing about a choice, so nothing is invented.
		{name: "trailing slash left alone", expr: "MIT/", want: "MIT/"},
		{name: "leading slash left alone", expr: "/MIT", want: "/MIT"},

		// Ecosystem metadata is mostly prose, and left alone none of it compares
		// equal to the identifier classification produces from the same files.
		{name: "prose naming one license", expr: "The Apache Software License, Version 2.0", want: "Apache-2.0"},
		{name: "a license URL", expr: "https://www.apache.org/licenses/LICENSE-2.0.txt", want: "Apache-2.0"},
		{name: "each operand of a choice is mapped", expr: "EPL 2.0 OR GPL2 w/ CPE", want: "EPL-2.0 OR GPL2 w/ CPE"},
		{name: "operator spelling normalized", expr: "MIT or Apache-2.0", want: "MIT OR Apache-2.0"},

		// Parentheses in a name are not grouping. Treating them as grouping sent
		// this through untouched, and it read as a divergence that was not one.
		{name: "prose containing parentheses", expr: "The MIT License (MIT)", want: "MIT"},
		// Parentheses in an expression are grouping, and a scan for infix
		// operators cannot respect it, so the expression is left whole.
		{name: "parenthesised expression preserved", expr: "(MIT OR Apache-2.0)", want: "(MIT OR Apache-2.0)"},
		// But a parenthesis inside a license name is not grouping, and must not
		// stop the operands beside it from being mapped.
		{
			name: "parenthesis inside a name does not block the other operands",
			expr: "EPL 2.0 OR The GNU General Public License (GPL), Version 2, With Classpath Exception",
			want: "EPL-2.0 OR The GNU General Public License (GPL), Version 2, With Classpath Exception",
		},

		// A slash appears in plenty of strings that are not a choice; splitting
		// this would invent "GPL2 w" and "CPE" as licenses.
		{name: "a slash that is not a choice", expr: "GPL2 w/ CPE", want: "GPL2 w/ CPE"},
		// The exception binds tighter than the operators split on here, and SPDX
		// carries no name data for license-plus-exception pairs.
		{name: "a WITH form left alone", expr: "GPL-2.0-only WITH Classpath-exception-2.0", want: "GPL-2.0-only WITH Classpath-exception-2.0"},
		// A bare family names no particular license, so resolving it would
		// invent a fact the metadata does not contain.
		{name: "unresolvable value unchanged", expr: "GPL", want: "GPL"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Canonicalize(tt.expr); got != tt.want {
				t.Errorf("got = %q, want = %q", got, tt.want)
			}
		})
	}
}
