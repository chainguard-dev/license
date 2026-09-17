/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package assess

import (
	"testing"

	"chainguard.dev/license/detect"
)

func TestChoiceOfLicense(t *testing.T) {
	for _, tt := range []struct {
		name    string
		excerpt string
		want    bool
	}{
		// The wordings upstreams actually use.
		{name: "rust convention", excerpt: "Licensed under either of Apache License, Version 2.0 or MIT license at your option.", want: true},
		{name: "dual licensed", excerpt: "This project is dual-licensed under MIT and Apache-2.0.", want: true},
		{name: "dual licenced", excerpt: "This crate is dual licenced (MIT/Apache-2.0).", want: true},
		{name: "either or", excerpt: "You may use this library under either the MIT license or the Apache 2.0 license.", want: true},
		{name: "your choice", excerpt: "Released under the GPL-2.0 or MPL-2.0 license, your choice.", want: true},
		{name: "any of the following", excerpt: "Available under any of the following licenses: MIT, Apache-2.0.", want: true},
		{name: "tri licensed", excerpt: "The library is tri-licensed: MPL-2.0, GPL-2.0, LGPL-2.1.", want: true},
		// rustix's own wording, which the abbreviated pattern missed.
		{name: "triple licensed", excerpt: "`rustix` is triple-licensed under Apache 2.0 with the LLVM Exception,", want: true},
		{name: "multi licensed", excerpt: "This package is multi-licensed; see the LICENSE files.", want: true},

		// A conjunction must never read as a choice: telling a consumer they may
		// pick the permissive license understates what they owe.
		{name: "conjunction", excerpt: "This work is licensed under the MIT license and the Apache-2.0 license.", want: false},
		{name: "both apply", excerpt: "Both licenses apply to this software.", want: false},
		{name: "subject to both", excerpt: "Use is subject to both licenses below.", want: false},

		// Prose that mentions a license without stating any relationship.
		{name: "plain statement", excerpt: "Released under the MIT license.", want: false},
		{name: "license file pointer", excerpt: "See the LICENSE file for details.", want: false},
		{name: "dependency note", excerpt: "Bundled dependencies retain their own licenses.", want: false},

		// "either ... or" outside a licensing construction is not a choice of
		// licenses, and reading it as one is the failure that matters.
		{name: "either file or file", excerpt: "Either the LICENSE file or the COPYING file applies.", want: false},
		{name: "either tool or tool", excerpt: "Build with either cmake or meson; see LICENSE for terms.", want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, got := ChoiceOfLicense([]detect.ProseHint{{Path: "README.md", Line: 3, Excerpt: tt.excerpt}})
			if got != tt.want {
				t.Errorf("got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func TestChoiceOfLicenseReportsTheLine(t *testing.T) {
	hints := []detect.ProseHint{
		{Path: "README.md", Line: 2, Excerpt: "See the LICENSE file."},
		{Path: "README.md", Line: 9, Excerpt: "Dual-licensed under MIT or Apache-2.0 at your option."},
	}
	got, ok := ChoiceOfLicense(hints)
	if !ok {
		t.Fatal("ChoiceOfLicense: got ok = false, want a choice to be found")
	}
	if got.Line != 9 {
		t.Errorf("line: got = %d, want = 9", got.Line)
	}
}

func TestChoiceOfLicenseNoHints(t *testing.T) {
	if _, ok := ChoiceOfLicense(nil); ok {
		t.Error("no hints cannot establish a choice")
	}
}
