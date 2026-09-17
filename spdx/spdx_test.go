/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package spdx

import "testing"

func TestNormalizeCurrentIdentifiersPassThrough(t *testing.T) {
	for _, id := range []string{"MIT", "Apache-2.0", "BSD-3-Clause", "Unicode-3.0", "0BSD"} {
		t.Run(id, func(t *testing.T) {
			got := Normalize(id)
			if got.ID != id {
				t.Errorf("got = %+v, want ID = %q", got, id)
			}
			if got.NeedsGrant() {
				t.Error("a current identifier needs no grant")
			}
		})
	}
}

// TestNormalizeNonSPDXClassifierNames covers names licenseclassifier emits that
// were never SPDX. Left alone they reach a licenseConcluded field as invalid
// identifiers and never compare equal to a declaration.
func TestNormalizeNonSPDXClassifierNames(t *testing.T) {
	for _, tt := range []struct{ name, want string }{
		{"BSD-0-Clause", "0BSD"},
		{"Apache-with-LLVM-Exception", "Apache-2.0 WITH LLVM-exception"},
		{"BSD-2-Clause-FreeBSD", "BSD-2-Clause-Views"},
		{"OpenLDAP", "OLDAP-2.8"},
		{"PNG", "libpng-2.0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Normalize(tt.name); got.ID != tt.want {
				t.Errorf("got = %+v, want ID = %q", got, tt.want)
			}
		})
	}
}

// TestNormalizeGPLFamilyNeedsAGrant pins the one class that cannot be
// normalized: SPDX ships identical text for -only and -or-later, so the
// classifier structurally cannot tell them apart and neither can this package.
func TestNormalizeGPLFamilyNeedsAGrant(t *testing.T) {
	for _, tt := range []struct{ name, base, only, later string }{
		{"LGPL-3.0", "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later"},
		{"GPL-2.0", "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later"},
		{"AGPL-3.0", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later"},
		{
			"GPL-2.0-with-classpath-exception", "GPL-2.0",
			"GPL-2.0-only WITH Classpath-exception-2.0",
			"GPL-2.0-or-later WITH Classpath-exception-2.0",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := Normalize(tt.name)
			if !got.NeedsGrant() {
				t.Fatalf("got = %+v, want a grant to be needed", got)
			}
			if got.GrantBase != tt.base || got.Only != tt.only || got.OrLater != tt.later {
				t.Errorf("got = %+v, want base=%q only=%q orLater=%q", got, tt.base, tt.only, tt.later)
			}
			if got.ID != "" {
				t.Errorf("an undecided grant must not yield an identifier, got %q", got.ID)
			}
		})
	}
}

// TestNormalizeUnlistedLicenseStaysARef keeps genuinely non-SPDX licenses off
// the list rather than forcing them onto the nearest match.
func TestNormalizeUnlistedLicenseStaysARef(t *testing.T) {
	for _, name := range []string{"AdColony-SDK", "Commons-Clause", "Waymo1P", "KUKA"} {
		t.Run(name, func(t *testing.T) {
			got := Normalize(name)
			if got.Ref != name {
				t.Errorf("got = %+v, want Ref = %q", got, name)
			}
			if got.Known() {
				t.Error("an unlisted license must not report as known")
			}
		})
	}
}

func TestFromText(t *testing.T) {
	for _, tt := range []struct {
		name, in, want string
	}{
		{name: "spdx name", in: "Apache License 2.0", want: "Apache-2.0"},
		{name: "pom phrasing", in: "The Apache Software License, Version 2.0", want: "Apache-2.0"},
		{name: "npm phrasing", in: "MIT License", want: "MIT"},
		{name: "bare url", in: "https://www.apache.org/licenses/LICENSE-2.0", want: "Apache-2.0"},
		{name: "url with extension", in: "http://www.apache.org/licenses/LICENSE-2.0.txt", want: "Apache-2.0"},
		{name: "eclipse url", in: "https://www.eclipse.org/legal/epl-2.0/", want: "EPL-2.0"},
		{name: "identifier", in: "BSD-3-Clause", want: "BSD-3-Clause"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := FromText(tt.in)
			if !ok || got != tt.want {
				t.Errorf("got = %q,%v, want = %q,true", got, ok, tt.want)
			}
		})
	}
}

// TestFromTextRefusesBareFamilies is the important negative: a metadata string
// naming no particular license must not be resolved to a guess.
func TestFromTextRefusesBareFamilies(t *testing.T) {
	for _, in := range []string{"GPL", "BSD", "PROPRIETARY", "Public Domain", ""} {
		t.Run(in, func(t *testing.T) {
			if got, ok := FromText(in); ok {
				t.Errorf("resolved %q to %q; it names no particular license", in, got)
			}
		})
	}
}

func TestTag(t *testing.T) {
	for _, tt := range []struct {
		name, in, want string
		ok             bool
	}{
		{name: "plain", in: "/* SPDX-License-Identifier: LGPL-2.1-or-later */", want: "LGPL-2.1-or-later", ok: true},
		{name: "hash comment", in: "# SPDX-License-Identifier: Apache-2.0", want: "Apache-2.0", ok: true},
		{name: "with exception", in: "// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception", want: "Apache-2.0 WITH LLVM-exception", ok: true},
		{name: "choice", in: "// SPDX-License-Identifier: MIT OR Apache-2.0", want: "MIT OR Apache-2.0", ok: true},
		{name: "absent", in: "/* just a copyright header */", ok: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Tag(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Errorf("got = %q,%v, want = %q,%v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

// TestHeaderGrant covers the variant table: the classifier files every wording
// of a GPL notice under the license name alone, so only the variant says which
// grant was made.
func TestHeaderGrant(t *testing.T) {
	for _, tt := range []struct {
		name, variant, want string
	}{
		// coreutils matches this pair in practice, and is GPL-3.0-or-later.
		{"GPL-3.0", "header.txt", "GPL-3.0-or-later"},
		{"GPL-3.0", "a.txt", "GPL-3.0-only"},
		{"GPL-2.0", "a.txt", "GPL-2.0-or-later"},
		{"GPL-2.0", "e.txt", "GPL-2.0-only"},
	} {
		t.Run(tt.name+"/"+tt.variant, func(t *testing.T) {
			got, ok := HeaderGrant(tt.name, tt.variant)
			if !ok || got != tt.want {
				t.Errorf("got = %q,%v, want = %q,true", got, ok, tt.want)
			}
		})
	}
	if _, ok := HeaderGrant("MIT", "header.txt"); ok {
		t.Error("a permissive license has no version grant to report")
	}
}

func TestIsDeprecated(t *testing.T) {
	for _, tt := range []struct {
		id   string
		want bool
	}{
		{"LGPL-3.0", true},
		{"GPL-2.0", true},
		{"LGPL-3.0-only", false},
		{"Apache-2.0", false},
		{"Unicode-3.0", false},
	} {
		t.Run(tt.id, func(t *testing.T) {
			if got := IsDeprecated(tt.id); got != tt.want {
				t.Errorf("got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func TestListVersionIsRecorded(t *testing.T) {
	if ListVersion() == "" {
		t.Error("the vendored list must record which SPDX release it came from")
	}
}
