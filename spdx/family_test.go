/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package spdx

import "testing"

func TestFamily(t *testing.T) {
	for _, tt := range []struct {
		id   string
		want string
	}{
		{"MIT", "MIT"},
		{"MIT-0", "MIT"},
		{"Apache-2.0", "Apache"},
		{"BSD-3-Clause", "BSD"},
		{"BSD-2-Clause-Views", "BSD"},
		{"0BSD", "BSD"},
		{"GPL-2.0-only", "GPL"},
		{"GPL-3.0-or-later", "GPL"},
		{"LGPL-2.1-only", "LGPL"},
		{"AGPL-3.0-only", "AGPL"},
		{"MPL-2.0", "MPL"},
		{"CC-BY-SA-4.0", "CC-BY-SA"},
		{"Unicode-3.0", "Unicode"},
		{"libpng-2.0", "libpng"},
		{"OLDAP-2.8", "OLDAP"},
		{"W3C-19980720", "W3C"},
		// No version to truncate at leaves the identifier as its own family.
		{"Zlib", "Zlib"},
		{"curl", "curl"},
		// The exception narrows terms rather than replacing them, so the family
		// is the license's.
		{"GPL-2.0-only WITH Classpath-exception-2.0", "GPL"},
		{"Apache-2.0 WITH LLVM-exception", "Apache"},
		// The deprecated or-later shorthand is a grant, not part of the name.
		{"GPL-2.0+", "GPL"},
		// A digit that is not a whole segment is part of the name, so the
		// family survives it.
		{"3D-Slicer-1.0", "3D-Slicer"},
		// A LicenseRef has no family: its terms are whatever its text says.
		{"LicenseRef-v1-0123456789abcdef", ""},
		{"LicenseRef-NVIDIA-CUDA-EULA", ""},
		{"", ""},
	} {
		t.Run(tt.id, func(t *testing.T) {
			if got := Family(tt.id); got != tt.want {
				t.Errorf("Family(%q): got = %q, want = %q", tt.id, got, tt.want)
			}
		})
	}
}

// TestFamilyGroupsAcrossVersionsAndVariants states the property a consumer
// relies on when it asks whether a licensing change crossed a family boundary:
// versions and variants of one license share a family, and different licenses
// do not.
func TestFamilyGroupsAcrossVersionsAndVariants(t *testing.T) {
	same := [][]string{
		{"GPL-2.0-only", "GPL-3.0-or-later", "GPL-2.0+"},
		{"BSD-2-Clause", "BSD-3-Clause", "0BSD"},
		{"Apache-1.1", "Apache-2.0"},
	}
	for _, group := range same {
		want := Family(group[0])
		for _, id := range group[1:] {
			if got := Family(id); got != want {
				t.Errorf("Family(%q) = %q, want %q to match Family(%q)", id, got, want, group[0])
			}
		}
	}

	// LGPL is not GPL, which is the distinction a prefix match would lose.
	if Family("LGPL-3.0-only") == Family("GPL-3.0-only") {
		t.Error("LGPL and GPL share a family, so a family comparison cannot tell them apart")
	}
	if Family("AGPL-3.0-only") == Family("GPL-3.0-only") {
		t.Error("AGPL and GPL share a family")
	}
}

func TestIsRef(t *testing.T) {
	for _, tt := range []struct {
		id   string
		want bool
	}{
		{"LicenseRef-v1-0123456789abcdef", true},
		{"LicenseRef-NVIDIA-CUDA-EULA", true},
		{" LicenseRef-x", true},
		{"MIT", false},
		{"", false},
		// Case matters: SPDX defines the prefix, and a consumer keying on it
		// must not accept a spelling the specification does not.
		{"licenseref-x", false},
	} {
		t.Run(tt.id, func(t *testing.T) {
			if got := IsRef(tt.id); got != tt.want {
				t.Errorf("IsRef(%q): got = %v, want = %v", tt.id, got, tt.want)
			}
		})
	}
}

func TestRef(t *testing.T) {
	for _, tt := range []struct{ name, want string }{
		{"NVIDIA-CUDA-EULA", "LicenseRef-NVIDIA-CUDA-EULA"},
		{"LicenseRef-NVIDIA-CUDA-EULA", "LicenseRef-NVIDIA-CUDA-EULA"},
		{"", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Ref(tt.name); got != tt.want {
				t.Errorf("Ref(%q): got = %q, want = %q", tt.name, got, tt.want)
			}
		})
	}
}
