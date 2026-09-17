/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package contenthash

import (
	"strings"
	"testing"
)

// TestVerify covers the subset test and the one case it deliberately cannot
// catch. The asymmetry is what makes vendoring verifiable at all: "go mod
// vendor" copies only the packages a build imports, so a pristine copy
// routinely holds fewer license files than the module it came from.
func TestVerify(t *testing.T) {
	published := []File{
		{Path: "LICENSE", Digest: "sha256:aaa"},
		{Path: "internal/third_party/LICENSE", Digest: "sha256:bbb"},
		{Path: "s2/LICENSE", Digest: "sha256:ccc"},
	}

	for _, tt := range []struct {
		name       string
		local      []File
		want       Verification
		wantReason string
	}{
		{
			name:  "a pristine copy holding every published file",
			local: published,
			want:  Pristine,
		},
		{
			// The measured case: vendoring dropped the subdirectories nobody
			// imported, and an equality test would call this divergent.
			name:  "a pristine copy holding fewer files than the artifact",
			local: []File{{Path: "LICENSE", Digest: "sha256:aaa"}},
			want:  Pristine,
		},
		{
			name:       "a license edited in place",
			local:      []File{{Path: "LICENSE", Digest: "sha256:tampered"}},
			want:       Diverged,
			wantReason: "differs",
		},
		{
			name: "a license added locally",
			local: []File{
				{Path: "LICENSE", Digest: "sha256:aaa"},
				{Path: "LICENSE-EXTRA", Digest: "sha256:invented"},
			},
			want:       Diverged,
			wantReason: "not in the published artifact",
		},
		{
			// Not detected, and documented as such: a removal cannot grant
			// terms upstream withheld, and the determination is drawn from the
			// published artifact anyway.
			name:  "a license removed locally is indistinguishable from one never copied",
			local: nil,
			want:  Pristine,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := Verify(tt.local, published)
			if got != tt.want {
				t.Errorf("verification: got = %v, want = %v (%s)", got, tt.want, reason)
			}
			if tt.wantReason != "" && !strings.Contains(reason, tt.wantReason) {
				t.Errorf("reason: got = %q, want it to mention %q", reason, tt.wantReason)
			}
			if tt.want == Pristine && reason != "" {
				t.Errorf("reason: got = %q, want empty for a pristine copy", reason)
			}
		})
	}
}

// TestVerifyReasonIsStable keeps the named file from depending on the order the
// caller happened to list its files in, so a divergence reads the same way
// twice.
func TestVerifyReasonIsStable(t *testing.T) {
	published := []File{{Path: "LICENSE", Digest: "sha256:aaa"}}
	local := []File{
		{Path: "b/LICENSE", Digest: "sha256:x"},
		{Path: "a/LICENSE", Digest: "sha256:y"},
	}
	_, first := Verify(local, published)
	_, second := Verify([]File{local[1], local[0]}, published)
	if first != second {
		t.Errorf("reason depends on input order: %q vs %q", first, second)
	}
	if !strings.HasPrefix(first, "a/LICENSE") {
		t.Errorf("reason: got = %q, want the lexicographically first failure", first)
	}
}

// TestLicenseRefIsContentDerived pins the two properties the name has to have:
// it is stable for one text, so a curation entry naming it keeps applying, and
// it differs for different text, so a revised EULA is re-read rather than
// silently inheriting the old name.
func TestLicenseRefIsContentDerived(t *testing.T) {
	const eula = "End User License Agreement\n\nYou may not redistribute.\n"

	first, second := LicenseRef([]byte(eula)), LicenseRef([]byte(eula))
	if first != second {
		t.Errorf("the same text minted two names: %q and %q", first, second)
	}
	if !strings.HasPrefix(first, "LicenseRef-"+RefScheme+"-") {
		t.Errorf("name %q does not carry the LicenseRef prefix and scheme", first)
	}
	if got := len(strings.TrimPrefix(first, "LicenseRef-"+RefScheme+"-")); got != refDigestChars {
		t.Errorf("digest is %d characters, want %d", got, refDigestChars)
	}
	if revised := LicenseRef([]byte(eula + "You may not benchmark either.\n")); revised == first {
		t.Error("revised terms minted the same name, so re-curation would never happen")
	}
	// Line endings are normalized first, for the same reason the content hash
	// normalizes them: one license, checked out two ways.
	if crlf := LicenseRef([]byte(strings.ReplaceAll(eula, "\n", "\r\n"))); crlf != first {
		t.Errorf("a CRLF checkout minted a different name: %q vs %q", crlf, first)
	}
	if LicenseRef(nil) != "" {
		t.Error("no text should mint no name")
	}
}

// TestVerifyRefusesAnEmptyArtifact covers the case that reaches this in
// practice: a caller whose fetch failed. A vacuous pass would key the local
// copy on an answer drawn from bytes nobody read.
func TestVerifyRefusesAnEmptyArtifact(t *testing.T) {
	local := []File{{Path: "LICENSE", Digest: "sha256:aaa"}}
	if got, reason := Verify(local, nil); got != Diverged {
		t.Errorf("verification: got = %v, want = %v (%s)", got, Diverged, reason)
	}

	// A local copy holding nothing is the empty case of the subset test, and
	// verifies.
	if got, _ := Verify(nil, nil); got != Pristine {
		t.Errorf("verification of two empty sets: got = %v, want = %v", got, Pristine)
	}
}
