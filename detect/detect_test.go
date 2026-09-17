/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"strings"
	"testing"
)

// detectTree runs a detection over an in-memory tree at project scope, which is
// what a build-time check and an upstream evaluation both do.
func detectTree(t *testing.T, files map[string][]byte) *Result {
	t.Helper()
	res, err := Detect(t.Context(), Request{FS: tree(files), RetainText: true})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	return res
}

// TestConclude covers the cases a caller has to act on differently. The
// expected values are written from the documented rules rather than computed
// from the implementation: a single recognized license settles, several do not,
// and text nothing recognizes is reported as such rather than dropped.
func TestConclude(t *testing.T) {
	mit := readFixture(t, "mit.txt")
	bsd := readFixture(t, "bsd-2-clause.txt")
	nvidia := readFixture(t, "nvidia-eula.txt")

	for _, tt := range []struct {
		name           string
		files          map[string][]byte
		wantExpression string
		wantReason     Reason
	}{
		{
			name:           "single recognized license",
			files:          map[string][]byte{"LICENSE": mit},
			wantExpression: "MIT",
		},
		{
			name:           "recognized license with a preferred extension",
			files:          map[string][]byte{"LICENSE.md": mit},
			wantExpression: "MIT",
		},
		{
			name:       "no license files at all",
			files:      map[string][]byte{"README.md": []byte("# hello")},
			wantReason: ReasonNoLicenseText,
		},
		{
			// A proprietary license is not a recognized SPDX license, and must
			// be reported as unrecognized text rather than as no license: the
			// caller mints a LicenseRef from it.
			name:       "proprietary license is unrecognized rather than absent",
			files:      map[string][]byte{"LICENSE.txt": nvidia},
			wantReason: ReasonUnrecognized,
		},
		{
			name:       "two licenses with nothing composing them",
			files:      map[string][]byte{"LICENSE-MIT": mit, "LICENSE-BSD": bsd},
			wantReason: ReasonSeveralLicenses,
		},
		{
			// A license one level down is found when the root has none.
			name:           "subdirectory license is a fallback",
			files:          map[string][]byte{"docs/LICENSE": mit},
			wantExpression: "MIT",
		},
		{
			// A root license wins outright: a different license deeper in the
			// tree does not make the project's own licensing ambiguous.
			name: "root license is not contradicted by a deeper one",
			files: map[string][]byte{
				"LICENSE":             mit,
				"docs/LICENSE-BSD":    bsd,
				"third_party/COPYING": bsd,
			},
			wantExpression: "MIT",
		},
		{
			// Trees belonging to other components are never candidates, even
			// when the root has no license of its own.
			name: "vendored licenses do not answer for the component",
			files: map[string][]byte{
				"vendor/LICENSE":       mit,
				"node_modules/LICENSE": bsd,
			},
			wantReason: ReasonNoLicenseText,
		},
		{
			name:       "license-named source files are not license text",
			files:      map[string][]byte{"license.go": []byte("package license")},
			wantReason: ReasonNoLicenseText,
		},
		{
			// A patent grant accompanies a license without being one. Counting
			// it as unreadable license text would escalate every golang.org/x
			// module, every time.
			name:       "a patent grant alone is not license text",
			files:      map[string][]byte{"PATENTS": []byte("Additional IP Rights Grant")},
			wantReason: ReasonNoLicenseText,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := detectTree(t, tt.files).Conclude(GrantEvidence{})
			if got.Expression != tt.wantExpression {
				t.Errorf("expression: got = %q, want = %q", got.Expression, tt.wantExpression)
			}
			if got.Reason != tt.wantReason {
				t.Errorf("reason: got = %q, want = %q", got.Reason, tt.wantReason)
			}
		})
	}
}

// TestConcludeGrantFromNotice covers the one thing a license text cannot state:
// SPDX ships identical text for GPL-2.0-only and GPL-2.0-or-later, so the
// suffix comes from the notice in the component's own source.
func TestConcludeGrantFromNotice(t *testing.T) {
	// A tagged notice needs no classifier, which is what makes this hermetic.
	notices := []Notice{{Path: "main.go", Text: "// SPDX-License-Identifier: GPL-2.0-or-later\n"}}

	for _, tt := range []struct {
		name       string
		grants     GrantEvidence
		wantBasis  GrantBasis
		wantSuffix string
	}{
		{
			name:       "a notice states the grant",
			grants:     GrantEvidence{Grants: Grants(nil, notices), Sampled: 1},
			wantBasis:  GrantFromNotice,
			wantSuffix: "-or-later",
		},
		{
			// Notices were read and none granted later versions. That is the
			// answer, not a gap: the grant has to be explicit.
			name:       "notices were read and granted nothing",
			grants:     GrantEvidence{Sampled: 12},
			wantBasis:  GrantAbsent,
			wantSuffix: "-only",
		},
		{
			// Nobody looked, so the same suffix rests on convention rather than
			// on evidence, and a reader has to be able to tell the difference.
			name:       "nobody looked",
			grants:     GrantEvidence{},
			wantBasis:  GrantUnknown,
			wantSuffix: "-only",
		},
		{
			// Both grants stated for one license is a finding, not a tie to
			// break.
			name: "the tree states both grants",
			grants: GrantEvidence{
				Grants:  []Grant{{Expression: "GPL-2.0-only"}, {Expression: "GPL-2.0-or-later"}},
				Sampled: 4,
			},
			wantBasis: GrantMixed,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// A synthesized result rather than a classified GPL text: the
			// property under test is the grant resolution, and the classifier
			// has its own tests.
			res := &Result{Files: []File{{
				Path:       "COPYING",
				License:    "GPL-2.0",
				Confidence: 1,
				SizeBytes:  100,
			}}}
			got := res.Conclude(tt.grants)
			if got.GrantBasis != tt.wantBasis {
				t.Errorf("grant basis: got = %q, want = %q", got.GrantBasis, tt.wantBasis)
			}
			if tt.wantSuffix == "" {
				if got.Expression != "" || got.Reason != ReasonGrantUndecided {
					t.Errorf("got = %+v, want no expression and a grant-undecided reason", got)
				}
				return
			}
			if !strings.HasSuffix(got.Expression, tt.wantSuffix) {
				t.Errorf("expression: got = %q, want a %q suffix", got.Expression, tt.wantSuffix)
			}
		})
	}
}

// TestDetectRecordsPerFileFailure verifies that one unreadable file does not
// discard the evidence the others carry, which is what lets a caller tell a
// tree with no license from a tree it could not finish reading.
func TestDetectRecordsPerFileFailure(t *testing.T) {
	fsys := tree(map[string][]byte{"LICENSE": readFixture(t, "mit.txt")})
	res, err := Detect(t.Context(), Request{FS: unreadable{fsys, "COPYING"}, RetainText: true})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	var failed, classified int
	for _, f := range res.Files {
		if f.Err != "" {
			failed++
			continue
		}
		if f.Confident() {
			classified++
		}
	}
	if failed != 1 || classified != 1 {
		t.Errorf("files: got %d failed and %d classified, want 1 of each: %+v", failed, classified, res.Files)
	}
	if got := res.Conclude(GrantEvidence{}); got.Expression != "MIT" {
		t.Errorf("expression: got = %q, want = %q despite the unreadable file", got.Expression, "MIT")
	}
}

// TestDetectClassifiesDeclaredPath verifies that a declaration naming a file
// discovery would not have selected is still read. A component keeping its
// license in an unconventionally named file has no other way to say so.
func TestDetectClassifiesDeclaredPath(t *testing.T) {
	fsys := tree(map[string][]byte{"unusual-terms.rst": readFixture(t, "mit.txt")})
	res, err := Detect(t.Context(), Request{
		FS:       fsys,
		Declared: []Declaration{{License: "MIT", Path: "unusual-terms.rst"}},
	})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Files) != 1 {
		t.Fatalf("files: got = %d, want the declared path to be read: %+v", len(res.Files), res.Files)
	}
	f := res.Files[0]
	if f.Declared != "MIT" || !f.Confident() {
		t.Errorf("declared path: got = %+v, want the declaration attached and the text classified", f)
	}
}

// TestDetectTruncatesRetainedText verifies the bound on retained text, and that
// the digest still covers the whole file: a digest over a truncated prologue
// would compare equal for two different licenses, which for the GPL variants is
// not hypothetical.
func TestDetectTruncatesRetainedText(t *testing.T) {
	long := append(readFixture(t, "mit.txt"), []byte(strings.Repeat("x", MaxTextBytes))...)
	res, err := Detect(t.Context(), Request{
		FS:         tree(map[string][]byte{"LICENSE": long}),
		RetainText: true,
	})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	f := res.Files[0]
	if !f.Truncated || len(f.Text) != MaxTextBytes {
		t.Errorf("text: got %d bytes, truncated = %v, want %d bytes and truncated", len(f.Text), f.Truncated, MaxTextBytes)
	}
	if f.SizeBytes != int64(len(long)) {
		t.Errorf("size: got = %d, want the whole file's %d", f.SizeBytes, len(long))
	}
	if f.Digest == "" {
		t.Error("digest: got empty, want the whole file's digest")
	}
	if len(res.Notes) == 0 {
		t.Error("Notes: got none, want a note recording the truncation")
	}
}

func TestDetectRejectsRequestWithoutFilesystem(t *testing.T) {
	if _, err := Detect(t.Context(), Request{}); err == nil {
		t.Error("Detect with no filesystem: got nil error, want one")
	}
}

// TestConcludeSeveralLicensesInOneFile covers the shape a single License field
// cannot express: a LICENSE that appends a bundled dependency's terms carries
// two licenses, and settling the component on the stronger match would hide
// the other's obligations.
func TestConcludeSeveralLicensesInOneFile(t *testing.T) {
	combined := append(readFixture(t, "mit.txt"), readFixture(t, "bsd-2-clause.txt")...)
	res := detectTree(t, map[string][]byte{"LICENSE": combined})

	f := res.Files[0]
	if len(f.AdditionalLicenses) == 0 {
		t.Fatalf("the second license in the file was dropped: %+v", f)
	}
	if got := len(f.Identifiers()); got < 2 {
		t.Errorf("identifiers: got = %v, want both licenses the file carries", f.Identifiers())
	}

	got := res.Conclude(GrantEvidence{})
	if got.Reason != ReasonSeveralLicenses {
		t.Errorf("reason: got = %q, want = %q", got.Reason, ReasonSeveralLicenses)
	}
	if got.Expression != "" {
		t.Errorf("expression: got = %q, want none until something says how they combine", got.Expression)
	}
}

// TestDetectToleratesAnUnreadableDirectory verifies one unreadable subtree does
// not discard the evidence in the rest of the tree, and is named rather than
// ignored.
func TestDetectToleratesAnUnreadableDirectory(t *testing.T) {
	fsys := unreadableDir{
		MapFS: tree(map[string][]byte{
			"LICENSE":          readFixture(t, "mit.txt"),
			"docs/LICENSE-BSD": readFixture(t, "bsd-2-clause.txt"),
		}),
		dir: "docs",
	}

	res, err := Detect(t.Context(), Request{FS: fsys})
	if err != nil {
		t.Fatalf("Detect: got err = %v, want the readable evidence returned", err)
	}
	if got := res.Conclude(GrantEvidence{}); got.Expression != "MIT" {
		t.Errorf("expression: got = %q, want the readable license concluded", got.Expression)
	}
	if len(res.Unreadable) == 0 {
		t.Error("unreadable: got none, want the directory that could not be read named")
	}
}

// TestUnrecognizedTextRefusesToNameTextNobodyKept covers the case where a
// caller detects without RetainText and then hits unrecognized license text.
//
// The empty string is a valid input to a hash, so naming it would succeed
// quietly and give every proprietary license in the fleet the same name - one
// that reads downstream as no license found. Failing is the only honest answer,
// and the path and digest stay in the conclusion so the caller can read the
// file and try again.
func TestUnrecognizedTextRefusesToNameTextNobodyKept(t *testing.T) {
	for _, tc := range []struct {
		name       string
		conclusion Conclusion
		want       string
		wantErr    bool
	}{{
		name:       "text retained",
		conclusion: Conclusion{Unrecognized: []File{{Path: "LICENSE", SizeBytes: 12, Text: "Bespoke EULA"}}},
		want:       "Bespoke EULA",
	}, {
		name:       "text not retained",
		conclusion: Conclusion{Unrecognized: []File{{Path: "LICENSE", SizeBytes: 12}}},
		wantErr:    true,
	}, {
		name:       "nothing unrecognized",
		conclusion: Conclusion{},
		wantErr:    true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.conclusion.UnrecognizedText()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("UnrecognizedText: got = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnrecognizedText: %v", err)
			}
			if got != tc.want {
				t.Errorf("UnrecognizedText: got = %q, want = %q", got, tc.want)
			}
		})
	}
}
