/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package assess

import (
	"math"
	"slices"
	"testing"

	"chainguard.dev/license/component"
	"chainguard.dev/license/detect"
	"chainguard.dev/license/spdx"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// file builds a classified license file. It takes the size explicitly because
// a zero-sized file is not evidence, and several cases turn on that.
func file(path, license string, confidence float64) detect.File {
	return detect.File{Path: path, License: license, Confidence: confidence, SizeBytes: 100}
}

func excluded(path, license string, reason detect.ExclusionReason) detect.File {
	f := file(path, license, 1)
	f.Excluded = reason
	return f
}

func TestAssess(t *testing.T) {
	for _, tt := range []struct {
		name                              string
		in                                Input
		wantProject, wantText, wantRelate float64
		wantScore                         float64
	}{{
		name:        "nothing found",
		in:          Input{},
		wantProject: 0, wantText: 1, wantRelate: 1, wantScore: 0,
	}, {
		name:        "prose alone is the weakest signal",
		in:          Input{Prose: []detect.ProseHint{{Path: "README"}}},
		wantProject: proseCredit, wantText: 1, wantRelate: 1, wantScore: proseCredit,
	}, {
		name: "a machine-readable manifest beats prose",
		in: Input{
			Manifests: []component.Manifest{{Path: "package.json", License: "MIT"}},
			Prose:     []detect.ProseHint{{Path: "README"}},
		},
		wantProject: manifestCredit, wantText: 1, wantRelate: 1, wantScore: manifestCredit,
	}, {
		name: "a classified license file beats a manifest, and a vendored one is out of scope",
		in: Input{
			Files: []detect.File{
				file("LICENSE", "Apache-2.0", 1),
				excluded("vendor/x/LICENSE", "GPL-3.0", detect.ExclusionVendored),
			},
			Manifests: []component.Manifest{{Path: "package.json", License: "MIT"}},
		},
		wantProject: 1, wantText: 1, wantRelate: 1, wantScore: 1,
	}, {
		name: "a fixture corpus license is out of scope",
		in: Input{Files: []detect.File{
			file("LICENSE", "Apache-2.0", 1),
			excluded("tests/syntax-tests/source/LICENSE", "LGPL-3.0", detect.ExclusionTestFixture),
		}},
		wantProject: 1, wantText: 1, wantRelate: 1, wantScore: 1,
	}, {
		// An unidentified license text is a real gap, and the two licenses that
		// did classify have nothing composing them: the 7zip / unRar shape.
		name: "unidentified text and an unsettled relationship",
		in: Input{Files: []detect.File{
			file("License.txt", "BSD-3-Clause", 1),
			file("copying.txt", "LGPL-2.1", 1),
			file("unRarLicense.txt", detect.NoAssertion, 0),
		}},
		wantProject: 1, wantText: 2.0 / 3.0, wantRelate: 0, wantScore: 0,
	}, {
		name: "a manifest expression settles dual licensing",
		in: Input{
			Files: []detect.File{
				file("LICENSE-MIT", "MIT", 1),
				file("LICENSE-APACHE", "Apache-2.0", 1),
			},
			Manifests: []component.Manifest{{Path: "Cargo.toml", License: "MIT OR Apache-2.0"}},
		},
		wantProject: 1, wantText: 1, wantRelate: 1, wantScore: 1,
	}, {
		// Cargo's deprecated spelling of a choice. Left unread it settles
		// nothing and every crate using it escalates.
		name: "a deprecated slash expression settles it too",
		in: Input{
			Files: []detect.File{
				file("LICENSE-MIT", "MIT", 1),
				file("LICENSE-APACHE", "Apache-2.0", 1),
			},
			Manifests: []component.Manifest{{Path: "Cargo.toml", License: "MIT/Apache-2.0"}},
		},
		wantProject: 1, wantText: 1, wantRelate: 1, wantScore: 1,
	}, {
		name: "a manifest naming only some detected licenses does not settle",
		in: Input{
			Files: []detect.File{
				file("LICENSE-MIT", "MIT", 1),
				file("LICENSE-APACHE", "Apache-2.0", 1),
			},
			Manifests: []component.Manifest{{Path: "Cargo.toml", License: "MIT"}},
		},
		wantProject: 1, wantText: 1, wantRelate: 0, wantScore: 0,
	}, {
		// Below the confidence threshold a match is not settled enough to count
		// as a second license for relationship purposes.
		name: "a low-confidence second match is a gap, not an ambiguity",
		in: Input{Files: []detect.File{
			file("LICENSE", "MIT", 1),
			file("COPYING", "GPL-2.0", 0.4),
		}},
		wantProject: 1, wantText: 0.5, wantRelate: 1, wantScore: 0.5,
	}} {
		t.Run(tt.name, func(t *testing.T) {
			got := Assess(tt.in)
			if got.Unknown {
				t.Fatalf("unknown: got = true, want false (%s)", got.Rationale)
			}
			if !approx(got.ProjectLicense, tt.wantProject) {
				t.Errorf("project license: got = %v, want = %v", got.ProjectLicense, tt.wantProject)
			}
			if !approx(got.TextResolution, tt.wantText) {
				t.Errorf("text resolution: got = %v, want = %v", got.TextResolution, tt.wantText)
			}
			if !approx(got.Relation, tt.wantRelate) {
				t.Errorf("relation: got = %v, want = %v", got.Relation, tt.wantRelate)
			}
			if !approx(got.Score, tt.wantScore) {
				t.Errorf("score: got = %v, want = %v", got.Score, tt.wantScore)
			}
			if got.Rationale == "" {
				t.Error("rationale is empty")
			}
		})
	}
}

// TestFlagsFromBothSides exercises every flag with an input that should raise
// it and an input that should not, because a flag that is always on is as
// useless as one that never fires.
func TestFlagsFromBothSides(t *testing.T) {
	twoLicenses := []detect.File{
		file("LICENSE-MIT", "MIT", 1),
		file("LICENSE-APACHE", "Apache-2.0", 1),
	}

	for _, tt := range []struct {
		name string
		in   Input
		flag Flag
		want bool
	}{{
		name: "several licenses with nothing composing them",
		in:   Input{Files: twoLicenses},
		flag: FlagRelationshipAmbiguous,
		want: true,
	}, {
		// The case that must stay clear: several licenses plus an expression
		// saying how they combine is a settled component.
		name: "several licenses composed by a manifest expression",
		in: Input{
			Files:     twoLicenses,
			Manifests: []component.Manifest{{Path: "Cargo.toml", License: "MIT OR Apache-2.0"}},
		},
		flag: FlagRelationshipAmbiguous,
		want: false,
	}, {
		name: "one license has no relationship to be uncertain about",
		in:   Input{Files: []detect.File{file("LICENSE", "MIT", 1)}},
		flag: FlagRelationshipAmbiguous,
		want: false,
	}, {
		name: "license text nothing identified",
		in:   Input{Files: []detect.File{file("LICENSE", detect.NoAssertion, 0)}},
		flag: FlagUnidentifiedText,
		want: true,
	}, {
		name: "text identified below the threshold is still unidentified",
		in:   Input{Files: []detect.File{file("LICENSE", "MIT", 0.4)}},
		flag: FlagUnidentifiedText,
		want: true,
	}, {
		name: "text identified confidently",
		in:   Input{Files: []detect.File{file("LICENSE", "MIT", 1)}},
		flag: FlagUnidentifiedText,
		want: false,
	}, {
		name: "no license text at all is a thin component, not an unidentified one",
		in:   Input{Manifests: []component.Manifest{{Path: "package.json", License: "MIT"}}},
		flag: FlagUnidentifiedText,
		want: false,
	}, {
		name: "the declaration names a license the content does not carry",
		in: Input{
			Files:    []detect.File{file("LICENSE", "MIT", 1)},
			Declared: "Apache-2.0",
		},
		flag: FlagDeclaredConflict,
		want: true,
	}, {
		name: "the declaration omits a license the content carries",
		in: Input{
			Files:    twoLicenses,
			Declared: "MIT",
		},
		flag: FlagDeclaredConflict,
		want: true,
	}, {
		name: "the declaration agrees with the content",
		in: Input{
			Files:    []detect.File{file("LICENSE", "MIT", 1)},
			Declared: "MIT",
		},
		flag: FlagDeclaredConflict,
		want: false,
	}, {
		// Prose spelling rather than an identifier. Left uncanonicalized this
		// reads as a disagreement that is not there.
		name: "a declaration written as prose still agrees",
		in: Input{
			Files:    []detect.File{file("LICENSE", "Apache-2.0", 1)},
			Declared: "The Apache Software License, Version 2.0",
		},
		flag: FlagDeclaredConflict,
		want: false,
	}, {
		// A declaration cannot disagree with an absence of evidence, or every
		// component with an unreadable license file would also read as
		// misdeclared.
		name: "nothing detected is not a conflict",
		in: Input{
			Files:    []detect.File{file("LICENSE", detect.NoAssertion, 0)},
			Declared: "MIT",
		},
		flag: FlagDeclaredConflict,
		want: false,
	}, {
		name: "no declaration is not a conflict",
		in:   Input{Files: []detect.File{file("LICENSE", "MIT", 1)}},
		flag: FlagDeclaredConflict,
		want: false,
	}} {
		t.Run(tt.name, func(t *testing.T) {
			got := Assess(tt.in)
			if raised := slices.Contains(got.Flags, tt.flag); raised != tt.want {
				t.Errorf("flag %q: raised = %v, want = %v (flags = %v, %s)", tt.flag, raised, tt.want, got.Flags, got.Rationale)
			}
		})
	}
}

// TestUnknownIsNotALowScore covers the distinction a consumer branches on: a
// low score means the evidence was read and was murky, and unknown means there
// was none to read. One is escalated, the other is retried.
func TestUnknownIsNotALowScore(t *testing.T) {
	for _, tt := range []struct {
		name        string
		in          Input
		wantUnknown bool
	}{{
		name:        "the tree could not be supplied",
		in:          Input{Incomplete: []string{"subject has no source tree"}},
		wantUnknown: true,
	}, {
		name: "every license file failed to be read",
		in: Input{Files: []detect.File{
			{Path: "LICENSE", Err: "permission denied"},
			{Path: "COPYING", Err: "permission denied"},
		}},
		wantUnknown: true,
	}, {
		// Read completely, and it simply ships no license text. That is a fact
		// about the component: a thin score and a coverage gap, not an unknown.
		name:        "a component that ships no license text",
		in:          Input{},
		wantUnknown: false,
	}, {
		// One file failed and another was read, so there is evidence to weigh.
		name: "a partial failure still leaves evidence",
		in: Input{Files: []detect.File{
			{Path: "LICENSE", Err: "permission denied"},
			file("COPYING", "MIT", 1),
		}},
		wantUnknown: false,
	}, {
		// The source tree was unavailable but the manifests were not, so
		// something was read.
		name: "a gap with other evidence present",
		in: Input{
			Manifests:  []component.Manifest{{Path: "package.json", License: "MIT"}},
			Incomplete: []string{"installed trees unavailable"},
		},
		wantUnknown: false,
	}} {
		t.Run(tt.name, func(t *testing.T) {
			got := Assess(tt.in)
			if got.Unknown != tt.wantUnknown {
				t.Errorf("unknown: got = %v, want = %v (%s)", got.Unknown, tt.wantUnknown, got.Rationale)
			}
			if got.Unknown && got.Score != 0 {
				t.Errorf("score: got = %v, want 0 to be meaningless alongside unknown", got.Score)
			}
			if got.Rationale == "" {
				t.Error("rationale is empty")
			}
		})
	}
}

// TestProseSettlesSeveralLicenses is the escalation the prose rung removes: two
// license texts and an explicit statement of choice is a settled component. Go
// is the case that matters, having no manifest license field at all.
func TestProseSettlesSeveralLicenses(t *testing.T) {
	got := Assess(Input{
		Files: []detect.File{
			file("LICENSE-MIT", "MIT", 1),
			file("LICENSE-APACHE", "Apache-2.0", 1),
		},
		Prose: []detect.ProseHint{
			{Path: "README.md", Line: 40, Excerpt: "Licensed under either of MIT or Apache-2.0 at your option."},
		},
	})
	if got.Relationship != spdx.OperatorOr {
		t.Errorf("relationship: got = %q, want = %q (%s)", got.Relationship, spdx.OperatorOr, got.Rationale)
	}
	if got.Score < 0.9 {
		t.Errorf("score: got = %v, want >= 0.9 so it settles (%s)", got.Score, got.Rationale)
	}
	if slices.Contains(got.Flags, FlagRelationshipAmbiguous) {
		t.Errorf("flags: got = %v, want no relationship ambiguity", got.Flags)
	}
}

// TestProseDoesNotSettleUnidentifiedText keeps the prose rung from papering
// over a license text nobody could identify: that text is exactly what a
// deeper look is for.
func TestProseDoesNotSettleUnidentifiedText(t *testing.T) {
	got := Assess(Input{
		Files: []detect.File{
			file("LICENSE-MIT", "MIT", 1),
			file("LICENSE-APACHE", "Apache-2.0", 1),
			file("LICENSE-THIRD", detect.NoAssertion, 0),
		},
		Prose: []detect.ProseHint{
			{Path: "README.md", Line: 40, Excerpt: "Dual-licensed at your option."},
		},
	})
	if got.Score >= 0.9 {
		t.Errorf("score: got = %v, want < 0.9 so the unidentified text is still read (%s)", got.Score, got.Rationale)
	}
	if !slices.Contains(got.Flags, FlagUnidentifiedText) {
		t.Errorf("flags: got = %v, want the unidentified text flagged", got.Flags)
	}
}

// TestProseWithoutAStatementStaysUncertain is the case the prose rung must not
// swallow: nothing says how these compose, so nothing may assume.
func TestProseWithoutAStatementStaysUncertain(t *testing.T) {
	got := Assess(Input{
		Files: []detect.File{
			file("LICENSE-MIT", "MIT", 1),
			file("LICENSE-GPL", "GPL-2.0-only", 1),
		},
		Prose: []detect.ProseHint{
			{Path: "README.md", Line: 3, Excerpt: "See the LICENSE files for licensing details."},
		},
	})
	if got.Relation != 0 {
		t.Errorf("relation: got = %v, want = 0 (%s)", got.Relation, got.Rationale)
	}
	if got.Relationship != "" {
		t.Errorf("relationship: got = %q, want it unstated", got.Relationship)
	}
}

// TestBundledLicensesBothCount covers a file carrying two license texts, which
// is what a LICENSE with a bundled dependency's terms appended looks like.
//
// Recording only the strongest match would settle the component on a subset of
// what it is under, and a consumer reading that would believe obligations they
// have do not apply to them.
func TestBundledLicensesBothCount(t *testing.T) {
	bundled := file("LICENSE", "MIT", 1)
	bundled.AdditionalLicenses = []detect.Match{{Name: "Apache-2.0", Confidence: 1}}

	got := Assess(Input{Files: []detect.File{bundled}})
	if want := []string{"Apache-2.0", "MIT"}; !slices.Equal(got.Identifiers, want) {
		t.Errorf("identifiers: got = %v, want = %v", got.Identifiers, want)
	}
	// Two licenses with nothing composing them is the ambiguity, so the
	// component must not come out settled.
	if !slices.Contains(got.Flags, FlagRelationshipAmbiguous) {
		t.Errorf("flags: got = %v, want it to include %q", got.Flags, FlagRelationshipAmbiguous)
	}
}

// TestMalformedDeclarationComposesNothing covers metadata that names several
// licenses without stating a relationship between them.
//
// spdx.Identifiers deliberately reads names out of a string that is not an
// expression, which is right when the question is what a declaration mentions
// and wrong here: "MIT Apache-2.0" composes nothing, and treating it as a
// composition lets malformed metadata make unresolved licensing look settled.
func TestMalformedDeclarationComposesNothing(t *testing.T) {
	in := Input{
		Files:     []detect.File{file("LICENSE", "MIT", 1), file("LICENSE.apache", "Apache-2.0", 1)},
		Manifests: []component.Manifest{{Path: "package.json", License: "MIT Apache-2.0"}},
	}

	got := Assess(in)
	if got.Relation != 0 {
		t.Errorf("relation: got = %v, want = 0; the declaration names both licenses and composes neither", got.Relation)
	}
	if !slices.Contains(got.Flags, FlagRelationshipAmbiguous) {
		t.Errorf("flags: got = %v, want it to include %q", got.Flags, FlagRelationshipAmbiguous)
	}
	// A real expression over the same two licenses still settles them.
	in.Manifests = []component.Manifest{{Path: "package.json", License: "MIT OR Apache-2.0"}}
	if settled := Assess(in); settled.Relation != 1 {
		t.Errorf("relation for a real expression: got = %v, want = 1", settled.Relation)
	}
}

// TestManifestWithoutALicenseEarnsNoCredit covers a manifest that points at a
// license file instead of naming a license, which leaves Manifest.License
// empty. It declared nothing, so it is not a project-license signal, and
// crediting it would also report a blank identifier in the rationale.
func TestManifestWithoutALicenseEarnsNoCredit(t *testing.T) {
	got := Assess(Input{Manifests: []component.Manifest{{Path: "package.json", LicenseFile: "LICENSE"}}})
	if got.ProjectLicense != 0 {
		t.Errorf("project license: got = %v, want = 0 for a manifest naming no license", got.ProjectLicense)
	}
	// A later manifest that does name one is still found.
	two := Assess(Input{Manifests: []component.Manifest{
		{Path: "package.json", LicenseFile: "LICENSE"},
		{Path: "Cargo.toml", License: "MIT"},
	}})
	if !approx(two.ProjectLicense, manifestCredit) {
		t.Errorf("project license: got = %v, want = %v from the manifest that names one", two.ProjectLicense, manifestCredit)
	}
}

// TestFlagsAreSorted pins the contract the Flags field documents. The value is
// content-addressed downstream, so an order that depends on which order the
// conditions are written in is not one a consumer can rely on.
func TestFlagsAreSorted(t *testing.T) {
	in := Input{
		Files:    []detect.File{file("LICENSE", "MIT", 1), file("COPYING", "", 0)},
		Declared: "Apache-2.0",
	}
	got := Assess(in)
	if len(got.Flags) < 2 {
		t.Fatalf("flags: got = %v, want at least two to order", got.Flags)
	}
	if !slices.IsSorted(got.Flags) {
		t.Errorf("flags: got = %v, want them sorted", got.Flags)
	}
}
