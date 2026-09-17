/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package assess_test

import (
	"fmt"

	"chainguard.dev/license/assess"
	"chainguard.dev/license/component"
	"chainguard.dev/license/detect"
)

// classified builds the shape a caller passes in after running detection: a
// license file the classifier recognized outright.
func classified(path, license string) detect.File {
	return detect.File{Path: path, License: license, Confidence: 1, SizeBytes: 100}
}

// Assess grades the evidence rather than deciding the license. Several licenses
// with nothing composing them is the ambiguity deterministic detection
// structurally cannot resolve, so the score is zero and the flag says why.
func ExampleAssess() {
	got := assess.Assess(assess.Input{
		Files: []detect.File{
			classified("LICENSE-MIT", "MIT"),
			classified("LICENSE-APACHE", "Apache-2.0"),
		},
	})
	fmt.Printf("score %.2f, flags %v\n", got.Score, got.Flags)

	// The same component with a manifest expression naming both licenses is
	// settled, and must not read as ambiguous.
	got = assess.Assess(assess.Input{
		Files: []detect.File{
			classified("LICENSE-MIT", "MIT"),
			classified("LICENSE-APACHE", "Apache-2.0"),
		},
		Manifests: []component.Manifest{{Path: "Cargo.toml", License: "MIT OR Apache-2.0"}},
	})
	fmt.Printf("score %.2f, flags %v\n", got.Score, got.Flags)
	// Output:
	// score 0.00, flags [relationship-ambiguous]
	// score 1.00, flags []
}

// A low score means the evidence was read and was murky. Unknown means there
// was none to read, which calls for a retry rather than a deeper analysis.
func ExampleAssess_unknown() {
	got := assess.Assess(assess.Input{Incomplete: []string{"subject has no source tree"}})
	fmt.Println(got.Unknown, got.Rationale)
	// Output: true no evidence: subject has no source tree
}

// ChoiceOfLicense reads a choice out of the project's own prose, which for
// ecosystems with no manifest license field is the only thing that can settle
// how several licenses compose.
func ExampleChoiceOfLicense() {
	hints := []detect.ProseHint{
		{Path: "README.md", Line: 3, Excerpt: "See the LICENSE files for details."},
		{Path: "README.md", Line: 40, Excerpt: "Licensed under either of MIT or Apache-2.0 at your option."},
	}

	hint, ok := assess.ChoiceOfLicense(hints)
	fmt.Println(ok, hint.Line)
	// Output: true 40
}
