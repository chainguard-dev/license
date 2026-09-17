/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import "testing"

func TestClassifyExclusion(t *testing.T) {
	for _, tt := range []struct {
		path string
		want ExclusionReason
	}{
		{path: "LICENSE", want: ExclusionNone},
		{path: "COPYING", want: ExclusionNone},
		{path: "src/LICENSE", want: ExclusionNone},
		// docs is deliberately in scope: projects do keep the real license there.
		{path: "docs/LICENSE", want: ExclusionNone},

		{path: "vendor/x/LICENSE", want: ExclusionVendored},
		{path: "third_party/y/COPYING", want: ExclusionVendored},
		{path: "node_modules/z/LICENSE", want: ExclusionVendored},
		{path: "deps/zlib/LICENSE", want: ExclusionVendored},
		{path: "VENDOR/x/LICENSE", want: ExclusionVendored},
		// "vendored" is not the "vendor" segment.
		{path: "internal/vendored/LICENSE", want: ExclusionNone},

		// The bat shape: fixture corpora carry unrelated licenses.
		{path: "tests/syntax-tests/source/LICENSE", want: ExclusionTestFixture},
		{path: "testdata/LICENSE", want: ExclusionTestFixture},
		{path: "src/test/resources/LICENSE", want: ExclusionTestFixture},
		{path: "examples/demo/LICENSE.md", want: ExclusionTestFixture},
		{path: "spec/fixtures/COPYING", want: ExclusionTestFixture},

		// Whole-segment matching: a component named after a test helper is not
		// itself a fixture.
		{path: "testify/LICENSE", want: ExclusionNone},
		{path: "src/latest/LICENSE", want: ExclusionNone},

		// Vendored wins so dependency collection can still find the text.
		{path: "vendor/x/testdata/LICENSE", want: ExclusionVendored},

		// The build's install root is another component's tree, whatever the
		// file is called there.
		{path: "melange-out/py3-foo/usr/lib/python3.13/site-packages/dep/LICENSE", want: ExclusionBuildOutput},
		{path: "melange-out/foo/usr/share/doc/PATENTS", want: ExclusionBuildOutput},
	} {
		t.Run(tt.path, func(t *testing.T) {
			if got := ClassifyExclusion(tt.path); got != tt.want {
				t.Errorf("got = %q, want = %q", got, tt.want)
			}
		})
	}
}

func TestClassifyExclusionSupplementaryFiles(t *testing.T) {
	// Every golang.org/x module ships a PATENTS file. Counting it as a license
	// text nobody could identify escalated all of them, every time.
	for _, tt := range []struct {
		path string
		want ExclusionReason
	}{
		{path: "PATENTS", want: ExclusionSupplementary},
		{path: "PATENTS.txt", want: ExclusionSupplementary},
		{path: "patents", want: ExclusionSupplementary},
		{path: "NOTICE", want: ExclusionSupplementary},
		{path: "NOTICE.md", want: ExclusionSupplementary},
		{path: "AUTHORS", want: ExclusionSupplementary},
		{path: "CONTRIBUTORS", want: ExclusionSupplementary},
		{path: "sub/dir/PATENTS", want: ExclusionSupplementary},

		// COPYRIGHT often is the license statement, so it stays in scope.
		{path: "COPYRIGHT", want: ExclusionNone},
		{path: "COPYING", want: ExclusionNone},
		{path: "LICENSE", want: ExclusionNone},

		// Vendored still wins: dependency attribution needs those texts.
		{path: "vendor/x/PATENTS", want: ExclusionVendored},
	} {
		t.Run(tt.path, func(t *testing.T) {
			if got := ClassifyExclusion(tt.path); got != tt.want {
				t.Errorf("got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// TestClassifyDirExclusion covers the location-only rule that identity
// enumeration uses, where filename rules must not apply: go.mod is not a
// license file, but where it sits still decides whether it describes this
// component.
func TestClassifyDirExclusion(t *testing.T) {
	for _, tt := range []struct {
		dir  string
		want ExclusionReason
	}{
		{dir: ".", want: ExclusionNone},
		{dir: "src", want: ExclusionNone},
		{dir: "docs", want: ExclusionNone},

		{dir: "vendor/github.com/dep", want: ExclusionVendored},
		{dir: "node_modules/left-pad", want: ExclusionVendored},

		{dir: "tests/syntax-tests/source/Go", want: ExclusionTestFixture},
		{dir: "testdata", want: ExclusionTestFixture},
		{dir: "examples/demo", want: ExclusionTestFixture},

		{dir: "melange-out", want: ExclusionBuildOutput},
		{dir: "melange-out/py3-foo/usr/lib/python3.13/site-packages/dep", want: ExclusionBuildOutput},
		// Whole-segment matching here too.
		{dir: "src/melange-outputs", want: ExclusionNone},

		// A supplementary filename means nothing here: only location counts.
		{dir: "authors", want: ExclusionNone},
	} {
		t.Run(tt.dir, func(t *testing.T) {
			if got := ClassifyDirExclusion(tt.dir); got != tt.want {
				t.Errorf("got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// TestClassifyDirExclusionEnvironmentTrees covers the interpreter and toolchain
// trees. A license inside a virtualenv or a vendored standard library describes
// an installed dependency, not the component, and the version embedded in such
// a directory name must not let it through.
func TestClassifyDirExclusionEnvironmentTrees(t *testing.T) {
	for _, tt := range []struct {
		path string
		want ExclusionReason
	}{
		{"venv/lib/python3.13/site-packages/x/LICENSE", ExclusionVendored},
		{".virtualenv/lib/x/LICENSE", ExclusionVendored},
		{"env/lib/x/LICENSE", ExclusionVendored},
		{"rust-src/library/std/LICENSE-MIT", ExclusionVendored},
		{"rust-1.86.0-src/library/std/LICENSE-MIT", ExclusionVendored},
		{"rustc-src/LICENSE-APACHE", ExclusionVendored},
		// A component whose own name merely contains one of those words is
		// unaffected, because matching is on whole segments.
		{"environment/LICENSE", ExclusionNone},
		{"src/rust-src-tools/LICENSE", ExclusionNone},
	} {
		t.Run(tt.path, func(t *testing.T) {
			if got := ClassifyDirExclusion(tt.path); got != tt.want {
				t.Errorf("ClassifyDirExclusion(%q): got = %q, want = %q", tt.path, got, tt.want)
			}
		})
	}
}
