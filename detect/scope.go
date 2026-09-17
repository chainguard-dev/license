/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"path"
	"regexp"
	"strings"
)

// ExclusionReason explains why a discovered license file is not evidence about
// the licensing of the component it was found in.
//
// Exclusions are recorded rather than dropped. A license file under docs/ or
// examples/ is occasionally the project's real license, so the decision stays
// visible to a reader of the evidence instead of silently removing a file from
// it.
type ExclusionReason string

const (
	// ExclusionNone marks a file that describes the component itself.
	ExclusionNone ExclusionReason = ""
	// ExclusionVendored marks a file that describes bundled third-party code.
	// These files are still load-bearing for dependency collection, which maps
	// them onto the components they belong to.
	ExclusionVendored ExclusionReason = "vendored"
	// ExclusionSupplementary marks a file that accompanies a license without
	// being one: a patent grant, an attribution notice, an authors list. These
	// are worth collecting as context, but treating one as an unreadable
	// license text would report a gap where none exists.
	ExclusionSupplementary ExclusionReason = "supplementary"
	// ExclusionTestFixture marks a file that describes test or sample data.
	// Fixture corpora routinely carry licenses unrelated to the project, and
	// often deliberately exotic ones, so they must not reach the component's
	// own license expression.
	ExclusionTestFixture ExclusionReason = "test-fixture"
	// ExclusionBuildOutput marks a file under the tree a build installed into
	// rather than the tree it was built from. What a build installs is a mix of
	// the component's own artifacts and whatever its dependencies brought with
	// them, so nothing there speaks for the component on its own.
	ExclusionBuildOutput ExclusionReason = "build-output"
)

// vendorDirSegments are path segments holding code that belongs to another
// component.
//
// The interpreter and toolchain trees are here for the same reason the
// package-manager directories are: a virtualenv holds installed dependencies
// and a rust-src tree holds the standard library's own source, so a license
// found inside either describes something other than the project. "env" is
// aggressive on its own terms, and is kept because the trees that carry it in
// practice are virtualenvs.
var vendorDirSegments = map[string]struct{}{
	"vendor":       {},
	"third_party":  {},
	"third-party":  {},
	"thirdparty":   {},
	"3rdparty":     {},
	"external":     {},
	"deps":         {},
	"node_modules": {},
	"venv":         {},
	".virtualenv":  {},
	"env":          {},
	"rust-src":     {},
	"rustc-src":    {},
}

// buildOutputDirSegments are path segments that indicate a build's install
// root. melange stages each (sub)package under melange-out/<name>/ inside the
// same workspace the source is unpacked into, so an audit pointed at that
// workspace sees the built tree beside the tree it was built from.
//
// That tree is worth enumerating on its own terms - it is where the identities
// of installed Python distributions and bundled jars come from - but it is
// never read as source. A dependency pip installed into site-packages carries
// its own notices, and attributing those to the package being built is a wrong
// answer stated confidently.
var buildOutputDirSegments = map[string]struct{}{
	"melange-out": {},
}

// testDirSegments are path segments that indicate test fixtures, sample inputs
// or demo material. Matching is on whole segments, so a component legitimately
// named "testify" is unaffected.
//
// docs/ is deliberately absent: projects do put their real license there.
var testDirSegments = map[string]struct{}{
	"test":       {},
	"tests":      {},
	"testdata":   {},
	"test_data":  {},
	"test-data":  {},
	"__tests__":  {},
	"example":    {},
	"examples":   {},
	"fixture":    {},
	"fixtures":   {},
	"sample":     {},
	"samples":    {},
	"demo":       {},
	"demos":      {},
	"spec":       {},
	"specs":      {},
	"benchmark":  {},
	"benchmarks": {},
}

// supplementaryFileNames are base names, extension aside, of files that sit
// beside a license without stating license terms.
//
// PATENTS is the case that matters most: every golang.org/x module ships one,
// so counting it as a license text nobody could identify would escalate the
// most widely depended-on modules in the corpus, every time, over a file that
// is not a license. COPYRIGHT is deliberately absent - it frequently is the
// license statement.
var supplementaryFileNames = map[string]struct{}{
	"patents":      {},
	"patent":       {},
	"notice":       {},
	"notices":      {},
	"authors":      {},
	"contributors": {},
	"credits":      {},
}

// semverSegmentRe collapses an embedded version in a path segment so that the
// segment lists match a versioned directory: rust-1.86.0-src becomes rust-src.
var semverSegmentRe = regexp.MustCompile(`-\d+\.\d+\.\d+-`)

// ClassifyExclusion reports whether a license-file path describes the component
// itself, and if not, why.
//
// Callers classifying the contents of a fetched artifact use it too, so a
// published module and a package's source tree are scoped by identical rules.
func ClassifyExclusion(p string) ExclusionReason {
	switch reason := ClassifyDirExclusion(p); reason {
	case ExclusionNone:
		return supplementaryName(p)
	case ExclusionVendored, ExclusionBuildOutput:
		// These say the file belongs to another component entirely, which
		// outranks anything its name could say about it. Vendored in particular
		// has to survive so dependency collection can still find the text.
		return reason
	default:
		// A supplementary file is named as such wherever it sits, and saying why
		// it is not a license is more useful than saying where it lives, so the
		// filename check still gets to speak.
		if named := supplementaryName(p); named != ExclusionNone {
			return named
		}
		return reason
	}
}

// ClassifyDirExclusion reports whether a path lies outside the component's own
// source, from its directory segments alone.
//
// Enumerating component identities uses this rather than ClassifyExclusion: a
// manifest is not a license file, so the filename rules do not apply to it, but
// the location rules do. A go.sum under tests/ belongs to a fixture corpus, and
// reading it invents dependencies the package does not have - in bat's tree
// that file is ANSI-rendered highlighter output, so the "modules" it yields
// carry escape codes in their purls. A go.sum under melange-out/ came from the
// build's own output and describes whatever was installed there, not the
// source.
func ClassifyDirExclusion(p string) ExclusionReason {
	reason := ExclusionNone
	for seg := range strings.SplitSeq(normalizePath(p), "/") {
		s := strings.ToLower(semverSegmentRe.ReplaceAllString(seg, "-"))
		if _, ok := vendorDirSegments[s]; ok {
			return ExclusionVendored
		}
		if _, ok := buildOutputDirSegments[s]; ok {
			return ExclusionBuildOutput
		}
		if _, ok := testDirSegments[s]; ok {
			reason = ExclusionTestFixture
		}
	}
	return reason
}

// supplementaryName reports whether a path's filename names a file that sits
// beside a license without stating license terms.
func supplementaryName(p string) ExclusionReason {
	base := strings.ToLower(path.Base(normalizePath(p)))
	if ext := path.Ext(base); ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	if _, ok := supplementaryFileNames[base]; ok {
		return ExclusionSupplementary
	}
	return ExclusionNone
}

// normalizePath renders a path with slash separators, so that a caller holding
// a native path is not silently misread on a platform that uses another one.
func normalizePath(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}
