/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package contenthash

import (
	"fmt"
	"slices"
	"strings"
)

// Verification is the outcome of checking a local copy of a component against
// the published artifact it claims to be. It is what decides which hash the
// determination is keyed on: the published one for a copy that verifies, its
// own for one that does not.
type Verification int

const (
	// Pristine means every license file the local copy holds appears in the
	// published artifact under the same path with the same digest. As far as
	// licensing goes the copy is the published content, and shares its answer.
	Pristine Verification = iota
	// Diverged means the local copy holds a license file the published artifact
	// does not, or holds one whose contents differ. It is a variant of its own
	// and answers only through the component that contains it.
	Diverged
)

// String renders the verification for a log line or a stored record.
func (v Verification) String() string {
	if v == Pristine {
		return "pristine"
	}
	return "diverged"
}

// Verify reports whether a local copy of a component is the published content,
// comparing its license files against the published artifact's.
//
// The test is a subset, not an equality: the local copy must hold nothing the
// published artifact lacks and nothing whose contents differ, but the published
// artifact may hold more. Vendoring is why. "go mod vendor" copies only the
// packages a build imports, so a pristine copy routinely holds fewer license
// files than the module it came from - measured across melange's own
// 165-module vendor tree, an equality test calls 13 of them divergent and this
// one calls none.
//
// The asymmetry costs one case. A license file deleted locally is
// indistinguishable from one vendoring never copied, so a removal is not
// detected. That miss is benign: a copy that verifies is determined from the
// published artifact rather than from the local copy, and removing evidence
// cannot grant terms upstream withheld. The two cases that could claim terms
// upstream never granted - a license file edited in place, or one added
// locally - both fail.
//
// A pass says nothing about provenance, and nothing about whether the license
// is acceptable. Checking the published artifact's digest against the
// ecosystem's own checksum database is a separate question that upstream
// answers.
//
// A local copy with no license files verifies, because nothing it holds is
// missing from the artifact - that is the empty case of the subset test, and
// it is why a caller must not call this with an artifact it failed to fetch.
//
// reason is empty for a pristine copy, and otherwise names the first file that
// failed, so a divergence can be explained.
func Verify(local, published []File) (v Verification, reason string) {
	// Nothing to compare against is not a pass. A published artifact with no
	// license files cannot contain the ones the local copy holds, and the case
	// that reaches here in practice is a caller whose fetch failed: a vacuous
	// pristine would key that copy on an answer drawn from bytes nobody read.
	if len(published) == 0 && len(local) > 0 {
		return Diverged, "the published artifact holds no license files to compare against"
	}

	byPath := make(map[string]string, len(published))
	for _, f := range published {
		byPath[f.Path] = f.Digest
	}

	// Sorted so the file named in the reason is stable across runs rather than
	// whichever one the caller happened to list first.
	sorted := make([]File, len(local))
	copy(sorted, local)
	slices.SortFunc(sorted, func(a, b File) int { return strings.Compare(a.Path, b.Path) })

	for _, f := range sorted {
		switch digest, present := byPath[f.Path]; {
		case !present:
			return Diverged, fmt.Sprintf("%s is not in the published artifact", f.Path)
		case digest != f.Digest:
			return Diverged, fmt.Sprintf("%s differs from the published artifact", f.Path)
		}
	}
	return Pristine, ""
}
