/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"

	"chainguard.dev/license/spdx"
)

// Reason names why a conclusion carries no expression. It is a closed set, so
// consumers match on it rather than parsing prose.
type Reason string

const (
	// ReasonSettled means the conclusion carries an expression.
	ReasonSettled Reason = ""
	// ReasonNoLicenseText means the component ships no license text in scope.
	// Nothing was read, so there is nothing for a deeper look to read either --
	// this is a coverage gap rather than an ambiguity.
	ReasonNoLicenseText Reason = "no-license-text"
	// ReasonUnrecognized means license text is present but nothing identified
	// it. A caller that has to record the license anyway mints a LicenseRef
	// from the text, so a proprietary EULA is recorded rather than dropped.
	ReasonUnrecognized Reason = "unrecognized-license-text"
	// ReasonSeveralLicenses means several licenses were identified with nothing
	// authoritative saying how they compose. Deterministic detection
	// structurally cannot decide between AND and OR here, and guessing wrong in
	// the OR direction would tell a consumer they may ignore obligations they
	// have.
	ReasonSeveralLicenses Reason = "several-licenses"
	// ReasonGrantUndecided means one license is identified but the tree states
	// both version grants for it, so which one the author made is a finding
	// rather than a tie to break.
	ReasonGrantUndecided Reason = "grant-undecided"
)

// Conclusion is the license a component's own license files resolve to.
type Conclusion struct {
	// Expression is the SPDX expression the evidence settles on, and is empty
	// exactly when Reason is not ReasonSettled.
	Expression string
	// Reason says why no expression was reached.
	Reason Reason
	// Identifiers are the distinct SPDX identifiers found in scope, sorted.
	// It is populated whether or not an expression was reached, so a caller
	// reporting an ambiguity can say what the licenses were.
	Identifiers []string
	// GrantBasis says where a GPL-family version grant came from, and is empty
	// when no license involved has one.
	GrantBasis GrantBasis
	// Unrecognized are the in-scope files holding license text that nothing
	// identified, in discovery order. A caller minting a LicenseRef names it
	// from the text of the first of these, which UnrecognizedText returns.
	Unrecognized []File
	// Files are the in-scope files the conclusion was drawn from.
	Files []File
}

// UnrecognizedText returns the text a LicenseRef is minted from, which is the
// text of the strongest file nothing identified.
//
// It reports an error rather than an empty string when the conclusion holds
// unrecognized text that was not retained, because the request did not ask for
// it. A ref cannot be derived from text nobody kept, and returning nothing
// would name the license the empty string hashes to - which reads downstream
// as no license found, the worst available answer for the proprietary license
// this path exists to catch. The file's path and digest are still in
// Unrecognized, so a caller holding the tree can read the text and try again.
func (c Conclusion) UnrecognizedText() (string, error) {
	if len(c.Unrecognized) == 0 {
		return "", errors.New("the conclusion holds no unrecognized license text")
	}
	first := c.Unrecognized[0]
	if first.Text == "" {
		return "", fmt.Errorf("license text at %q was not retained: naming it needs Request.RetainText", first.Path)
	}
	return first.Text, nil
}

// Conclude resolves the component's own license from the files that were
// classified.
//
// Only files in scope count: a vendored dependency's license and a fixture
// corpus's exotic license say nothing about this component. Of those, a license
// file in the root wins outright - when the root holds any license file, files
// below it are not considered at all, so a stray license deeper in the tree
// cannot make the project's own licensing look ambiguous.
//
// grants resolves the GPL family's -only versus -or-later suffix, which no
// license text can express. Where the notices state no grant, the conclusion is
// the -only form, because that grant has to be explicit; whether that reading
// rests on notices actually read or on nobody having looked is the difference
// between GrantAbsent and GrantUnknown, and the caller can tell which it got.
func (r *Result) Conclude(grants GrantEvidence) Conclusion {
	files := preferRoot(r.InScope())
	c := Conclusion{Files: files}

	// A file contributes every license it carries, not just its strongest: two
	// license texts in one file are two licenses, and settling the component on
	// one of them would hide the other's terms.
	byIdentifier := map[string]File{}
	for _, f := range files {
		if f.Err != "" {
			continue
		}
		identifiers := f.Identifiers()
		for _, id := range identifiers {
			byIdentifier[id] = f
		}
		if len(identifiers) > 0 {
			continue
		}
		// Text was there and nothing named it confidently. A file that merely
		// accompanies a license is already out of scope, so what is left is a
		// real license nobody recognized.
		if f.SizeBytes > 0 {
			c.Unrecognized = append(c.Unrecognized, f)
		}
	}
	c.Identifiers = slices.Sorted(maps.Keys(byIdentifier))

	switch len(c.Identifiers) {
	case 0:
		if len(c.Unrecognized) > 0 {
			c.Reason = ReasonUnrecognized
			return c
		}
		c.Reason = ReasonNoLicenseText
		return c
	case 1:
	default:
		c.Reason = ReasonSeveralLicenses
		return c
	}

	resolution := spdx.Normalize(c.Identifiers[0])
	if !resolution.NeedsGrant() {
		c.Expression = c.Identifiers[0]
		return c
	}

	switch expr, matched := GrantFor(resolution, grants.Grants); {
	case matched == 1:
		c.Expression, c.GrantBasis = expr, GrantFromNotice
	case matched > 1:
		c.Reason, c.GrantBasis = ReasonGrantUndecided, GrantMixed
	case grants.Sampled > 0:
		c.Expression, c.GrantBasis = resolution.Only, GrantAbsent
	default:
		c.Expression, c.GrantBasis = resolution.Only, GrantUnknown
	}
	return c
}

// preferRoot restricts the files to those in the component root, when the root
// holds any at all.
func preferRoot(files []File) []File {
	root := make([]File, 0, len(files))
	for _, f := range files {
		if path.Dir(f.Path) == "." {
			root = append(root, f)
		}
	}
	if len(root) > 0 {
		return root
	}
	return files
}
