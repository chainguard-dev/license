/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"io"
	"io/fs"
	"sync"

	licenseclassifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
)

// ConfidenceThreshold is the classifier confidence at or above which a
// license-text match is treated as settled. Below it the match is reported with
// its confidence and counts as unidentified, which is what sends a component to
// be read by something that can weigh the whole document.
const ConfidenceThreshold = 0.9

// NoAssertion is the SPDX sentinel for "no claim is being made", reported both
// when no license text was found and when a classification was inconclusive.
const NoAssertion = "NOASSERTION"

// Match is one license the classifier recognized in a file.
type Match struct {
	// Name is the classifier's own name for the license, reported verbatim.
	// It is frequently not an SPDX identifier - the classifier emits names
	// that were never SPDX and names SPDX has deprecated - so nothing
	// downstream should compare or publish it without normalizing it through
	// the spdx package first.
	Name       string
	Confidence float64
}

// HeaderMatch is a license notice matched in source text.
//
// Notices are matched separately from license files because they answer a
// different question. A license file says which license; a notice says how the
// author applied it - and for the GPL family that is the only place the
// -only/-or-later grant appears, since SPDX ships identical text for both.
// Variant identifies which wording matched, which is what distinguishes a
// later-version grant from a bare-version one.
type HeaderMatch struct {
	Name       string
	Variant    string
	Confidence float64
}

// Classifier identifies license texts and license notices.
type Classifier interface {
	// Identify classifies the contents of one file, returning one Match per
	// distinct license recognized in it, in the classifier's own order.
	Identify(fsys fs.FS, path string) ([]Match, error)
	// IdentifyHeader matches a license notice in source text.
	IdentifyHeader(data []byte) []HeaderMatch
}

// classifier wraps licenseclassifier behind the Classifier interface, so that
// callers can substitute one and so that the dependency does not appear in this
// package's public API.
type classifier struct {
	inner *licenseclassifier.Classifier
}

// NewClassifier returns a classifier over the licenseclassifier corpus together
// with Supplement, which is the combination this module treats as
// authoritative.
func NewClassifier() (Classifier, error) {
	return NewClassifierWithSupplement(Supplement())
}

// NewClassifierWithSupplement returns a classifier that also knows the license
// texts in extra, keyed by SPDX identifier.
//
// The bundled corpus covers a minority of the SPDX license list, and a license
// missing from it is not reported as unrecognized: it is reported as the
// nearest text the corpus does contain, at full confidence. Supplying the
// missing texts is the only fix for that, since no amount of reasoning about a
// wrong answer recovers the right one.
//
// A caller that must reproduce the bundled corpus exactly, with no additions,
// passes nil.
func NewClassifierWithSupplement(extra map[string][]byte) (Classifier, error) {
	c, err := assets.DefaultClassifier()
	if err != nil {
		return nil, err
	}
	for id, text := range extra {
		c.AddContent("License", id, "pristine", text)
	}
	return &classifier{inner: c}, nil
}

// sharedClassifier builds the default classifier once per process; its embedded
// license corpus is expensive to parse and every caller wants the same one.
var sharedClassifier = sync.OnceValues(NewClassifier)

// DefaultClassifier returns the classifier this package uses when a request
// names none, built once per process.
//
// It is exported because parsing the corpus costs a third of a second, and a
// caller that needs a classifier of its own - to read notices alongside
// license files, say - should not pay that per component. It is also what
// keeps one classifier answering every question in a run, which is what stops
// a supplemented corpus from being silently bypassed by half the callers.
func DefaultClassifier() (Classifier, error) { return sharedClassifier() }

// Identify implements Classifier.
func (c *classifier) Identify(fsys fs.FS, path string) ([]Match, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// The read is bounded because the tree is untrusted input. MatchFrom
	// consumes its reader in chunks but retains a token per word for the whole
	// document, so its memory grows with the file and a multi-gigabyte file
	// named LICENSE would let the tree decide how much the caller holds. The
	// bound is the one MaxTextBytes sets on retention, for the same reason: a
	// file far past it is not a license.
	matches, err := c.inner.MatchFrom(io.LimitReader(f, MaxTextBytes))
	if err != nil {
		return nil, err
	}

	var out []Match
	seen := map[string]struct{}{}
	for _, m := range matches.Matches {
		// Header matches are dropped here on purpose: a license file that
		// happens to contain a notice is still classified by the license text
		// it contains. IdentifyHeader is the other half.
		if m.MatchType != "License" {
			continue
		}
		if _, repeated := seen[m.Name]; repeated {
			continue
		}
		seen[m.Name] = struct{}{}
		out = append(out, Match{Name: m.Name, Confidence: m.Confidence})
	}
	return out, nil
}

// IdentifyHeader implements Classifier.
func (c *classifier) IdentifyHeader(data []byte) []HeaderMatch {
	var out []HeaderMatch
	for _, m := range c.inner.Match(data).Matches {
		if m.MatchType != "Header" {
			continue
		}
		out = append(out, HeaderMatch{Name: m.Name, Variant: m.Variant, Confidence: m.Confidence})
	}
	return out
}
