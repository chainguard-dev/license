/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"

	"chainguard.dev/license/internal/digest"
	"chainguard.dev/license/spdx"
)

// MaxTextBytes is the default bound on how much of one license text is
// retained. License texts are kilobytes; a file far past this is not a license,
// and retaining it unbounded would let a source tree decide how much memory the
// caller holds.
const MaxTextBytes = 128 << 10

// Declaration is a license the caller already believes applies, taken from a
// build configuration or a manifest.
//
// It is ecosystem-neutral on purpose. melange reads it out of a package's
// copyright block, an npm consumer out of package.json, and another consumer
// out of whatever produced its evidence; none of that shape reaches this
// package, which knows only that somebody claimed a license and, sometimes,
// which file they claimed it for.
type Declaration struct {
	// License is the declared SPDX expression, exactly as declared. It is not
	// canonicalized here: reporting what was written is what lets a
	// disagreement be attributed to the declaration rather than to a rewrite of
	// it. Run spdx.Canonicalize to compare it against detection.
	License string `json:"license"`
	// Path names the license file the declaration describes, when it describes
	// one. A declaration with no path speaks for the component as a whole.
	Path string `json:"path,omitempty"`
	// Override records a classification the declaration knowingly disagrees
	// with, so that a difference somebody has already reviewed stops being
	// reported as new. It holds the identifier the classifier is expected to
	// produce, and stops applying the moment the classifier produces a
	// different one.
	Override string `json:"override,omitempty"`
}

// Request is what to inspect.
type Request struct {
	// FS is the tree to read. Callers scanning a directory should pass an
	// os.Root filesystem, so a symlink escaping the tree fails to resolve
	// rather than reading the host filesystem.
	FS fs.FS
	// Scope bounds discovery. The zero value, ScopeProject, looks for the
	// component's own license.
	Scope Scope
	// Declared are the licenses the caller already believes apply. A
	// declaration naming a path that discovery did not find is still read and
	// classified, since a component that keeps its license somewhere
	// unconventional is exactly the case a declaration exists to record.
	Declared []Declaration
	// RetainText keeps each classified text in the result, bounded by
	// MaxTextBytes, for a caller that has to persist evidence or classify it
	// again later. It is off by default: a build-time check has the tree in
	// front of it and needs no copy.
	//
	// Naming an unrecognized license needs it. A LicenseRef is a digest of the
	// license text, so Conclusion.UnrecognizedText fails without it rather than
	// naming the component something that reads as unlicensed.
	RetainText bool
	// Classifier identifies the texts. A nil Classifier uses a shared default
	// built once per process from the licenseclassifier corpus and Supplement.
	Classifier Classifier
}

// File is one discovered license file and what it was concluded to be.
type File struct {
	// Path is the file's path within the scanned filesystem.
	Path string `json:"path"`
	// Weight is the filename-based relevance from discovery, carried so that
	// whatever weighs candidates later weighs them as discovery did.
	Weight float64 `json:"weight"`
	// Excluded says why the file is not evidence about this component, and is
	// empty for a file that is.
	Excluded ExclusionReason `json:"excluded,omitempty"`
	// License is the classifier's own name for the strongest match, reported
	// verbatim, and NoAssertion when nothing matched. Normalize it through the
	// spdx package before comparing or publishing it.
	License string `json:"license"`
	// Confidence is the classifier's confidence in License.
	Confidence float64 `json:"confidence"`
	// AdditionalLicenses are the other licenses the classifier recognized in
	// the same file, strongest first.
	//
	// One file can carry two license texts - a LICENSE that appends a bundled
	// dependency's terms is the common shape - and they are two licenses. Only
	// reporting the strongest would settle such a component on one license and
	// hide the other, which is the direction of error that tells a consumer
	// they may ignore obligations they have.
	AdditionalLicenses []Match `json:"additional_licenses,omitempty"`
	// Declared is the license the caller declared for this file, when they
	// declared one, and Override the classification that declaration knowingly
	// disagrees with.
	Declared string `json:"declared,omitempty"`
	Override string `json:"override,omitempty"`
	// SizeBytes and Digest identify the whole file regardless of what Text
	// holds. The digest normalizes line endings; see contenthash for what that
	// means and why.
	SizeBytes int64  `json:"size_bytes"`
	Digest    string `json:"digest"`
	// Text is the retained license text, present only when the request asked
	// for it, and Truncated records that it is only the beginning of the file
	// so that a later non-match can be attributed to the bound rather than to
	// the text.
	Text      string `json:"text,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	// Err records why this file could not be read or classified. The rest of
	// the result stands: one unreadable file is not a reason to discard the
	// evidence the others carry.
	Err string `json:"error,omitempty"`
}

// Identifier is the SPDX identifier of the file's strongest match, or "" for a
// file nothing identified.
//
// A GPL-family match whose version grant is still undecided contributes its
// base identifier, so that two files carrying the same license do not read as
// two different licenses and raise a relationship ambiguity that is not there.
func (f File) Identifier() string {
	return identifierOf(f.License)
}

// Identifiers are every SPDX identifier the file contributes to the component's
// license set, from the matches classified at or above ConfidenceThreshold,
// sorted.
//
// Empty when nothing in the file classified confidently, which is what
// distinguishes a file that named a license from one that only held text.
func (f File) Identifiers() []string {
	found := map[string]struct{}{}
	for _, m := range append([]Match{{Name: f.License, Confidence: f.Confidence}}, f.AdditionalLicenses...) {
		if m.Confidence < ConfidenceThreshold {
			continue
		}
		if id := identifierOf(m.Name); id != "" {
			found[id] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(found))
}

// identifierOf normalizes one classifier name onto the identifier it
// contributes.
func identifierOf(name string) string {
	if name == "" || name == NoAssertion {
		return ""
	}
	r := spdx.Normalize(name)
	if r.ID != "" {
		return r.ID
	}
	return r.GrantBase
}

// Resolution maps the classifier's name onto SPDX.
//
// Derived rather than stored, so there is one source of truth: a stored copy
// could be left unset by a caller building the struct directly, and the file
// would then read as unidentified.
func (f File) Resolution() spdx.Resolution {
	if f.License == "" || f.License == NoAssertion {
		return spdx.Resolution{}
	}
	return spdx.Normalize(f.License)
}

// Identified reports whether the file classified to a license SPDX can name.
func (f File) Identified() bool { return f.Resolution().Known() }

// Confident reports whether the file both classified and did so at or above
// ConfidenceThreshold.
func (f File) Confident() bool {
	return f.Identified() && f.Confidence >= ConfidenceThreshold
}

// InScope reports whether the file is evidence about the component's own
// licensing.
func (f File) InScope() bool { return f.Excluded == ExclusionNone }

// Result is what a tree contained.
type Result struct {
	// Files are the discovered license files, ordered by descending discovery
	// weight with ties broken by path.
	Files []File `json:"files"`
	// Unreadable are the paths the scan could not read or descend into, so that
	// a tree with no license evidence stays distinguishable from one that could
	// not be read to the end.
	Unreadable []string `json:"unreadable,omitempty"`
	// Notes carry caveats about the completeness of the result: texts truncated
	// at the bound, declarations naming a file that is not there. They describe
	// the collection, never the licensing.
	Notes []string `json:"notes,omitempty"`
}

// InScope returns the files that are evidence about the component itself.
func (r *Result) InScope() []File {
	var out []File
	for _, f := range r.Files {
		if f.InScope() {
			out = append(out, f)
		}
	}
	return out
}

// Detect discovers the license files in a tree and classifies them.
//
// An invalid request returns an error, as does a failure to walk the tree at
// all. Everything else is reported per file: a file that could not be read or
// classified carries its own Err and the rest of the result stands, so a caller
// can tell a tree with no license evidence from one it could not finish
// reading.
func Detect(ctx context.Context, req Request) (*Result, error) {
	if req.FS == nil {
		return nil, errors.New("detect: request has no filesystem")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c := req.Classifier
	if c == nil {
		shared, err := sharedClassifier()
		if err != nil {
			return nil, fmt.Errorf("detect: loading the license classifier: %w", err)
		}
		c = shared
	}

	found, err := Find(req.FS, req.Scope)
	if err != nil {
		return nil, fmt.Errorf("detect: finding license files: %w", err)
	}

	res := &Result{Unreadable: found.Unreadable}
	candidates := found.Candidates
	declared := declarationsByPath(req.Declared)

	// A declaration naming a file discovery did not select is read anyway. That
	// is the whole point of being able to declare a path: a component keeping
	// its license in an unconventionally named file has no other way to say so.
	for _, extra := range declaredOnlyPaths(declared, candidates) {
		candidates = append(candidates, Candidate{Path: extra, Excluded: ClassifyExclusion(extra)})
	}

	truncated := 0
	for _, cand := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f := File{
			Path:     cand.Path,
			Weight:   cand.Weight,
			Excluded: cand.Excluded,
			License:  NoAssertion,
		}
		if d, ok := declared[cand.Path]; ok {
			f.Declared, f.Override = d.License, d.Override
		}

		if err := readFile(req, cand.Path, &f); err != nil {
			f.Err = err.Error()
			res.Files = append(res.Files, f)
			continue
		}
		if f.Truncated {
			truncated++
		}
		matches, err := c.Identify(req.FS, cand.Path)
		if err != nil {
			f.Err = fmt.Sprintf("classifying: %v", err)
			res.Files = append(res.Files, f)
			continue
		}
		if len(matches) > 0 {
			f.License, f.Confidence = matches[0].Name, matches[0].Confidence
			f.AdditionalLicenses = matches[1:]
		}
		res.Files = append(res.Files, f)
	}

	if truncated > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d license texts truncated at %d bytes", truncated, MaxTextBytes))
	}
	return res, nil
}

// readFile fills in a file's size, digest and, when the request asks for it,
// its bounded text.
//
// The digest covers the whole file and the retained text may not, so they are
// read separately rather than the digest being taken over what was retained.
// A truncated text whose digest only covered its beginning would compare equal
// to a different file that happened to share a prologue, which for license
// texts is not a hypothetical: every GPL variant shares one.
func readFile(req Request, p string, f *File) error {
	info, err := fs.Stat(req.FS, p)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	f.SizeBytes = info.Size()

	body, err := req.FS.Open(p)
	if err != nil {
		return fmt.Errorf("opening: %w", err)
	}
	defer body.Close()
	if f.Digest, err = digest.File(body); err != nil {
		return fmt.Errorf("digesting: %w", err)
	}

	if !req.RetainText {
		return nil
	}
	text, err := req.FS.Open(p)
	if err != nil {
		return fmt.Errorf("opening: %w", err)
	}
	defer text.Close()
	retained, err := io.ReadAll(io.LimitReader(text, MaxTextBytes))
	if err != nil {
		return fmt.Errorf("reading: %w", err)
	}
	f.Text = string(retained)
	f.Truncated = int64(len(retained)) < f.SizeBytes
	return nil
}

// declarationsByPath indexes the declarations that name a file.
//
// A declaration with no path is not indexed here: it speaks for the component
// rather than for a file, and attaching it to an arbitrary file would put words
// in the declarer's mouth.
func declarationsByPath(declared []Declaration) map[string]Declaration {
	byPath := make(map[string]Declaration, len(declared))
	for _, d := range declared {
		if d.Path != "" {
			byPath[path.Clean(d.Path)] = d
		}
	}
	return byPath
}

// declaredOnlyPaths lists the declared paths discovery did not select, sorted so
// the result stays deterministic.
func declaredOnlyPaths(declared map[string]Declaration, candidates []Candidate) []string {
	if len(declared) == 0 {
		return nil
	}
	found := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		found[c.Path] = struct{}{}
	}
	extra := map[string]struct{}{}
	for p := range declared {
		if _, ok := found[p]; !ok {
			extra[p] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(extra))
}
