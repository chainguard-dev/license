/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"chainguard.dev/license/assess"
	"chainguard.dev/license/component"
	"chainguard.dev/license/contenthash"
	"chainguard.dev/license/detect"
	"chainguard.dev/license/internal/digest"
)

// SchemaVersion is the version of the bundle format. It is written into every
// bundle, so a reader never has to infer which rules produced one.
//
// Bump it when a field changes meaning or a required field is added. Adding an
// optional field that an old reader can ignore does not need a bump; changing
// what an existing field records does.
const SchemaVersion = 1

// ErrNoSource means a subject could not supply its source tree. It is recorded
// as incomplete evidence rather than returned, because the installed trees may
// still be readable.
var ErrNoSource = errors.New("subject has no source tree")

// Gap is evidence that could not be gathered.
//
// Gaps are the reason a bundle is trustworthy at all. A component with no
// license file and a component whose license file could not be read look
// identical in a result that only lists what was found, and they mean opposite
// things: the first is a fact about the component, the second is a fact about
// the collection.
type Gap struct {
	// Kind is which evidence is missing, from a closed set so a consumer can
	// match on it.
	Kind GapKind `json:"kind"`
	// Detail is what went wrong, for a human.
	Detail string `json:"detail"`
}

// GapKind names a category of missing evidence.
type GapKind string

const (
	// GapSource means the source tree could not be read, so nothing about the
	// component's own licensing was observed.
	GapSource GapKind = "source"
	// GapInstalled means the installed trees could not be read, so the
	// components that exist only after a build were not enumerated.
	GapInstalled GapKind = "installed"
	// GapNoInstalled means there were no installed trees to read. It is not a
	// failure: it says that the ecosystems named only by a build's output were
	// not covered, which a consumer measuring coverage has to be able to see.
	GapNoInstalled GapKind = "no-installed-trees"
	// GapLicenseFile means an individual license file could not be read. The
	// file's own error says which and why.
	GapLicenseFile GapKind = "license-file"
	// GapUnreadableTree means part of a tree could not be listed, so whatever
	// license files it holds were never discovered.
	GapUnreadableTree GapKind = "unreadable-tree"
	// GapDependencies means a manifest or lockfile could not be read, so the
	// components it names are missing from the closure. Without it, a package
	// whose lockfile failed to parse would be indistinguishable from one with
	// no dependencies.
	GapDependencies GapKind = "dependencies"
)

// Bundle is everything observed about one subject's licensing.
type Bundle struct {
	// SchemaVersion is the format this bundle was written in.
	SchemaVersion int `json:"schema_version"`
	// Subject is the subject's own account of itself.
	Subject Description `json:"subject"`

	// Files are the license texts found in the source tree, classified, with
	// their texts retained and bounded so the bundle can be classified again
	// later without the tree.
	//
	// Vendored copies are retained too, text and all. A pristine one is
	// determined from its registry artifact and its bytes go unread, but
	// collection has no network and so cannot know which copies are pristine --
	// and a copy that turns out to diverge can only be determined from the
	// bytes it actually holds. Retaining them keeps the bundle self-contained,
	// so a divergence found a year later needs no refetch of a tag that may be
	// gone.
	Files []detect.File `json:"files"`
	// Manifests are the license fields the component's own manifests declare:
	// in-source author metadata, distinct from what the build configuration
	// declares.
	Manifests []component.Manifest `json:"manifests,omitempty"`
	// Prose are license mentions in the component's own prose, which is where
	// upstreams that ship no license file state their licensing, and where a
	// choice between several licenses is usually spelled out.
	Prose []detect.ProseHint `json:"prose,omitempty"`
	// Notices are the sampled source-file heads a GPL-family version grant is
	// read from, and NoticesSampled is how many of them were read. The count
	// is what distinguishes notices that were read and granted nothing from
	// notices nobody looked at, so it counts files that were opened rather
	// than candidates that were found.
	Notices        []detect.Notice `json:"notices,omitempty"`
	NoticesSampled int             `json:"notices_sampled"`
	// Grants are the version grants the notices state.
	Grants []detect.Grant `json:"grants,omitempty"`

	// Components are the things whose licenses have to be determined: the
	// subject's own source first, followed by the ecosystem components it pulls
	// in. Identities only; no licensing is resolved here.
	//
	// A dependency's own licensing is deliberately absent, because collection
	// has no network and most dependencies are named by a lockfile and never
	// appear in the tree at all. What the bundle carries instead is enough to
	// settle each one later without collecting again: the identity and
	// ecosystem digest to fetch it by, the license files of any copy vendored
	// into the tree, which are in Files and marked as belonging to it, and that
	// copy's license-content hash, so it can be checked against the artifact it
	// claims to be.
	Components []component.Component `json:"components"`
	// VendorRoot is the directory the build vendors dependency source into,
	// relative to the source tree, recorded so a consumer can locate a
	// component's local copy without a tree to look at.
	VendorRoot string `json:"vendor_root,omitempty"`
	// VendoredCopies name the components whose source is vendored into the
	// tree, and the directory each copy occupies.
	//
	// Recorded rather than re-derived, because deriving it needs the tree's
	// layout and a consumer reading a bundle a year later has only the bundle.
	// It is what makes the subset test possible from evidence alone: the copy's
	// own license files are in Files, and this says which of them are whose.
	VendoredCopies []VendoredCopy `json:"vendored_copies,omitempty"`

	// LicenseContentHash keys the subject's own licensing evidence. A consumer
	// storing a determination stores it under this.
	LicenseContentHash string `json:"license_content_hash"`
	// Conclusion is what the subject's own license files resolve to, and
	// Assessment is how far that evidence goes.
	Conclusion Conclusion        `json:"conclusion"`
	Assessment assess.Assessment `json:"assessment"`

	// Gaps are the evidence that could not be gathered.
	Gaps []Gap `json:"gaps,omitempty"`
	// Notes carry caveats about the collection: how many texts were truncated,
	// which enumerators found nothing. They describe the collection, never the
	// licensing.
	Notes []string `json:"notes,omitempty"`
}

// VendoredCopy is one component whose source is vendored into the subject's
// tree.
type VendoredCopy struct {
	// PURL identifies the component.
	PURL string `json:"purl"`
	// Root is the directory its copy occupies, relative to the source tree.
	Root string `json:"root"`
}

// LocalLicenseFiles returns the license files the tree's own copy of a
// component holds, with paths relative to that copy so they compare against a
// published artifact rooted at the component itself.
//
// This is the local side of the subset test in contenthash.Verify. Nothing is
// returned for a component with no copy in the tree, which is most of them: a
// crate or an npm package is named by a lockfile and never appears. A caller
// gets no verification in that case rather than a wrong one - an empty local
// set is trivially a subset, which leaves the answer where it was.
func (b *Bundle) LocalLicenseFiles(purl string) []contenthash.File {
	root := ""
	roots := make([]string, 0, len(b.VendoredCopies))
	for _, copied := range b.VendoredCopies {
		roots = append(roots, copied.Root)
		if copied.PURL == purl {
			root = copied.Root
		}
	}
	if root == "" {
		return nil
	}
	return contenthash.Relative(contenthash.From(b.Files), root, contenthash.NestedRoots(root, roots))
}

// Conclusion is the license the subject's own files resolve to, in the form a
// bundle records it.
//
// It repeats what detect.Conclude returns rather than embedding that type,
// because a bundle is a wire format: the fields here are the ones a consumer
// reads back, and they have to stay stable independently of a Go struct that
// carries whole file records for the caller's convenience.
type Conclusion struct {
	// Expression is the SPDX expression the evidence settles on, empty when it
	// does not settle one.
	Expression string `json:"expression,omitempty"`
	// Reason says why no expression was reached.
	Reason detect.Reason `json:"reason,omitempty"`
	// Identifiers are the distinct SPDX identifiers found in scope.
	Identifiers []string `json:"identifiers,omitempty"`
	// GrantBasis says where a GPL-family version grant came from.
	GrantBasis detect.GrantBasis `json:"grant_basis,omitempty"`
	// LicenseRef is the name minted for license text nothing recognized, empty
	// when everything was recognized. It is derived from the text of the
	// highest-weighted unrecognized file.
	LicenseRef string `json:"license_ref,omitempty"`
}

// Complete reports whether every kind of evidence the bundle set out to gather
// was gathered.
//
// A consumer deciding whether to trust a "no license found" answer has to check
// this first: the same empty result means "this component has no license
// declaration" on a complete bundle and "we could not look" on an incomplete
// one.
func (b *Bundle) Complete() bool { return len(b.Gaps) == 0 }

// Encode renders the bundle canonically, so that identical observations produce
// identical bytes and a consumer can content-address it.
//
// The guarantee rests on the bundle holding no maps and on every slice in it
// being ordered by collection: Go's JSON encoder writes struct fields in
// declaration order, so the remaining source of variation would be iteration
// order, and there is none to have.
func (b *Bundle) Encode() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// Escaping is deterministic either way, but leaving license texts unescaped
	// keeps a stored bundle readable by anything that reads JSON.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(b); err != nil {
		return nil, fmt.Errorf("encoding bundle: %w", err)
	}
	return buf.Bytes(), nil
}

// Digest is the content address of the bundle's canonical encoding, which is
// what a consumer stores it under.
func (b *Bundle) Digest() (string, error) {
	encoded, err := b.Encode()
	if err != nil {
		return "", err
	}
	return digest.Bytes(encoded), nil
}
