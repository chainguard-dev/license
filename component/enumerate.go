/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"cmp"
	"context"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"unicode"

	"chainguard.dev/license/detect"
)

// Tree is a filesystem a build produced, as opposed to the source tree it was
// produced from.
//
// Taking an fs.FS is what keeps enumeration independent of how the build was
// run: a staged melange-out directory, an expanded apk, and a published jar or
// wheel differ in how they were acquired, not in how a component announces
// itself inside them.
type Tree struct {
	// Name labels where the tree came from, so an identity can be traced back
	// to the artifact it was read out of. It need not exist on disk.
	Name string
	// FS is the tree's contents, rooted at what the build installed.
	FS fs.FS
}

// Failure is a manifest or lockfile that could not be read.
//
// It is reported apart from the notes because it is a different kind of fact.
// A note says something about the fidelity of a result that was produced; a
// failure says a result was not produced, and a consumer has to be able to tell
// "this package has no dependencies" from "its lockfile could not be parsed"
// without reading prose.
type Failure struct {
	// Ecosystem is the enumerator that failed.
	Ecosystem Ecosystem `json:"ecosystem"`
	// Path is the file it could not read, empty when the failure is not about
	// one particular file.
	Path string `json:"path,omitempty"`
	// Detail is what went wrong.
	Detail string `json:"detail"`
}

// Enumeration is what reading a tree for component identities produced.
type Enumeration struct {
	// Components are the identities found.
	Components []Component
	// Failures are the manifests and lockfiles that could not be read.
	Failures []Failure
	// Notes describe anything a reader should know about the fidelity of the
	// result: a module list that is over-inclusive, dependencies excluded
	// because they do not ship.
	Notes []string
}

// Merge folds another enumeration into this one.
//
// It is exported because a caller combining source and installed enumeration
// has the same job the registries have: two reads of two trees, one closure.
func (e *Enumeration) Merge(other Enumeration) {
	e.Components = append(e.Components, other.Components...)
	e.Failures = append(e.Failures, other.Failures...)
	e.Notes = append(e.Notes, other.Notes...)
}

// sourceEnumerator reads component identities for one ecosystem out of a source
// tree.
type sourceEnumerator struct {
	ecosystem Ecosystem
	// enumerate returns what reading the tree produced.
	enumerate func(ctx context.Context, fsys fs.FS) Enumeration
}

// sourceEnumerators is the registry of source-tree enumerators, in a stable
// order so that enumeration output is reproducible.
var sourceEnumerators = []sourceEnumerator{
	{ecosystem: EcosystemGo, enumerate: enumerateGo},
	{ecosystem: EcosystemCargo, enumerate: enumerateCargo},
	{ecosystem: EcosystemNpm, enumerate: enumerateNpm},
}

// installedEnumerator reads component identities for one ecosystem out of the
// trees a build produced.
type installedEnumerator struct {
	ecosystem Ecosystem
	// enumerate returns what reading the build's output trees produced. own is
	// the name of the package being built, so an enumerator can recognize the
	// package's own project among what it installed.
	enumerate func(ctx context.Context, trees []Tree, own string) Enumeration
}

// installedEnumerators is the registry of installed-tree enumerators, in a
// stable order so that enumeration output is reproducible.
var installedEnumerators = []installedEnumerator{
	{ecosystem: EcosystemPyPI, enumerate: enumeratePython},
	{ecosystem: EcosystemMaven, enumerate: enumerateJava},
}

// SourceEcosystems lists the ecosystems that can be enumerated from a source
// tree, and InstalledEcosystems those that can be enumerated from a build's
// output. A caller measuring its own coverage needs to know which gaps are
// gaps in this module rather than in the package it scanned.
func SourceEcosystems() []Ecosystem {
	out := make([]Ecosystem, 0, len(sourceEnumerators))
	for _, e := range sourceEnumerators {
		out = append(out, e.ecosystem)
	}
	return out
}

// InstalledEcosystems lists the ecosystems that can be enumerated from a
// build's output trees.
func InstalledEcosystems() []Ecosystem {
	out := make([]Ecosystem, 0, len(installedEnumerators))
	for _, e := range installedEnumerators {
		out = append(out, e.ecosystem)
	}
	return out
}

// EnumerateSource collects the identities of every ecosystem component named by
// a manifest or lockfile in a source tree.
//
// The result is deliberately identity-only. Licensing is decided per component
// against its published content, not per package against whatever happened to
// be vendored into this build.
func EnumerateSource(ctx context.Context, fsys fs.FS) Enumeration {
	var out Enumeration
	for _, e := range sourceEnumerators {
		if err := ctx.Err(); err != nil {
			out.Failures = append(out.Failures, Failure{Ecosystem: e.ecosystem, Detail: err.Error()})
			break
		}
		out.Merge(e.enumerate(ctx, fsys))
	}
	return Finalize(out)
}

// EnumerateInstalled collects the identities of every ecosystem component that
// only exists once a build has run, from the trees it installed into.
//
// own is the name of the package being built. It is used to recognize the
// package's own project among what it installed, which is covered by the source
// component and must not be counted twice.
func EnumerateInstalled(ctx context.Context, trees []Tree, own string) Enumeration {
	if len(trees) == 0 {
		return Enumeration{}
	}
	var out Enumeration
	for _, e := range installedEnumerators {
		if err := ctx.Err(); err != nil {
			out.Failures = append(out.Failures, Failure{Ecosystem: e.ecosystem, Detail: err.Error()})
			break
		}
		out.Merge(e.enumerate(ctx, trees, own))
	}
	return Finalize(out)
}

// Finalize applies the rules every enumerated set has to satisfy: no unusable
// purls, a stable order, and one entry per identity.
//
// It is exported because a caller combining source and installed enumeration
// has to apply them again over the union: a component named by both a lockfile
// and the installed tree is still one component. The caller's slice is left as
// it was, so passing a union assembled from two enumerations does not reorder
// or truncate either of them.
func Finalize(e Enumeration) Enumeration {
	comps, dropped := dropMalformed(e.Components)
	if dropped > 0 {
		e.Notes = append(e.Notes, fmt.Sprintf("%d component identities dropped for containing control characters or spaces in their purl", dropped))
	}
	slices.SortFunc(comps, func(a, b Component) int {
		return cmp.Or(strings.Compare(a.PURL, b.PURL), strings.Compare(a.Digest, b.Digest))
	})
	e.Components = dedupe(comps)
	return e
}

// dropMalformed removes components whose purl is not a usable identifier,
// reporting how many went.
//
// A determination is keyed on the purl and kept forever, so a malformed one is
// not a cosmetic problem: it permanently occupies a row nothing will ever look
// up again. These arise from a parser reading a file that only looks like a
// manifest, which the location rules now prevent - this is the backstop for
// the next such file, in whatever shape it arrives.
func dropMalformed(comps []Component) ([]Component, int) {
	// A fresh slice rather than a filter in place: this runs under an exported
	// function whose callers pass slices they still hold, and reusing the
	// backing array would reorder and truncate theirs.
	out := make([]Component, 0, len(comps))
	dropped := 0
	for _, c := range comps {
		if usableIdentifier(c.PURL) {
			out = append(out, c)
			continue
		}
		dropped++
	}
	return out, dropped
}

// usableIdentifier reports whether s can serve as a component identity. Every
// ecosystem enumerated here names its components in printable, unspaced ASCII,
// so anything else came from misreading a file rather than from a real
// manifest.
func usableIdentifier(s string) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// dedupe collapses repeated identities. The same module can be listed by more
// than one manifest in a multi-module tree; it is still one component.
func dedupe(comps []Component) []Component {
	if len(comps) == 0 {
		return nil
	}
	type key struct{ purl, digest string }
	seen := make(map[key]struct{}, len(comps))
	out := make([]Component, 0, len(comps))
	for _, c := range comps {
		k := key{c.PURL, c.Digest}
		if _, repeated := seen[k]; repeated {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, c)
	}
	return out
}

// findShallowest returns the path of the shallowest file with the given name,
// ignoring locations that are not the component's own source.
//
// A manifest under vendor/ belongs to a dependency, and one under tests/ or
// examples/ belongs to a fixture corpus. Anchoring enumeration on either
// describes something the package does not actually build.
func findShallowest(fsys fs.FS, name string) (string, bool) {
	best := ""
	bestDepth := -1
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != name {
			return nil //nolint:nilerr // an unreadable subtree contributes nothing and is not fatal
		}
		if detect.ClassifyDirExclusion(path.Dir(p)) != detect.ExclusionNone {
			return nil
		}
		if depth := len(strings.Split(p, "/")); bestDepth == -1 || depth < bestDepth {
			bestDepth, best = depth, p
		}
		return nil
	})
	if bestDepth == -1 {
		return "", false
	}
	return best, true
}
