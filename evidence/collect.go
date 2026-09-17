/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package evidence

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"

	"chainguard.dev/license/assess"
	"chainguard.dev/license/component"
	"chainguard.dev/license/contenthash"
	"chainguard.dev/license/detect"
)

// Options adjust a collection.
type Options struct {
	// Classifier identifies the license texts. A nil Classifier uses the
	// shared default.
	Classifier detect.Classifier
}

// Collect gathers the evidence bundle for a subject.
//
// A subject that cannot be described at all, or a context that is already
// cancelled, returns an error. Everything else is recorded: a tree that could
// not be read becomes a gap, an unreadable license file carries its own error,
// and the collection continues. That is deliberate - the bundle is the record
// of what could be observed, and a collection that gave up on the first failure
// would leave a consumer with nothing to reason about.
func Collect(ctx context.Context, subject Subject, opts Options) (*Bundle, error) {
	if subject == nil {
		return nil, errors.New("evidence: no subject to collect")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	description := subject.Describe()
	b := &Bundle{
		SchemaVersion: SchemaVersion,
		Subject:       description,
		Files:         []detect.File{},
	}

	// The subject's own source is the first component. It is named even when
	// the source tree cannot be read: the identity comes from the description,
	// so a consumer can still record that this component was seen and that its
	// evidence could not be gathered.
	source := component.SourceComponent(description.Source)
	var ecosystem component.Enumeration

	var res *detect.Result
	sourceFS, err := subject.Source(ctx)
	if err != nil {
		b.Gaps = append(b.Gaps, Gap{Kind: GapSource, Detail: err.Error()})
	} else {
		var enumerated component.Enumeration
		if res, enumerated, err = collectSource(ctx, b, sourceFS, description, opts); err != nil {
			return nil, err
		}
		ecosystem.Merge(enumerated)
	}

	installed, err := subject.Installed(ctx)
	switch {
	case err != nil:
		b.Gaps = append(b.Gaps, Gap{Kind: GapInstalled, Detail: err.Error()})
	case len(installed) == 0:
		b.Gaps = append(b.Gaps, Gap{
			Kind:   GapNoInstalled,
			Detail: fmt.Sprintf("no installed tree supplied; %s components were not enumerated", strings.Join(component.InstalledEcosystems(), ", ")),
		})
	default:
		ecosystem.Merge(component.EnumerateInstalled(ctx, installed, description.Package))
	}

	// One pass over the union: a component named by both a lockfile and an
	// installed tree is still one component.
	ecosystem = component.Finalize(ecosystem)
	b.Notes = append(b.Notes, ecosystem.Notes...)
	for _, failure := range ecosystem.Failures {
		b.Gaps = append(b.Gaps, Gap{Kind: GapDependencies, Detail: dependencyGap(failure)})
	}
	components := ecosystem.Components

	for _, f := range b.Files {
		if f.Err != "" {
			b.Gaps = append(b.Gaps, Gap{Kind: GapLicenseFile, Detail: fmt.Sprintf("%s: %s", f.Path, f.Err)})
		}
	}

	// Which directories hold a vendored copy decides both what the components
	// inside them hash to and which license files are the subject's own, so it
	// is worked out once, now that every component is known.
	vendored := vendoredRoots(components, b.Files, b.VendorRoot)
	if hashed := hashVendored(components, b.Files, vendored); hashed > 0 {
		b.Notes = append(b.Notes, fmt.Sprintf("%d components have a vendored copy in the tree, hashed for verification against their published artifacts", hashed))
	}
	for _, purl := range slices.Sorted(maps.Keys(vendored)) {
		b.VendoredCopies = append(b.VendoredCopies, VendoredCopy{PURL: purl, Root: vendored[purl]})
	}

	source.LicenseContentHash = contenthash.Compute(ownFiles(b.Files, vendored))
	b.LicenseContentHash = source.LicenseContentHash
	// The subject's own source leads the list rather than being sorted in with
	// the rest, so a reader finds the thing being built at the top.
	b.Components = append([]component.Component{source}, components...)

	b.Conclusion = conclude(res, b)
	b.Assessment = assess.Assess(assess.Input{
		Files:      b.Files,
		Manifests:  b.Manifests,
		Prose:      b.Prose,
		Declared:   declaredExpression(description.Declared),
		Incomplete: gapDetails(b.Gaps),
	})
	return b, nil
}

// conclude resolves the subject's own license, and mints a LicenseRef for
// license text nothing recognized so that a proprietary license is recorded
// rather than dropped.
//
// A nil result means the source tree was never read, which is not the same as
// reading it and finding no license: the reason distinguishes them, and the
// bundle's gaps say why.
func conclude(res *detect.Result, b *Bundle) Conclusion {
	if res == nil {
		return Conclusion{Reason: detect.ReasonNoLicenseText}
	}
	c := res.Conclude(detect.GrantEvidence{Grants: b.Grants, Sampled: b.NoticesSampled})
	out := Conclusion{
		Expression:  c.Expression,
		Reason:      c.Reason,
		Identifiers: c.Identifiers,
		GrantBasis:  c.GrantBasis,
	}
	if len(c.Unrecognized) > 0 {
		out.LicenseRef = contenthash.LicenseRef([]byte(c.Unrecognized[0].Text))
	}
	return out
}

// collectSource reads everything the source tree can say about the subject's
// own licensing, and returns the ecosystem components its manifests name.
func collectSource(ctx context.Context, b *Bundle, fsys fs.FS, description Description, opts Options) (*detect.Result, component.Enumeration, error) {
	// A deep scan, vendored subdirectories included: a vendored license belongs
	// to the component that vendored it, and the bundle has to carry it in
	// order to say so.
	res, err := detect.Detect(ctx, detect.Request{
		FS:         fsys,
		Scope:      detect.ScopeTree,
		Declared:   description.Declared,
		RetainText: true,
		Classifier: opts.Classifier,
	})
	if err != nil {
		return nil, component.Enumeration{}, fmt.Errorf("detecting licenses: %w", err)
	}
	b.Files = res.Files
	b.Notes = append(b.Notes, res.Notes...)
	for _, path := range res.Unreadable {
		b.Gaps = append(b.Gaps, Gap{Kind: GapUnreadableTree, Detail: path + ": could not be read"})
	}

	b.Manifests = component.Manifests(fsys)
	b.Prose = detect.Prose(fsys)
	b.Notices, b.NoticesSampled = detect.Notices(fsys)

	classifier := opts.Classifier
	if classifier == nil {
		// The same classifier that read the license files reads the notices,
		// and it is the shared one, so a sweep parses the corpus once rather
		// than once per component. Failing to build it is not fatal: the
		// SPDX-tag half of the reading needs no classifier at all.
		if shared, err := detect.DefaultClassifier(); err == nil {
			classifier = shared
		}
	}
	b.Grants = detect.Grants(classifier, b.Notices)

	if root, ok := component.VendorRoot(fsys); ok {
		b.VendorRoot = root
	}
	return res, component.EnumerateSource(ctx, fsys), nil
}

// dependencyGap renders an enumeration failure as a gap detail.
func dependencyGap(failure component.Failure) string {
	if failure.Path == "" {
		return fmt.Sprintf("%s: %s", failure.Ecosystem, failure.Detail)
	}
	return fmt.Sprintf("%s: %s: %s", failure.Ecosystem, failure.Path, failure.Detail)
}

// ownFiles selects the license files belonging to the subject itself, leaving
// out the ones that belong to a component inside it.
//
// Without this, a package that vendors its dependencies would hash its
// dependencies' licenses into its own key, and every dependency bump would look
// like a change to the package's own licensing.
//
// Ownership is decided two ways, because one is not enough. A component this
// module enumerated contributes the directory its copy lives in, which is
// exact. Everything else falls back to the trees that hold another component's
// code by construction - a vendor directory, node_modules, a build's install
// root - because a license file under one of those belongs to whatever was
// vendored or installed there whether or not this module can name it, and
// ecosystems it cannot enumerate are exactly the ones with no exact root to
// contribute. That is nested-component ownership by a coarser instrument, not
// discovery's cost heuristic: depth and filename rules still do not apply here.
func ownFiles(files []detect.File, vendored map[string]string) []contenthash.File {
	nested := slices.Sorted(maps.Values(vendored))
	out := make([]contenthash.File, 0, len(files))
	for _, f := range files {
		if !contenthash.Covers(f.Path) || f.Digest == "" {
			continue
		}
		if belongsToAnother(f) || ownedByAny(f.Path, nested) {
			continue
		}
		out = append(out, contenthash.File{Path: f.Path, Digest: f.Digest})
	}
	return out
}

// belongsToAnother reports whether a discovered file describes a component
// inside the subject rather than the subject itself.
func belongsToAnother(f detect.File) bool {
	switch f.Excluded {
	case detect.ExclusionVendored, detect.ExclusionBuildOutput:
		return true
	case detect.ExclusionTestFixture:
		// A fixture's license describes the fixture. Those texts are often
		// deliberately exotic, and hashing one in would make editing an
		// unrelated fixture re-key the subject and force it to be audited
		// again. Covers matches on the filename, so testdata/x/LICENSE reaches
		// here with no vendored root to be owned by.
		return true
	default:
		return false
	}
}

// hashVendored fills in the license-content hash of every component with a copy
// vendored into the tree, and reports how many were hashed.
//
// A component with no local copy keeps an empty hash. That is not a gap: most
// components are named by a lockfile and never appear in the tree, and there is
// nothing local to verify for them.
func hashVendored(comps []component.Component, files []detect.File, roots map[string]string) int {
	if len(roots) == 0 {
		return 0
	}
	all := slices.Sorted(maps.Values(roots))
	records := contenthash.From(files)

	hashed := 0
	for i := range comps {
		root, ok := roots[comps[i].PURL]
		if !ok {
			continue
		}
		comps[i].LicenseContentHash = contenthash.Compute(
			contenthash.Relative(records, root, contenthash.NestedRoots(root, all)))
		hashed++
	}
	return hashed
}

// vendoredRoots maps each component with a copy vendored under the tree's
// vendor root to the directory that copy lives in, keyed by purl.
//
// A component is included only when license files were actually found under its
// directory: a module listed in a lockfile but absent from the tree has no
// local copy to verify, and inventing a root for it would hash an empty set and
// then claim that as evidence.
//
// A local hash is only meaningful where the in-tree copy and the published
// artifact use the same path layout, so that the two can hash alike at all. A
// Go vendor tree does, which is what this reads; a jar and a crate do too, and
// have no in-tree form this collects from yet.
//
// Python is excluded deliberately. pip restructures a distribution on install,
// so a source archive's root LICENSE becomes dist-info/licenses/LICENSE, an
// installed tree shares no path with the artifact it came from, and the two can
// never hash alike. Nothing is lost:
// that tree was installed by our own build from the very registry it would be
// compared against, so it carries no independent claim to verify.
func vendoredRoots(comps []component.Component, files []detect.File, vendorRoot string) map[string]string {
	if vendorRoot == "" {
		return nil
	}
	roots := make(map[string]string, len(comps))
	for _, c := range comps {
		if c.Kind != component.KindEcosystem || c.Name == "" {
			continue
		}
		root := strings.TrimSuffix(vendorRoot, "/") + "/" + c.Name
		for _, f := range files {
			if strings.HasPrefix(f.Path, root+"/") && contenthash.Covers(f.Path) {
				roots[c.PURL] = root
				break
			}
		}
	}
	return roots
}

// ownedByAny reports whether a path lies inside one of the given roots.
func ownedByAny(p string, roots []string) bool {
	for _, root := range roots {
		if strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/") {
			return true
		}
	}
	return false
}

// declaredExpression joins what the build configuration declares into one
// expression, so it can be compared against what was detected.
//
// Several declarations compose with AND: a package declaring MIT for one path
// and BSD-3-Clause for another is subject to both, which is what a consumer of
// the whole package is exposed to.
func declaredExpression(declared []detect.Declaration) string {
	seen := map[string]struct{}{}
	var parts []string
	for _, d := range declared {
		expr := strings.TrimSpace(d.License)
		if expr == "" {
			continue
		}
		if _, repeated := seen[expr]; repeated {
			continue
		}
		seen[expr] = struct{}{}
		parts = append(parts, expr)
	}
	return strings.Join(parts, " AND ")
}

// gapDetails renders the gaps as the reasons assess reads, so that a bundle
// with no readable evidence scores unknown rather than zero.
func gapDetails(gaps []Gap) []string {
	var out []string
	for _, g := range gaps {
		if g.Kind == GapNoInstalled {
			// Not a failure to read anything: it says which ecosystems were out
			// of reach, which is a coverage statement rather than a gap in this
			// component's own evidence.
			continue
		}
		out = append(out, g.Detail)
	}
	return out
}
