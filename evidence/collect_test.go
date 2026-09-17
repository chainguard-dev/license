/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package evidence

import (
	"errors"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"chainguard.dev/license/component"
	"chainguard.dev/license/detect"
)

const (
	mitText    = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n"
	eulaText   = "End User License Agreement\n\nThis software is licensed, not sold. You may not redistribute it.\n"
	goSumEntry = "github.com/google/uuid v1.6.0 h1:NIvaJDMOsjJZ2wPCH3sHXTKbA==\ngithub.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=\n"
)

// tree builds an in-memory filesystem from a map of path to contents.
func tree(files map[string]string) fstest.MapFS {
	fsys := make(fstest.MapFS, len(files))
	for p, content := range files {
		fsys[p] = &fstest.MapFile{Data: []byte(content)}
	}
	return fsys
}

// subject returns a Trees subject over a source tree, with coordinates a real
// build would supply.
func subject(source fs.FS, installed ...component.Tree) *Trees {
	return &Trees{
		Description: Description{
			Package: "example",
			Version: "1.2.3",
			Source: component.Source{
				Name:       "example",
				Version:    "1.2.3",
				Repository: "https://github.com/example/project",
				Commit:     "0123456789abcdef0123456789abcdef01234567",
			},
			Origin: "example.yaml",
		},
		SourceFS:    source,
		InstalledFS: installed,
	}
}

func TestCollect(t *testing.T) {
	fsys := tree(map[string]string{
		"LICENSE":                     mitText,
		"README.md":                   "Licensed under the MIT license.\n",
		"package.json":                `{"name":"example","license":"MIT"}`,
		"main.go":                     "// SPDX-License-Identifier: MIT\npackage main\n",
		"go.mod":                      "module github.com/example/project\n",
		"go.sum":                      goSumEntry,
		"vendor/github.com/x/LICENSE": mitText,
	})

	b, err := Collect(t.Context(), subject(fsys), Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if b.SchemaVersion != SchemaVersion {
		t.Errorf("schema version: got = %d, want = %d", b.SchemaVersion, SchemaVersion)
	}
	if b.Conclusion.Expression != "MIT" {
		t.Errorf("conclusion: got = %+v, want MIT", b.Conclusion)
	}
	if b.LicenseContentHash == "" {
		t.Error("license-content hash is empty, so nothing could key a determination on this bundle")
	}
	if b.Assessment.Unknown || b.Assessment.Score == 0 {
		t.Errorf("assessment: got = %+v, want a real score", b.Assessment)
	}

	// The subject's own source is the first component, so a reader finds the
	// thing being built at the top of the list rather than in purl order.
	if len(b.Components) == 0 || b.Components[0].Kind != component.KindPackageSource {
		t.Fatalf("components: got = %+v, want the source component first", b.Components)
	}
	if b.Components[0].LicenseContentHash != b.LicenseContentHash {
		t.Errorf("the source component carries %q, want the bundle's %q",
			b.Components[0].LicenseContentHash, b.LicenseContentHash)
	}
	if !slices.ContainsFunc(b.Components, func(c component.Component) bool {
		return c.PURL == "pkg:golang/github.com/google/uuid@v1.6.0"
	}) {
		t.Errorf("components: got = %+v, want the Go module the lockfile names", b.Components)
	}

	// The vendored license is retained, and marked as belonging to something
	// else rather than dropped.
	var vendored bool
	for _, f := range b.Files {
		if f.Path == "vendor/github.com/x/LICENSE" {
			vendored = f.Excluded == detect.ExclusionVendored && f.Text != ""
		}
	}
	if !vendored {
		t.Errorf("files: got = %+v, want the vendored license retained and marked", b.Files)
	}

	if len(b.Manifests) == 0 || b.Manifests[0].License != "MIT" {
		t.Errorf("manifests: got = %+v, want the declared MIT", b.Manifests)
	}
	if len(b.Prose) == 0 {
		t.Error("prose: got none, want the README license mention")
	}
	if b.NoticesSampled == 0 {
		t.Error("notices: got none sampled, so a version grant could never be established")
	}
	if b.VendorRoot != "vendor" {
		t.Errorf("vendor root: got = %q, want = %q", b.VendorRoot, "vendor")
	}
}

// TestCollectHashExcludesVendoredLicenses keeps a dependency's licensing out of
// the subject's own key. Without this, every dependency bump would look like a
// change to the package's own licensing and re-audit it.
func TestCollectHashExcludesVendoredLicenses(t *testing.T) {
	base := map[string]string{
		"LICENSE": mitText,
		"go.mod":  "module github.com/example/project\n",
		"go.sum":  goSumEntry,
		"vendor/modules.txt": "# github.com/google/uuid v1.6.0\n" +
			"## explicit\ngithub.com/google/uuid\n",
		"vendor/github.com/google/uuid/LICENSE": mitText,
	}
	withDependency := withFiles(base, map[string]string{
		"vendor/github.com/google/uuid/LICENSE": eulaText,
	})

	first, err := Collect(t.Context(), subject(tree(base)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Collect(t.Context(), subject(tree(withDependency)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if first.LicenseContentHash != second.LicenseContentHash {
		t.Errorf("a vendored dependency's license changed the subject's own hash:\n  %s\n  %s",
			first.LicenseContentHash, second.LicenseContentHash)
	}

	// The vendored component is hashed on its own terms, so a consumer can
	// check it against the artifact it claims to be.
	var hashes []string
	for _, c := range second.Components {
		if c.PURL == "pkg:golang/github.com/google/uuid@v1.6.0" {
			hashes = append(hashes, c.LicenseContentHash)
		}
	}
	if len(hashes) != 1 || hashes[0] == "" {
		t.Errorf("vendored component hashes: got = %v, want one non-empty hash", hashes)
	}
}

// TestCollectMintsALicenseRef verifies that a license nothing recognizes is
// recorded rather than dropped, which is the difference between a proprietary
// component and one with no license at all.
func TestCollectMintsALicenseRef(t *testing.T) {
	b, err := Collect(t.Context(), subject(tree(map[string]string{"LICENSE": eulaText})), Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if b.Conclusion.Reason != detect.ReasonUnrecognized {
		t.Errorf("reason: got = %q, want = %q", b.Conclusion.Reason, detect.ReasonUnrecognized)
	}
	if !strings.HasPrefix(b.Conclusion.LicenseRef, "LicenseRef-") {
		t.Errorf("license ref: got = %q, want a minted name", b.Conclusion.LicenseRef)
	}
	if b.Conclusion.Expression != "" {
		t.Errorf("expression: got = %q, want none for text nothing recognized", b.Conclusion.Expression)
	}
}

// TestCollectRecordsAMissingSource covers the property the whole bundle format
// rests on: an incomplete bundle has to stay distinguishable from a clean one,
// because "no license found" means opposite things in the two.
func TestCollectRecordsAMissingSource(t *testing.T) {
	b, err := Collect(t.Context(), &Trees{Description: subject(nil).Description}, Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if b.Complete() {
		t.Error("a bundle with no source tree reports itself complete")
	}
	if !slices.ContainsFunc(b.Gaps, func(g Gap) bool { return g.Kind == GapSource }) {
		t.Errorf("gaps: got = %+v, want a source gap", b.Gaps)
	}
	// Unknown rather than a low score: nothing was read, which is not the same
	// as reading something inconclusive.
	if !b.Assessment.Unknown {
		t.Errorf("assessment: got = %+v, want unknown", b.Assessment)
	}
	// The component is still named, so a consumer can record that it was seen
	// and that its evidence could not be gathered.
	if len(b.Components) != 1 || b.Components[0].Kind != component.KindPackageSource {
		t.Errorf("components: got = %+v, want the source component named anyway", b.Components)
	}
}

// TestCollectRecordsMissingInstalledTrees keeps a coverage gap visible: the
// ecosystems named only by a build's output were not covered, and a consumer
// measuring coverage has to be able to see that rather than reading it as
// "this package has no Python dependencies".
func TestCollectRecordsMissingInstalledTrees(t *testing.T) {
	b, err := Collect(t.Context(), subject(tree(map[string]string{"LICENSE": mitText})), Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !slices.ContainsFunc(b.Gaps, func(g Gap) bool { return g.Kind == GapNoInstalled }) {
		t.Errorf("gaps: got = %+v, want a no-installed-trees gap", b.Gaps)
	}
	// It is a coverage statement, not a failure to read this component's own
	// evidence, so it must not make the assessment unknown.
	if b.Assessment.Unknown {
		t.Errorf("assessment: got = %+v, want a real score despite the coverage gap", b.Assessment)
	}
}

func TestCollectEnumeratesInstalledTrees(t *testing.T) {
	installed := component.Tree{
		Name: "melange-out/example",
		FS: tree(map[string]string{
			"usr/lib/python3.13/site-packages/requests-2.32.3.dist-info/METADATA": "Name: requests\nVersion: 2.32.3\nLicense-Expression: Apache-2.0\n\nbody\n",
		}),
	}
	b, err := Collect(t.Context(), subject(tree(map[string]string{"LICENSE": mitText}), installed), Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !slices.ContainsFunc(b.Components, func(c component.Component) bool {
		return c.PURL == "pkg:pypi/requests@2.32.3"
	}) {
		t.Errorf("components: got = %+v, want the installed distribution", b.Components)
	}
	if slices.ContainsFunc(b.Gaps, func(g Gap) bool { return g.Kind == GapNoInstalled }) {
		t.Errorf("gaps: got = %+v, want no missing-tree gap when a tree was supplied", b.Gaps)
	}
}

// TestCollectRecordsAnUnreadableLicenseFile verifies a per-file failure lands
// in the gaps while the rest of the bundle stands.
func TestCollectRecordsAnUnreadableLicenseFile(t *testing.T) {
	fsys := tree(map[string]string{"LICENSE": mitText})
	b, err := Collect(t.Context(), subject(brokenFile{fsys, "COPYING"}), Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !slices.ContainsFunc(b.Gaps, func(g Gap) bool { return g.Kind == GapLicenseFile }) {
		t.Errorf("gaps: got = %+v, want a license-file gap", b.Gaps)
	}
	if b.Conclusion.Expression != "MIT" {
		t.Errorf("conclusion: got = %+v, want the readable license still concluded", b.Conclusion)
	}
}

func TestCollectRejectsNoSubject(t *testing.T) {
	if _, err := Collect(t.Context(), nil, Options{}); err == nil {
		t.Error("Collect with no subject: got nil error, want one")
	}
}

// withFiles merges overrides into a copy of base.
func withFiles(base, overrides map[string]string) map[string]string {
	out := make(map[string]string, len(base))
	maps.Copy(out, base)
	maps.Copy(out, overrides)
	return out
}

// brokenFile adds one license file that fails to open, which is how a per-file
// failure is exercised without a filesystem that has to be broken on disk.
type brokenFile struct {
	fstest.MapFS
	name string
}

func (b brokenFile) Open(name string) (fs.File, error) {
	if name == b.name {
		return nil, errors.New("permission denied")
	}
	return b.MapFS.Open(name)
}

func (b brokenFile) Stat(name string) (fs.FileInfo, error) {
	if name == b.name {
		return nil, errors.New("permission denied")
	}
	return fs.Stat(b.MapFS, name)
}

func (b brokenFile) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := b.MapFS.ReadDir(name)
	if err != nil || name != "." {
		return entries, err
	}
	return append(entries, brokenEntry{name: b.name}), nil
}

// brokenEntry is the directory entry for the file that cannot be read.
type brokenEntry struct{ name string }

func (e brokenEntry) Name() string               { return e.name }
func (e brokenEntry) IsDir() bool                { return false }
func (e brokenEntry) Type() fs.FileMode          { return 0 }
func (e brokenEntry) Info() (fs.FileInfo, error) { return nil, errors.New("permission denied") }

// TestCollectHashExcludesEveryNestedComponent is the general case of the Go
// vendor test above: a license file inside anything the subject vendored or
// installed belongs to that component, whether or not this module can enumerate
// the ecosystem it came from.
//
// Without it, a package with a node_modules tree would hash its dependencies'
// licenses into its own key, and every dependency bump would re-audit the
// package itself.
func TestCollectHashExcludesEveryNestedComponent(t *testing.T) {
	own := map[string]string{"LICENSE": mitText}

	for _, tt := range []struct {
		name  string
		files map[string]string
	}{
		{
			name:  "an npm dependency tree",
			files: map[string]string{"node_modules/left-pad/LICENSE": eulaText},
		},
		{
			name:  "a bundled third-party tree",
			files: map[string]string{"third_party/zlib/LICENSE": eulaText},
		},
		{
			name:  "a build's install root",
			files: map[string]string{"melange-out/example/usr/share/licenses/LICENSE": eulaText},
		},
		{
			name:  "a virtualenv",
			files: map[string]string{"venv/lib/python3.13/site-packages/x/LICENSE": eulaText},
		},
		{
			// A fixture's license describes the fixture, and those texts are
			// often deliberately exotic. Covers matches on the filename, so
			// this reaches the hash with no vendored root to be owned by:
			// editing an unrelated fixture would otherwise re-key the subject.
			name:  "a test fixture",
			files: map[string]string{"testdata/weird/LICENSE": eulaText},
		},
		{
			name:  "an examples tree",
			files: map[string]string{"examples/demo/LICENSE": eulaText},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			alone, err := Collect(t.Context(), subject(tree(own)), Options{})
			if err != nil {
				t.Fatal(err)
			}
			nested, err := Collect(t.Context(), subject(tree(withFiles(own, tt.files))), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if alone.LicenseContentHash != nested.LicenseContentHash {
				t.Errorf("a nested component's license changed the subject's own hash:\n  %s\n  %s",
					alone.LicenseContentHash, nested.LicenseContentHash)
			}
		})
	}
}

// TestCollectRecordsAnUnreadableLockfile covers the gap that separates a
// package with no dependencies from one whose lockfile could not be parsed.
func TestCollectRecordsAnUnreadableLockfile(t *testing.T) {
	b, err := Collect(t.Context(), subject(tree(map[string]string{
		"LICENSE":    mitText,
		"Cargo.lock": "[[package]\nnot toml at all",
	})), Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if !slices.ContainsFunc(b.Gaps, func(g Gap) bool { return g.Kind == GapDependencies }) {
		t.Errorf("gaps: got = %+v, want a dependencies gap", b.Gaps)
	}
	if b.Complete() {
		t.Error("a bundle whose lockfile could not be parsed reports itself complete")
	}
	// The licensing evidence that was readable still stands.
	if b.Conclusion.Expression != "MIT" {
		t.Errorf("conclusion: got = %+v, want the license still concluded", b.Conclusion)
	}
}

// TestCollectGivesNoLocalHashToAnInstalledDistribution pins the design's Python
// exclusion. pip moves a source archive's LICENSE into dist-info on install, so
// an installed tree shares no path layout with the artifact it came from and the
// two can never hash alike. There is nothing to lose by it: that tree was
// installed from the very registry it would be compared against.
func TestCollectGivesNoLocalHashToAnInstalledDistribution(t *testing.T) {
	installed := component.Tree{
		Name: "melange-out/example",
		FS: tree(map[string]string{
			"site-packages/requests-2.32.3.dist-info/METADATA":         "Name: requests\nVersion: 2.32.3\n\nbody\n",
			"site-packages/requests-2.32.3.dist-info/licenses/LICENSE": mitText,
		}),
	}

	b, err := Collect(t.Context(), subject(tree(map[string]string{"LICENSE": mitText}), installed), Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, c := range b.Components {
		if c.Ecosystem == component.EcosystemPyPI && c.LicenseContentHash != "" {
			t.Errorf("%s carries a local hash %q, want none: an installed tree shares no layout with its artifact",
				c.PURL, c.LicenseContentHash)
		}
	}
}

// TestCollectRecordsVendoredCopies covers what a consumer needs in order to
// verify a local copy from the bundle alone: which component each copy belongs
// to, and which of the bundle's license files are that copy's.
func TestCollectRecordsVendoredCopies(t *testing.T) {
	b, err := Collect(t.Context(), subject(tree(map[string]string{
		"LICENSE": mitText,
		"go.mod":  "module github.com/example/project\n",
		"go.sum":  goSumEntry,
		"vendor/modules.txt": "# github.com/google/uuid v1.6.0\n" +
			"## explicit\ngithub.com/google/uuid\n",
		"vendor/github.com/google/uuid/LICENSE": mitText,
	})), Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	const purl = "pkg:golang/github.com/google/uuid@v1.6.0"
	var root string
	for _, copied := range b.VendoredCopies {
		if copied.PURL == purl {
			root = copied.Root
		}
	}
	if root != "vendor/github.com/google/uuid" {
		t.Fatalf("vendored copies: got = %+v, want the module's directory", b.VendoredCopies)
	}

	// The local side of the subset test: paths relative to the copy, so they
	// compare against an artifact rooted at the component itself.
	local := b.LocalLicenseFiles(purl)
	if len(local) != 1 || local[0].Path != "LICENSE" {
		t.Errorf("local license files: got = %+v, want the copy's own LICENSE at its root", local)
	}

	// A component with no copy in the tree gets nothing, rather than a wrong
	// answer: an empty local set is trivially a subset.
	if got := b.LocalLicenseFiles("pkg:golang/example.com/absent@v1.0.0"); got != nil {
		t.Errorf("local license files for a component with no copy: got = %+v, want none", got)
	}
}
