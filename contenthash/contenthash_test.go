/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package contenthash

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
)

// tree builds an in-memory filesystem from a map of path to contents.
func tree(files map[string]string) fstest.MapFS {
	fsys := make(fstest.MapFS, len(files))
	for p, content := range files {
		fsys[p] = &fstest.MapFile{Data: []byte(content)}
	}
	return fsys
}

// TestComputeIsOrderIndependent pins the property the whole scheme rests on:
// the key identifies a set of license files, so the order the caller found them
// in cannot change it. If it could, two producers scanning the same component
// would store two determinations for it.
func TestComputeIsOrderIndependent(t *testing.T) {
	files := []File{
		{Path: "LICENSE", Digest: "sha256:aaa"},
		{Path: "COPYING", Digest: "sha256:bbb"},
		{Path: "docs/LICENSE-MIT", Digest: "sha256:ccc"},
	}
	reversed := slices.Clone(files)
	slices.Reverse(reversed)

	if Compute(files) != Compute(reversed) {
		t.Errorf("reordering the inputs changed the hash:\n%s\n%s", Compute(files), Compute(reversed))
	}
}

// TestComputeCoversPathAndContent covers the other half: a license file moving
// between directories, or a second one appearing beside the first, changes a
// component's licensing evidence as surely as an edit does.
func TestComputeCoversPathAndContent(t *testing.T) {
	base := []File{{Path: "LICENSE", Digest: "sha256:aaa"}}
	for _, tt := range []struct {
		name  string
		files []File
	}{
		{name: "changed content", files: []File{{Path: "LICENSE", Digest: "sha256:zzz"}}},
		{name: "moved file", files: []File{{Path: "docs/LICENSE", Digest: "sha256:aaa"}}},
		{name: "extra file", files: append(slices.Clone(base), File{Path: "COPYING", Digest: "sha256:bbb"})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if Compute(tt.files) == Compute(base) {
				t.Errorf("%s produced the same hash as the original", tt.name)
			}
		})
	}
}

// TestComputeFramingSeparatesRecords verifies that the framing does its job: a
// path and digest concatenation must not be readable as a different set of
// files. Without length prefixes, ("AB", "c") and ("A", "Bc") would hash alike.
func TestComputeFramingSeparatesRecords(t *testing.T) {
	a := []File{{Path: "AB", Digest: "c"}}
	b := []File{{Path: "A", Digest: "Bc"}}
	if Compute(a) == Compute(b) {
		t.Error("two different record sequences hashed alike; the framing is not separating them")
	}
}

// TestComputeCarriesTheScheme keeps the version in the key. A stored key has to
// state the rules it was computed under, or a change to those rules silently
// re-keys data instead of reading as a miss.
func TestComputeCarriesTheScheme(t *testing.T) {
	got := Compute([]File{{Path: "LICENSE", Digest: "sha256:aaa"}})
	if !strings.HasPrefix(got, Scheme+"-") {
		t.Errorf("hash %q does not carry the %q scheme prefix", got, Scheme)
	}
}

// TestComputeEmpty pins what a component with no license files hashes to. It is
// a real key rather than an empty string: "we looked and found none" is an
// observation about content, and two such components share the answer.
func TestComputeEmpty(t *testing.T) {
	if got, want := Compute(nil), Compute([]File{}); got != want {
		t.Errorf("nil and empty inputs hash differently: %q vs %q", got, want)
	}
	if got := Compute(nil); !strings.HasPrefix(got, Scheme+"-") {
		t.Errorf("hash of no files = %q, want a scheme-prefixed digest", got)
	}
}

// TestFilesNormalizesLineEndings covers the normalization the scheme promises:
// the same license text carries the same terms however it was checked out, so a
// CRLF checkout of a vendored dependency must not read as a different license
// from a LF one.
func TestFilesNormalizesLineEndings(t *testing.T) {
	unix, err := ComputeFS(tree(map[string]string{"LICENSE": "MIT License\n\nPermission is granted.\n"}))
	if err != nil {
		t.Fatal(err)
	}
	windows, err := ComputeFS(tree(map[string]string{"LICENSE": "MIT License\r\n\r\nPermission is granted.\r\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if unix != windows {
		t.Errorf("line endings changed the hash:\n  LF:   %s\n  CRLF: %s", unix, windows)
	}
}

// TestComputeFSSelectsLicenseFilesOnly verifies that manifests and prose stay
// out of the hash. Vendoring does not preserve them, so hashing them would
// manufacture divergence between a copy and the artifact it came from.
func TestComputeFSSelectsLicenseFilesOnly(t *testing.T) {
	withOnlyLicense, err := ComputeFS(tree(map[string]string{"LICENSE": "MIT"}))
	if err != nil {
		t.Fatal(err)
	}
	withExtras, err := ComputeFS(tree(map[string]string{
		"LICENSE":      "MIT",
		"README.md":    "a readme mentioning the license",
		"package.json": `{"license":"MIT"}`,
		"main.go":      "package main",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if withOnlyLicense != withExtras {
		t.Errorf("non-license files changed the hash:\n  %s\n  %s", withOnlyLicense, withExtras)
	}
}

// TestComputeFSHasNoDepthLimit covers the difference from discovery: a depth
// cap here would make two copies differing only in a subdirectory's license
// hash alike, and one determination would answer for both.
func TestComputeFSHasNoDepthLimit(t *testing.T) {
	shallow, err := ComputeFS(tree(map[string]string{"LICENSE": "MIT"}))
	if err != nil {
		t.Fatal(err)
	}
	deep, err := ComputeFS(tree(map[string]string{
		"LICENSE":                 "MIT",
		"a/b/c/d/e/LICENSE-EXTRA": "GPL-3.0",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if shallow == deep {
		t.Error("a license file five directories down did not change the hash")
	}
}

func TestRelativeExcludesNestedComponents(t *testing.T) {
	files := []File{
		{Path: "vendor/github.com/containerd/errdefs/LICENSE", Digest: "sha256:parent"},
		{Path: "vendor/github.com/containerd/errdefs/pkg/LICENSE", Digest: "sha256:nested"},
		{Path: "vendor/github.com/other/LICENSE", Digest: "sha256:other"},
	}
	roots := []string{
		"vendor/github.com/containerd/errdefs",
		"vendor/github.com/containerd/errdefs/pkg",
		"vendor/github.com/other",
	}

	// The parent's published zip excludes its own submodule, so attributing the
	// submodule's LICENSE to the parent reports a divergence that is not there.
	parent := Relative(files, roots[0], NestedRoots(roots[0], roots))
	want := []File{{Path: "LICENSE", Digest: "sha256:parent"}}
	if diff := cmp.Diff(want, parent); diff != "" {
		t.Errorf("Relative for the parent (-want, +got):\n%s", diff)
	}

	nested := Relative(files, roots[1], NestedRoots(roots[1], roots))
	wantNested := []File{{Path: "LICENSE", Digest: "sha256:nested"}}
	if diff := cmp.Diff(wantNested, nested); diff != "" {
		t.Errorf("Relative for the nested component (-want, +got):\n%s", diff)
	}
}

func TestNestedRoots(t *testing.T) {
	all := []string{"vendor/a", "vendor/a/b", "vendor/a/b/c", "vendor/other"}
	if diff := cmp.Diff([]string{"vendor/a/b", "vendor/a/b/c"}, NestedRoots("vendor/a", all)); diff != "" {
		t.Errorf("NestedRoots (-want, +got):\n%s", diff)
	}
	if got := NestedRoots("vendor/other", all); got != nil {
		t.Errorf("NestedRoots for a leaf: got = %v, want none", got)
	}
}

// TestComputeGoldenVector freezes the license-content hash.
//
// Every other test here is relative - this input hashes like that one - and
// relative tests stay green through a change to the framing, the record order
// or the normalization, all of which silently re-key every determination
// already stored. This vector is what makes such a change fail: if it fails,
// the scheme changed and the constant has to be bumped and the data migrated,
// which is the whole reason the key carries a version.
func TestComputeGoldenVector(t *testing.T) {
	files := []File{
		{Path: "LICENSE", Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000001"},
		{Path: "s2/LICENSE", Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000002"},
	}
	const want = "v1-ac1d9c5e70b9e4a0796e05717668298f85df7cfa407f5c0e927a4c42f3ca6352"
	if got := Compute(files); got != want {
		t.Errorf("Compute: got = %q, want = %q\nthe hash scheme changed; bump %s and migrate", got, want, "Scheme")
	}

	// A component with no license files is a real key rather than an empty
	// string, so two such components share one answer.
	const wantEmpty = "v1-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := Compute(nil); got != wantEmpty {
		t.Errorf("Compute(nil): got = %q, want = %q", got, wantEmpty)
	}
}

// TestComputeFSGoldenVector freezes the hash end to end, over a filesystem
// rather than over records the test computed itself, so the file selection and
// the content normalization are covered by the vector too.
func TestComputeFSGoldenVector(t *testing.T) {
	got, err := ComputeFS(tree(map[string]string{
		"LICENSE":      "MIT License\n",
		"s2/LICENSE":   "BSD 2-Clause\r\n",
		"package.json": `{"license":"MIT"}`,
		"main.go":      "package main",
	}))
	if err != nil {
		t.Fatal(err)
	}
	const want = "v1-f13fe7b0c0b390947d172da656682d74c17e52cc90ae0425c24d0a38857efde1"
	if got != want {
		t.Errorf("ComputeFS: got = %q, want = %q\nthe selection, the framing or the normalization changed", got, want)
	}
}

// TestLicenseRefGoldenVector freezes the other durable key, for the same
// reason: a consumer that curated a name for a ref can no longer find it if
// the derivation moves.
func TestLicenseRefGoldenVector(t *testing.T) {
	const want = "LicenseRef-v1-8bae776427bb3b18"
	if got := LicenseRef([]byte("End User License Agreement\n")); got != want {
		t.Errorf("LicenseRef: got = %q, want = %q\nthe ref scheme changed; bump %s and re-curate", got, want, "RefScheme")
	}
}
