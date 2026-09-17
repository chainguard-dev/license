/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
)

// tree builds an in-memory filesystem from a map of path to contents.
func tree(files map[string][]byte) fstest.MapFS {
	fsys := make(fstest.MapFS, len(files))
	for name, data := range files {
		fsys[name] = &fstest.MapFile{Data: data}
	}
	return fsys
}

func TestIsLicenseFile(t *testing.T) {
	for _, tt := range []struct {
		name string
		want bool
	}{
		{"LICENSE", true},
		{"LICENCE", true},
		{"UNLICENSE", true},
		{"LICENSE.md", true},
		{"COPYING.txt", true},
		{"COPYRIGHT", true},
		{"LICENSE-APACHE", true},
		{"MIT-COPYING", true},
		{"OFL", true},
		{"PATENTS.txt", true},
		{"README.md", false},
		{"copyme", false},
		{"COPY", false},
		// A license-named source file holds code, and a license-named metadata
		// file holds metadata. Neither is license text.
		{"license.go", false},
		{"LICENSE.gemspec", false},
		{"LICENSE.spdx", false},
		// The test is on the name alone. Where a file sits is ClassifyExclusion's
		// question, and the license-content hash needs the two separable.
		{"src/LICENSE", true},
		{"vendor/LICENSE", true},
		{"node_modules/foo/LICENSE", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := IsLicenseFile(tt.name); got != tt.want {
				t.Errorf("IsLicenseFile(%q): got = %v, want = %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestIsLicenseFileWeightIsHighestMatch pins the tie-break, because several
// patterns match a name like LICENSE.md and a weight that depended on map
// iteration order would make discovery order differ between runs.
func TestIsLicenseFileWeightIsHighestMatch(t *testing.T) {
	for _, tt := range []struct {
		name string
		want float64
	}{
		{"LICENSE", 1.00},
		{"LICENSE.md", 0.95},
		{"COPYING", 0.90},
		{"LICENSE.textile", 0.80},
		{"LICENSE-MIT", 0.70},
		{"PATENTS", 0.35},
	} {
		t.Run(tt.name, func(t *testing.T) {
			is, got := IsLicenseFile(tt.name)
			if !is || got != tt.want {
				t.Errorf("IsLicenseFile(%q): got = (%v, %v), want = (true, %v)", tt.name, is, got, tt.want)
			}
		})
	}
}

func TestFindProjectScope(t *testing.T) {
	fsys := tree(map[string][]byte{
		"LICENSE":                 []byte("a"),
		"COPYING":                 []byte("a"),
		"LICENSE-MIT":             []byte("a"),
		"OFL.md":                  []byte("a"),
		"PATENTS":                 []byte("a"),
		"README.md":               []byte("a"),
		"license.go":              []byte("a"),
		"LICENSE.spdx":            []byte("a"),
		"docs/LICENSE":            []byte("a"),
		"vendor/LICENSE":          []byte("a"),
		"node_modules/LICENSE":    []byte("a"),
		"venv/LICENSE.txt":        []byte("a"),
		"rust-1.86.0-src/COPYING": []byte("a"),
		"a/b/LICENSE":             []byte("a"),
	})

	found, err := Find(fsys, ScopeProject)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(found.Candidates))
	for _, f := range found.Candidates {
		got = append(got, f.Path)
	}

	// Ordered by descending weight, with root files carrying RootWeightBonus.
	// The trees belonging to other components are skipped outright, and
	// anything deeper than one directory is out of scope.
	want := []string{
		"LICENSE",      // 1.00 + 0.5
		"COPYING",      // 0.90 + 0.5
		"LICENSE-MIT",  // 0.70 + 0.5
		"OFL.md",       // 0.50 + 0.5
		"docs/LICENSE", // 1.00, no bonus, so it sorts below OFL.md
		"PATENTS",      // 0.35 + 0.5
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Find(ScopeProject) (-want, +got):\n%s", diff)
	}
}

// TestFindTreeScopeRecordsExclusions covers the other half of the contract:
// evidence collection needs the vendored and fixture licenses, and needs to
// know which they are, so they are returned with a reason rather than skipped.
func TestFindTreeScopeRecordsExclusions(t *testing.T) {
	fsys := tree(map[string][]byte{
		"LICENSE":                       []byte("a"),
		"vendor/github.com/x/LICENSE":   []byte("a"),
		"testdata/fixture/LICENSE":      []byte("a"),
		"melange-out/pkg/usr/LICENSE":   []byte("a"),
		"PATENTS":                       []byte("a"),
		"deep/nested/tree/here/LICENSE": []byte("a"),
	})

	found, err := Find(fsys, ScopeTree)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]ExclusionReason{}
	for _, f := range found.Candidates {
		got[f.Path] = f.Excluded
	}
	want := map[string]ExclusionReason{
		"LICENSE":                       ExclusionNone,
		"PATENTS":                       ExclusionSupplementary,
		"vendor/github.com/x/LICENSE":   ExclusionVendored,
		"testdata/fixture/LICENSE":      ExclusionTestFixture,
		"melange-out/pkg/usr/LICENSE":   ExclusionBuildOutput,
		"deep/nested/tree/here/LICENSE": ExclusionNone,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Find(ScopeTree) exclusions (-want, +got):\n%s", diff)
	}
}

// TestFindFollowsSymlinksWithinRoot verifies that a symlinked license file is
// read (repositories commonly symlink LICENSE to the real text) while a symlink
// escaping the filesystem is skipped rather than read.
//
// It needs a real directory: fstest.MapFS has no symlinks, and the property
// under test is exactly what os.Root does to link resolution.
func TestFindFollowsSymlinksWithinRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docs", "text.txt"), []byte("MIT"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("docs", "text.txt"), filepath.Join(dir, "LICENSE")); err != nil {
		t.Fatal(err)
	}

	outside := filepath.Join(t.TempDir(), "escaped.txt")
	if err := os.WriteFile(outside, []byte("BSD"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "COPYING")); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	found, err := Find(root.FS(), ScopeProject)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(found.Candidates))
	for _, f := range found.Candidates {
		got = append(got, f.Path)
	}
	if diff := cmp.Diff([]string{"LICENSE"}, got); diff != "" {
		t.Errorf("Find over an os.Root filesystem (-want, +got):\n%s", diff)
	}
}
