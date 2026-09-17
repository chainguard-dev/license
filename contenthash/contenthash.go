/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package contenthash

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"chainguard.dev/license/detect"
	"chainguard.dev/license/internal/digest"
)

// Scheme names the version of the license-content hash, and prefixes every one
// this package produces, so a stored key states the rules it was computed
// under.
//
// The LicenseRef name carries its own version in RefScheme. The two keys are
// versioned separately because they are re-derived by different consumers over
// different inputs: changing how a component's file set is framed should not
// invalidate the curated name somebody gave a EULA.
const Scheme = "v1"

// File identifies one license file by where it sits and what it contains.
type File struct {
	// Path is relative to the component's own root, not to the tree the file
	// was found in. A module vendored at vendor/github.com/pkg/errors/LICENSE
	// and the same module's published zip both reduce to "LICENSE".
	Path string `json:"path"`
	// Digest is the digest of the file's contents with line endings
	// normalized, "sha256:"-prefixed. It is the content record the hash covers,
	// which is what lets a file's contribution travel without its text.
	Digest string `json:"digest"`
}

// Compute digests a component's licensing evidence.
//
// The records are ordered by path, so the order the caller found the files in
// does not change the key, and each record is length-framed, so no two
// different sets of files can produce the same input bytes. Filename weights
// are deliberately not part of the input: changing a weight changes which file
// a reader is shown first, not what the component contains.
//
// Traversal that produced the files must have had no depth limit and given no
// precedence to the component root, because two copies differing only in a
// subdirectory's license must not hash alike. Discovery's depth caps and
// ignored-directory lists are cost and attribution heuristics and do not apply
// here; nested-component ownership decides what to leave out instead.
func Compute(files []File) string {
	sorted := make([]File, len(files))
	copy(sorted, files)
	slices.SortFunc(sorted, func(a, b File) int {
		return cmp.Or(strings.Compare(a.Path, b.Path), strings.Compare(a.Digest, b.Digest))
	})

	h := sha256.New()
	for _, f := range sorted {
		fmt.Fprintf(h, "%d:%s%d:%s", len(f.Path), f.Path, len(f.Digest), f.Digest)
	}
	return Scheme + "-" + hex.EncodeToString(h.Sum(nil))
}

// ComputeFS digests the licensing evidence of a filesystem rooted at the
// component itself, which is the form a fetched artifact arrives in.
func ComputeFS(fsys fs.FS) (string, error) {
	files, err := Files(fsys)
	if err != nil {
		return "", err
	}
	return Compute(files), nil
}

// Files lists a component's license files with their digests, from a filesystem
// rooted at the component itself.
//
// Selection lives here rather than at each call site, so that both sides of a
// comparison are looking at the same category of file.
func Files(fsys fs.FS) ([]File, error) {
	var out []File
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree contributes nothing and is not fatal
		}
		if d.IsDir() || !Covers(p) {
			return nil
		}
		f, err := fsys.Open(p)
		if err != nil {
			return fmt.Errorf("opening %q: %w", p, err)
		}
		defer f.Close()
		sum, err := digest.File(f)
		if err != nil {
			return fmt.Errorf("digesting %q: %w", p, err)
		}
		out = append(out, File{Path: p, Digest: sum})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Covers reports whether a path contributes to a component's license-content
// hash.
//
// One predicate for both sides of the comparison. It is narrower than what
// evidence collection retains, which also keeps manifests and prose for
// classification: those are evidence, but no packaging route preserves them
// identically, so hashing them would manufacture divergence.
func Covers(p string) bool {
	is, _ := detect.IsLicenseFile(p)
	return is
}

// From converts discovered files into hash records, keeping the ones the hash
// covers and discarding the rest.
//
// A file discovery could not read is dropped rather than contributing an empty
// digest, since a record claiming a file hashes to nothing would key an answer
// to evidence nobody has. The consequence is that a component with an
// unreadable license file hashes like one that has none, which the key cannot
// express and is not the place to: what the file set was is a fact about
// content, and what could be read is a fact about the collection. A caller that
// needs to tell the two apart reads the collection's own record of the
// failure, which the evidence package reports as a gap, before trusting the
// answer the key resolves to.
func From(files []detect.File) []File {
	out := make([]File, 0, len(files))
	for _, f := range files {
		if f.Digest == "" || !Covers(f.Path) {
			continue
		}
		out = append(out, File{Path: f.Path, Digest: f.Digest})
	}
	return out
}

// Relative selects the license files belonging to a component rooted at root,
// with their paths made relative to it.
//
// It is the collect-side counterpart to Files: evidence records a license file
// by its path in the whole tree, and a component's hash has to be over paths
// relative to the component itself.
//
// nested lists the roots of components inside this one, whose files belong to
// them rather than to this component. Nesting is real and not rare:
// github.com/containerd/errdefs vendors its own errdefs/pkg submodule inside
// its directory, and the parent's published zip excludes it, so attributing
// pkg's LICENSE to the parent reports a divergence that is not there.
func Relative(files []File, root string, nested []string) []File {
	root = strings.TrimSuffix(root, "/")
	if root == "" {
		return nil
	}
	var out []File
	for _, f := range files {
		rel, inside := strings.CutPrefix(f.Path, root+"/")
		if !inside || rel == "" || ownedByNested(f.Path, nested) {
			continue
		}
		out = append(out, File{Path: rel, Digest: f.Digest})
	}
	return out
}

// ownedByNested reports whether a path falls inside one of the nested component
// roots rather than the component being collected.
//
// The rule is the longest matching root wins, which this expresses by asking
// only whether a deeper root claims the file: the caller has already narrowed
// nested to the roots strictly inside this one.
func ownedByNested(p string, nested []string) bool {
	for _, n := range nested {
		if strings.HasPrefix(p, strings.TrimSuffix(n, "/")+"/") {
			return true
		}
	}
	return false
}

// NestedRoots returns the component roots lying strictly inside root, which is
// what Relative needs in order to leave them out.
func NestedRoots(root string, all []string) []string {
	root = strings.TrimSuffix(root, "/")
	var out []string
	for _, other := range all {
		other = strings.TrimSuffix(other, "/")
		if other != root && strings.HasPrefix(other, root+"/") {
			out = append(out, other)
		}
	}
	slices.Sort(out)
	return out
}
