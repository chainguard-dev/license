/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"chainguard.dev/license/internal/digest"
)

// Patch is one patch a build applies to the upstream source before building it.
type Patch struct {
	// Name is how the build refers to the patch.
	Name string `json:"name"`
	// Digest is the digest of the patch's contents. Its presence is what makes
	// the identity meaningful: a patch changed in place under the same filename
	// is different source, and a name alone could not say so.
	Digest string `json:"digest"`
}

// Source describes the upstream source a package is built from.
type Source struct {
	// Name and Version are the package's own coordinates, used when the build
	// records no upstream repository to name instead.
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	// Repository and Commit locate the upstream source. A commit is what makes
	// the locator exact; a tag can move.
	Repository string `json:"repository,omitempty"`
	Commit     string `json:"commit,omitempty"`
	// Patches are the patches the build applies, in any order.
	Patches []Patch `json:"patches,omitempty"`
}

// SourceComponent names the component a package is built from.
//
// No purl identifies a package's exact source state, because the source that
// gets built is upstream's tree with our patches applied and nothing publishes
// that combination. So the identity is a source locator plus a digest over the
// patches: rebuilding unchanged source and unchanged patches at a new package
// revision keeps the same identity, and a determination made once is still
// found. Changing a patch is new content and gets its own.
//
// The upstream repository is preferred as the locator, since that is what the
// licensing is actually about. A package with no recorded upstream falls back
// to naming the apk itself, which is weaker - two packages built from the same
// upstream no longer share an identity - but it is the strongest locator that
// exists for such a package.
func SourceComponent(s Source) Component {
	c := Component{
		PURL:       SourcePURL(s),
		Name:       s.Name,
		Version:    s.Version,
		Ecosystem:  EcosystemSource,
		Kind:       KindPackageSource,
		Digest:     PatchSetDigest(s.Patches),
		DigestAlgo: DigestPatchSet,
	}
	if s.Repository != "" {
		c.Name = s.Repository
	}
	return c
}

// SourcePURL renders the locator for a package's own source.
func SourcePURL(s Source) string {
	if s.Repository == "" {
		return "pkg:apk/" + s.Name + "@" + s.Version
	}
	locator := strings.TrimSuffix(repositoryPath(s.Repository), ".git")
	if s.Commit != "" {
		return "pkg:generic/" + locator + "@" + s.Commit
	}
	return "pkg:generic/" + locator + "@" + s.Version
}

// repositoryPath reduces a repository URL to host and path, which is what
// identifies it. The scheme is dropped because the same repository cloned over
// https and over ssh is one repository.
func repositoryPath(repo string) string {
	trimmed := repo
	for _, scheme := range []string{"https://", "http://", "git+https://", "ssh://", "git@"} {
		trimmed = strings.TrimPrefix(trimmed, scheme)
	}
	return strings.TrimSuffix(trimmed, "/")
}

// PatchSetDigest digests the patches applied to a source tree, or returns empty
// when none were.
//
// Records are ordered by name and length-framed, so the order the build listed
// its patches in does not change the identity and no two different patch sets
// can produce the same input bytes.
func PatchSetDigest(patches []Patch) string {
	if len(patches) == 0 {
		return ""
	}
	sorted := make([]Patch, len(patches))
	copy(sorted, patches)
	slices.SortFunc(sorted, func(a, b Patch) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Digest, b.Digest))
	})

	var b strings.Builder
	for _, p := range sorted {
		fmt.Fprintf(&b, "%d:%s%d:%s", len(p.Name), p.Name, len(p.Digest), p.Digest)
	}
	return digest.Bytes([]byte(b.String()))
}
