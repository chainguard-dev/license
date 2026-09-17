/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component

// Kind distinguishes the source a package is built from from the ecosystem
// components it pulls in. Both are determined the same way; they differ in how
// their content is acquired.
type Kind string

const (
	// KindPackageSource is the upstream source tree the package is built from.
	KindPackageSource Kind = "package-source"
	// KindEcosystem is a published module, crate, jar, wheel or similar that
	// the package links or bundles.
	KindEcosystem Kind = "ecosystem"
)

// Linkage describes how a component's code reaches the shipped artifact, which
// is what decides the relationship an SBOM records for it.
type Linkage string

const (
	// LinkageStatic means the component is compiled into a shipped binary, as
	// Go modules and Rust crates always are.
	LinkageStatic Linkage = "static"
	// LinkageBundled means the component ships as its own file inside the
	// artifact: an installed distribution, a bundled jar, a packaged tarball.
	LinkageBundled Linkage = "bundled"
)

// Ecosystem is a purl type. It is the vocabulary identities are keyed in, so a
// package and its dependencies are reported under one label rather than
// splitting across "go" and "golang".
type Ecosystem = string

// The ecosystems this package can enumerate.
const (
	EcosystemGo     Ecosystem = "golang"
	EcosystemCargo  Ecosystem = "cargo"
	EcosystemNpm    Ecosystem = "npm"
	EcosystemPyPI   Ecosystem = "pypi"
	EcosystemMaven  Ecosystem = "maven"
	EcosystemApk    Ecosystem = "apk"
	EcosystemSource Ecosystem = "generic"
)

// Component is something whose license is decided once, keyed by its identity
// together with the digest of the content that was examined.
type Component struct {
	// PURL is the canonical package URL, without qualifiers. It is the logical
	// identity: two copies of one version share it.
	PURL string `json:"purl"`
	// Name and Version are the ecosystem-native coordinates behind the purl,
	// kept separately so a consumer does not have to re-parse it.
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	// Ecosystem is the purl type.
	Ecosystem Ecosystem `json:"ecosystem"`
	Kind      Kind      `json:"kind"`

	// Digest is the ecosystem's own content digest for this version, and
	// DigestAlgo names the scheme it came from. Recording the scheme is not
	// decoration: an npm integrity string written years ago is sha1 and today's
	// is sha512, and hashing with the wrong one produces a value that can
	// neither agree nor disagree with what the lockfile recorded.
	Digest     string `json:"digest,omitempty"`
	DigestAlgo string `json:"digest_algo,omitempty"`

	// LicenseContentHash is the digest of this component's licensing evidence
	// as a local copy holds it, set only where the component's source is
	// present in the tree. It is what a determination is keyed on and what the
	// published artifact is verified against: a copy that verifies shares the
	// published answer, and one that does not is a variant of its own.
	//
	// Empty for a component with no local copy, which is most of them. A crate
	// or an npm package is named by a lockfile and never appears in the tree,
	// and there is nothing local to verify for it.
	LicenseContentHash string `json:"license_content_hash,omitempty"`

	// DiscoveredFrom records the file the identity was read out of, so a
	// surprising component can be traced back to what claimed it.
	DiscoveredFrom string `json:"discovered_from"`
	// Linkage describes how the component reaches the shipped artifact.
	Linkage Linkage `json:"linkage,omitempty"`
}

// withContentDigest records a content digest and the scheme it came from, and
// records neither when there is no digest.
//
// Every ecosystem has entries without one: a go.sum that does not cover a
// vendored module, an npm link entry pointing at a workspace, a crate resolved
// from git rather than the registry. A scheme named beside an empty digest
// claims a verification nobody can perform, so the two are set together or not
// at all.
func (c Component) withContentDigest(digest, algo string) Component {
	if digest == "" {
		return c
	}
	c.Digest, c.DigestAlgo = digest, algo
	return c
}

// Digest algorithm names, recorded beside a component's digest.
const (
	// DigestGoModule is the dirhash "h1:" hash of a module zip, verifiable
	// against sum.golang.org.
	DigestGoModule = "h1"
	// DigestSHA256 is a bare sha256, which is what Cargo.lock records.
	DigestSHA256 = "sha256"
	// DigestSHA1 is a bare sha1, which is what Maven Central publishes.
	DigestSHA1 = "sha1"
	// DigestNpmIntegrity is a Subresource Integrity string, carrying its own
	// algorithm prefix.
	DigestNpmIntegrity = "npm-integrity"
	// DigestPatchSet is a digest over the patches applied to a package's
	// source. See SourceComponent.
	DigestPatchSet = "patch-set"
)
