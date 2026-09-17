# license

Shared license discovery, classification and identity for Chainguard's build
and analysis tooling.

We detect licenses in more than one place: melange warns at build time when a
package's declared license disagrees with the license files it ships, an
upstream release has to be evaluated before it is consumed, and the License
Oracle needs the same answer. Each had its own copy of the detection code, and
the copies drifted. This module is the single implementation they share.

## Packages

- **`spdx`** - normalizes classifier and manifest names onto SPDX identifiers,
  and parses SPDX expressions. Derives the identifiers an expression exposes a
  consumer to, and evaluates an expression against a caller's condition.
- **`detect`** - finds the license files in a tree and identifies what they
  are. Discovery scopes the sweep; identification is a conclusion, and is
  reported with the confidence it was reached at. Failure is per file, so a
  tree carrying no license evidence stays distinguishable from one that could
  not be read.
- **`component`** - names the things whose licenses have to be determined, and
  enumerates them from a source tree's manifests and lockfiles or from a
  build's output trees. Purl construction lives here, per ecosystem, so every
  producer derives the same identity for the same component. Enumeration
  reports identity only; a manifest's own license field is recorded as
  upstream's declaration, never as a conclusion.
- **`contenthash`** - computes the license-content hash and the `LicenseRef-`
  name, and verifies a local copy against a published artifact. Verification is
  a subset test rather than an equality test: `go mod vendor` copies only the
  packages a build imports, so a vendored tree legitimately omits license files
  the published artifact carries.
- **`assess`** - scores how complete and conclusive the collected evidence is,
  from 0 to 1, and flags the ambiguities behind a low score. The flags are
  values from a stable enum, so a consumer matches on them rather than parsing
  text. A separate `Unknown` reports that there was no evidence to weigh, which
  a caller checks before reading the score. The threshold for acting on a low
  score belongs to the consumer.
- **`upstream`** - fetches published artifacts, checks out repositories at a
  ref, and expands archives into filesystems the other packages can read. It
  follows a Java component's POM parent chain, since a POM often inherits its
  license declaration from a parent that no tree carries. It reports whether a
  digest matched an ecosystem checksum service and leaves the trust policy to
  the consumer. This is the only package that reaches the network or writes to
  disk.
- **`evidence`** - assembles what the other packages found into one versioned
  bundle, and defines the `Subject` interface a producer implements to supply a
  component's source and installed trees. Where a required tree is unavailable
  the bundle records that failure, so an incomplete bundle stays distinguishable
  from a clean one. The encoding is canonical, because consumers store bundles
  under their own digest.

Every package that inspects a tree takes an `fs.FS`, so one code path reads a
live build workspace, an unpacked package, a downloaded archive or an in-memory
test fixture.

Deciding whether a license is acceptable is not this module's job. The module
reports what it finds.

## Durable keys

Two values this module derives end up in consumers' stored records, so their
definitions are a compatibility surface rather than an implementation detail.

- **The license-content hash** identifies a component's license files as a set.
  It is `v1-` followed by SHA-256 over framed path and content records for every
  selected file, ordered by path. The framing stops two different record
  sequences from producing the same input bytes. Manifests and files belonging
  to a nested component are excluded, and traversal has no depth limit, because
  two trees differing only in a subdirectory's license must not hash alike.
- **The `LicenseRef-` name** identifies one license text that has no SPDX
  identifier. It is `LicenseRef-v1-` followed by the first 16 hexadecimal
  characters of the SHA-256 digest of that one file. The digest is per file
  rather than per component, so identical text yields the same name in every
  component that carries it.

Contents are converted from CRLF to LF before either digest, since the same
text carries the same terms however it was checked out. Nothing else is
normalized: whitespace and case stay significant.

Both names carry a scheme version, in the manner of `go.sum`'s `h1:`, and the
two versions move independently: re-framing a component's file set should not
invalidate a curated name somebody gave a EULA. A version covers how bytes
become a digest, meaning the framing, the normalization and the digest
function, but not which files went in. Changing a definition re-keys stored
data and is therefore a migration rather than a refactor. Changing which files
are selected re-keys only the affected components, and that changed hash reads
as a cache miss, so the consumer examines those components again.

## Contributing

Chainguard employees should make changes in
[chainguard-dev/mono](https://github.com/chainguard-dev/mono) under
`public/license`, from where they are exported here.

External contributions are welcome as pull requests on this repository. An
approved PR is merged internally in mono and then exported back, so the merge
will not show up as a merge commit here.
