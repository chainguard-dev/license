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

Deciding whether a license is acceptable is not this module's job. The module
reports what it finds.

## Contributing

Chainguard employees should make changes in
[chainguard-dev/mono](https://github.com/chainguard-dev/mono) under
`public/license`, from where they are exported here.

External contributions are welcome as pull requests on this repository. An
approved PR is merged internally in mono and then exported back, so the merge
will not show up as a merge commit here.
