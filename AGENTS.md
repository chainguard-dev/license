# AGENTS.md

Module `chainguard.dev/license` finds, classifies and names the licenses in a source tree or artifact. It is a library: other code imports it, and it is published as its own repository. `README.md` describes each package; each package's `doc.go` gives its reasoning. Paths here are relative to the module root.

## What a wrong answer costs

License results carry legal weight. Consumers publish them in SBOMs and decide from them what may ship.

- A license reported as more permissive than it is, or an obligation dropped, tells a consumer it may ignore terms it is bound by.
- An unreadable or partly read tree that reads as "no license" or as settled hides a gap as a fact.
- A changed durable key makes every stored result keyed on the old value unreachable.

## What must stay true

- The module MUST report what it finds and MUST NOT decide what is acceptable. Policy, thresholds and family rankings belong to the consumer.
- A failure MUST be recorded, never dropped. An unreadable file, lockfile, tree or POM ancestor MUST appear as a per-file error, a `Failure`, a `Gap` or a note. Counts such as grant `Sampled` MUST count only what was actually read.
- Ambiguity MUST stay visible. Several licenses with no stated relationship conclude as `ReasonSeveralLicenses`, never as an AND or an OR. A GPL-family grant is never guessed. A malformed or empty declared expression MUST NOT earn certainty in `assess`.
- Evidence MUST be attributed to its own component. Files in test fixtures, vendored copies, nested components or sibling archive roots MUST NOT count toward a component's own conclusion or content hash.
- An identity MUST NOT be attached to content it was not derived from. A purl or digest from one source (registry, git, a URL tarball) MUST NOT be given to another. A digest scheme MUST NOT be recorded beside an empty digest.
- Every license a file names MUST reach `assess` and the conclusion, not only the strongest match.
- `spdx` MUST treat a `LicenseRef-` identifier as opaque: no grant stripping, no normalization. It MUST NOT map a bare family name ("GPL", "BSD") to a specific license.
- Classifier names MUST go through `spdx` before they are compared or published.
- `upstream` is the only package that reaches the network or writes to disk. Every other package reads an `fs.FS`. Nothing fetched is executed.

## Durable keys and wire formats

- The license-content hash (`contenthash.Scheme`) and the `LicenseRef-` name (`contenthash.RefScheme`) are stored by consumers. A change to framing, normalization or digest function MUST bump the matching scheme and say in the PR that stored data must be migrated or re-curated. A golden vector in `contenthash` MUST NOT change without that bump.
- A change to which files are selected re-keys the affected components. The PR MUST say which components change.
- `evidence.Bundle` embeds types from `detect`, `component` and `assess`. Renaming or retyping a JSON field in any of them changes the bundle format. A change of meaning or a new required field MUST bump `evidence.SchemaVersion`.
- Flag, `Reason` and `GrantBasis` values are a closed set consumers match on. Existing values MUST NOT be renamed or reused.
- Exported identifiers are public API. A breaking change MUST use a `!` commit type and SHOULD be avoided.

## Changing classification

This covers `detect` (discovery, scoping, classification, grants, conclusion), `ConfidenceThreshold`, `detect/supplement/`, the `spdx` tables and synonyms, `assess`, and a `licenseclassifier` upgrade. The PR MUST show:

- **Before/after counts.** Run the old and new code over the same corpus of real license files or trees, and give per-identifier counts and `Reason` counts for both. Name the corpus and say how to rerun it. Explain every change.
- **Tests.** `TestClassifyGoldenLicenses`, `TestSupplementIsRecognized` and `TestConclude` MUST pass unchanged, or the PR MUST explain each changed expectation. A new rule MUST have a test that fails without it.
- **Supplement entries** MUST be canonical SPDX texts keyed by a current SPDX identifier, added because real inputs carry that license. A license missing from the corpus is reported as its nearest neighbour at full confidence, so check the counts for licenses that moved.
- **Generated tables.** `spdx/tables.go` is generated from `spdx/licenses.json` and the classifier. Run `go generate ./...` in `spdx` and MUST NOT hand-edit it. `TestTablesAreCurrent` enforces this.

## Public repository

This directory is exported to a public repository at every commit. Code, comments, tests, fixtures and commit messages MUST NOT name internal systems, services, hosts, URLs, people or customers. Use public names and generic descriptions.

## Before merging

- `go test ./...` in this directory. `TestTablesRegenerateFromColdModuleCache` downloads the classifier module and needs network access.
- `golangci-lint run ./...` against this directory's `.golangci.yml`.
