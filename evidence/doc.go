/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package evidence records everything observed about one subject's licensing,
// and reaches no conclusion about whether that licensing is acceptable.
//
// # Immutable evidence, re-derivable conclusions
//
// A bundle records what a tree contained: the license texts, the licensing
// fields the component's own manifests declare, the license mentions in its
// prose, the identities of the ecosystem components it pulls in, and the
// digests of all of it. Improving the classifier, moving a threshold or
// changing an ambiguity rule then means re-deriving answers from bundles
// already collected, rather than fetching every source tree in the fleet
// again.
//
// Classification and scoring are included because they are cheap and because a
// consumer wants them, but they are derived values over the retained texts.
// Nothing in a bundle depends on the tree still existing.
//
// # Subjects
//
// Collect does not care where the trees it reads came from. It operates on a
// Subject: something that can supply the source a component was built from and
// the trees it installed into. A live build is one subject, with its workspace
// and its staged output directories; a published package is another, supplying
// its installed file tree directly and naming its source by the commit its own
// metadata records; a published jar or wheel is a third.
//
// The bundle format does not vary between them, only how complete it is. A
// subject that cannot supply a tree says so, and the bundle records the failure
// instead of representing the tree as empty - an incomplete bundle has to stay
// distinguishable from a clean one, because the two mean opposite things about
// a component that appears to have no license.
//
// # Canonical encoding
//
// Consumers store bundles under their digest, so identical observations have to
// encode to identical bytes: rebuilding unchanged source is then a storage
// no-op rather than a second copy. Every bundle carries its schema version, so
// a reader never has to infer which rules produced it.
package evidence
