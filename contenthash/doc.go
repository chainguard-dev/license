/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package contenthash derives the two durable keys this module owns, and
// verifies a local copy of a component against the artifact it claims to be.
//
// Both keys carry a scheme version, in the manner of go.sum's "h1:", because
// changing either re-keys stored data: a consumer that keyed a determination on
// one of these can no longer find it. The version covers how bytes become a
// digest - the framing, the normalization, the digest function - and not which
// files went in.
//
// # The license-content hash
//
// This is the variant key: what a determination is recorded under, so that one
// answer serves every copy of the same licensing evidence and a copy with
// different evidence gets its own.
//
// What it covers is deliberately narrow. Hashing a whole tree would let a stray
// timestamp or a line-ending difference mint a fresh variant, and the
// deduplication the whole scheme depends on would disappear. Hashing the
// licensing evidence instead means "same evidence, same answer", which is the
// only claim a determination actually makes.
//
// License files only, no manifests: vendoring does not preserve manifests, so
// keeping both sides of a comparison to the same category of file is what makes
// them comparable at all.
//
// # The LicenseRef name
//
// A license nothing recognizes still has to be recorded, or a proprietary EULA
// would silently read as no license at all. LicenseRef names it by the digest
// of its text, per file rather than per component, so identical text produces
// the same name in every component that carries it. Mapping that name to
// something a human wrote, and deciding what to serve for one nobody has named,
// is the consumer's job rather than this package's.
//
// # Verification is not the hash
//
// Compute keys an answer. Verify decides which key to use: it is a subset test
// rather than an equality, because vendoring legitimately drops files. The two
// are separate operations and neither implies the other.
package contenthash
