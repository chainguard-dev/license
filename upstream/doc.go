/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package upstream acquires the content whose license is in question: a
// published ecosystem artifact, or a repository at a revision.
//
// It is the only package here that touches the network or the disk. Everything
// else reads an fs.FS, which is what this returns, so no other package has to
// know whether the tree it is reading came from a build workspace, a downloaded
// archive or a test fixture.
//
// # Why content and not metadata
//
// Reading a license field out of registry metadata reproduces what a build-time
// scanner already does, and reproduces its blind spots: Go modules have no
// license field anywhere in their metadata, Cargo.lock records checksums but no
// licenses, and a manifest that does carry a license routinely disagrees with
// the license files in the artifact. Metadata is worth capturing - it is the
// declared license, and agreement with the content raises confidence - but the
// conclusion has to come from classifying the content.
//
// # Identity, not trust
//
// A fetch reports whether the retrieved bytes carry the digest the caller
// expected, and Checksum asks the ecosystem's own checksum database the same
// question independently. Both are statements about content identity and
// neither is a statement about licensing or provenance: a match means these are
// the bytes that database recorded, so an answer drawn from them is safe to
// share with every other package depending on that version. What policy to
// apply to a mismatch is the caller's decision.
//
// # Posture
//
// Fetches are https-only, validated immediately before the request against the
// addresses the host resolves to, size-bounded, and - for artifact
// registries - unauthenticated, since every artifact fetched here is public by
// definition. A repository checkout may carry a credential, which travels in
// the environment and never in a command line, a log or an error.
//
// Nothing fetched is ever executed. Archives are read for their bytes, and a
// build script or install hook inside one is just another file.
package upstream
