/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package component names the things whose licenses have to be determined, and
// enumerates them.
//
// A component is the unit of determination: something whose license is decided
// once and then reused. The same Go module vendored into hundreds of packages,
// or the same jar bundled into hundreds of images, is one component with one
// answer, and that only works if every producer derives the same identity for
// it. So purl construction lives here, per ecosystem, rather than at each call
// site.
//
// # Two places components are named
//
// A source tree names them in manifests and lockfiles: coordinates and a
// content digest, with no toolchain, no network and no dependency sources
// needed. A build output names the ones that exist nowhere else - a Python
// application's resolved dependency versions do not exist until pip has run,
// and neither do the jars a Java package bundles.
//
// The two are separate registries rather than a flag on one, because they
// answer different questions: a source enumerator reports what the package
// asked for, and an output enumerator reports what it shipped. Where both exist
// for an ecosystem they are complementary, and where no build has run only the
// first can answer at all.
//
// # Identity only
//
// Nothing here resolves a license. Enumeration reports coordinates and
// digests; the licensing is determined per component against its published
// content, so that one determination serves every package that depends on that
// version rather than being re-derived per build. Reading a manifest's own
// declared license field is the one exception, and it is recorded as a
// declaration - upstream's claim - never as a conclusion.
//
// # No network
//
// Enumeration reads local trees. Fetching a component's published content, or
// following a POM's parent chain to a registry, is the upstream package's job.
package component
