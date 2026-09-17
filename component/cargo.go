/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"cmp"
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/chainguard-dev/clog"
)

// CargoPURL renders a crate name and version as a purl.
func CargoPURL(name, version string) string {
	if version == "" {
		return "pkg:cargo/" + name
	}
	return "pkg:cargo/" + name + "@" + version
}

// enumerateCargo lists the crates a Rust package statically links, as
// identities rather than resolved licenses. Cargo always links its whole
// dependency tree.
//
// Cargo.lock records name, version and the registry checksum but no license:
// the license field lives in each crate's Cargo.toml, which the lockfile does
// not contain. That is why a lockfile-only scanner reports nothing for Rust,
// and why the license has to come from the published .crate content, identified
// by the checksum recorded here.
func enumerateCargo(ctx context.Context, fsys fs.FS) (out Enumeration) {
	lockPath, ok := findShallowest(fsys, "Cargo.lock")
	if !ok {
		return out
	}
	clog.DebugContextf(ctx, "found Cargo.lock at %s", lockPath)

	data, err := readBounded(fsys, lockPath, maxLockfileBytes)
	if err != nil {
		out.Failures = append(out.Failures, Failure{Ecosystem: EcosystemCargo, Path: lockPath, Detail: err.Error()})
		return out
	}
	var lock cargoLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		out.Failures = append(out.Failures, Failure{Ecosystem: EcosystemCargo, Path: lockPath, Detail: err.Error()})
		return out
	}

	checksums := lock.metadataChecksums()
	workspaceLocal := 0
	for _, p := range lock.Package {
		// A package with no source is a workspace-local crate: it is part of
		// the package's own source, covered by the source component.
		if p.Source == "" {
			workspaceLocal++
			continue
		}
		// Version 1 lockfiles record the checksum in a metadata table instead
		// of on the package, so both are consulted. Reading only the inline
		// field left every crate in an older lockfile with no content digest
		// and nothing to verify a fetch against.
		checksum := cmp.Or(p.Checksum, checksums[cargoPackage{name: p.Name, version: p.Version, source: p.Source}])
		out.Components = append(out.Components, Component{
			PURL:           CargoPURL(p.Name, p.Version),
			Name:           p.Name,
			Version:        p.Version,
			Ecosystem:      EcosystemCargo,
			Kind:           KindEcosystem,
			DiscoveredFrom: lockPath,
			Linkage:        LinkageStatic,
		}.withContentDigest(checksum, DigestSHA256))
	}
	if workspaceLocal > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("cargo: %d workspace-local crates covered by the package source", workspaceLocal))
	}
	return out
}

// cargoLock is the part of Cargo.lock that identifies crates. Checksum is the
// registry digest of the published .crate archive, which is that content's
// identity.
//
// Metadata is where version 1 lockfiles kept those checksums, under keys of
// the form "checksum <name> <version> (<source>)". Cargo moved them onto the
// package entries in version 2 and left the older form in the wild.
type cargoLock struct {
	Package []struct {
		Name     string `toml:"name"`
		Version  string `toml:"version"`
		Source   string `toml:"source"`
		Checksum string `toml:"checksum"`
	} `toml:"package"`
	Metadata map[string]string `toml:"metadata"`
}

// cargoPackage identifies a crate the way a lockfile does.
//
// The source is part of the identity, not decoration. Cargo resolves the same
// name and version from the registry and from git in one graph, and only the
// registry copy is checksummed, so indexing on name and version alone hands
// the registry crate's digest to the git one and reports arbitrary git code as
// content that was verified.
type cargoPackage struct{ name, version, source string }

// metadataChecksums indexes a version 1 lockfile's checksums, whose keys have
// the form "checksum <name> <version> (<source>)".
func (l cargoLock) metadataChecksums() map[cargoPackage]string {
	out := make(map[cargoPackage]string, len(l.Metadata))
	for key, checksum := range l.Metadata {
		if !strings.HasPrefix(key, "checksum ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(key, "checksum "))
		if len(fields) < 3 {
			continue
		}
		out[cargoPackage{name: fields[0], version: fields[1], source: strings.Trim(fields[2], "()")}] = checksum
	}
	return out
}
