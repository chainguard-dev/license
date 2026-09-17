/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"strings"

	"github.com/chainguard-dev/clog"
)

// npmLockFiles are the lockfiles npm writes, in the order they are looked for.
// A shrinkwrap is the same format and takes precedence when a project ships
// one.
var npmLockFiles = []string{"npm-shrinkwrap.json", "package-lock.json"}

// NpmPURL renders an npm package name and version as a purl.
//
// A scoped name is escaped one path component at a time, which keeps a literal
// separator between scope and package and leaves the "@" alone - it is a legal
// path character, so PathEscape does not touch it. That yields
// "pkg:npm/@scope/name", matching what the rest of the fleet emits.
//
// The spelling matters more than it looks. "pkg:npm/%40scope/name" is equally
// valid and equally common in the wild, the two are not interchangeable as map
// keys, and a determination is found again by exact purl.
func NpmPURL(name, version string) string {
	escaped := url.PathEscape(name)
	if scope, base, ok := strings.Cut(name, "/"); ok {
		escaped = url.PathEscape(scope) + "/" + url.PathEscape(base)
	}
	if version == "" {
		return "pkg:npm/" + escaped
	}
	return "pkg:npm/" + escaped + "@" + url.PathEscape(version)
}

// enumerateNpm lists the npm packages a project installs, as identities rather
// than resolved licenses.
//
// The lockfile is the whole source: it pins an exact version and an integrity
// hash for every package in the tree, which together are the component's
// identity, and it does so without a toolchain, a network, or node_modules
// having ever been populated.
//
// Development dependencies are excluded. Unlike Go's module graph, where an
// over-inclusive go.sum still lists code that could be linked, a package marked
// dev is reachable only from devDependencies and does not ship - and in a
// typical project it outnumbers what does. Reporting its license would overstate
// the obligations the package actually carries.
func enumerateNpm(ctx context.Context, fsys fs.FS) (out Enumeration) {
	var lockPath string
	for _, name := range npmLockFiles {
		if p, ok := findShallowest(fsys, name); ok {
			lockPath = p
			break
		}
	}
	if lockPath == "" {
		return out
	}
	clog.DebugContextf(ctx, "found npm lockfile at %s", lockPath)

	data, err := readBounded(fsys, lockPath, maxLockfileBytes)
	if err != nil {
		out.Failures = append(out.Failures, Failure{Ecosystem: EcosystemNpm, Path: lockPath, Detail: err.Error()})
		return out
	}
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		out.Failures = append(out.Failures, Failure{Ecosystem: EcosystemNpm, Path: lockPath, Detail: err.Error()})
		return out
	}

	entries, dev, local := lock.entries()
	for _, e := range entries {
		out.Components = append(out.Components, Component{
			PURL:           NpmPURL(e.name, e.version),
			Name:           e.name,
			Version:        e.version,
			Ecosystem:      EcosystemNpm,
			Kind:           KindEcosystem,
			DiscoveredFrom: lockPath,
			Linkage:        LinkageBundled,
		}.withContentDigest(e.integrity, DigestNpmIntegrity))
	}

	if dev > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("npm: %d development dependencies excluded; they are not shipped", dev))
	}
	if local > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("npm: %d workspace or non-registry entries covered by the package source", local))
	}
	return out
}

// npmLock is the part of a lockfile that identifies packages.
//
// Two layouts have to be read. Version 2 and 3 record a flat Packages map keyed
// by install path, which is the one to prefer because it states the dev flag
// per entry. Version 1 records only a nested Dependencies tree, and version 2
// carries both for backward compatibility.
type npmLock struct {
	Packages     map[string]npmPackage `json:"packages"`
	Dependencies map[string]npmDep     `json:"dependencies"`
}

// npmPackage is one entry of the flat layout.
type npmPackage struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
	// Link marks a workspace symlink, whose target is another entry in the same
	// lockfile rather than anything published.
	Link bool `json:"link"`
	// Name is set when the install path does not carry it, which happens for
	// aliased dependencies.
	Name string `json:"name"`
}

// npmDep is one entry of the nested version 1 layout.
type npmDep struct {
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved"`
	Integrity    string            `json:"integrity"`
	Dev          bool              `json:"dev"`
	Dependencies map[string]npmDep `json:"dependencies"`
}

// npmEntry is one identified package.
type npmEntry struct{ name, version, integrity string }

// entries flattens whichever layout the lockfile uses, reporting how many were
// left out and why.
func (l npmLock) entries() (out []npmEntry, dev, local int) {
	seen := make(map[npmEntry]struct{})
	keep := func(e npmEntry) {
		if _, repeated := seen[e]; repeated {
			return
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}

	if len(l.Packages) > 0 {
		for installPath, p := range l.Packages {
			// The empty key is the project itself, already covered by the
			// source component.
			if installPath == "" {
				continue
			}
			if p.Dev {
				dev++
				continue
			}
			name := cmp.Or(p.Name, npmNameFromPath(installPath))
			if name == "" || p.Version == "" || p.Link || !fromNpmRegistry(p.Resolved) {
				local++
				continue
			}
			keep(npmEntry{name, p.Version, p.Integrity})
		}
		return out, dev, local
	}

	var walk func(deps map[string]npmDep)
	walk = func(deps map[string]npmDep) {
		for name, d := range deps {
			switch {
			case d.Dev:
				dev++
			case d.Version == "" || !fromNpmRegistry(d.Resolved):
				local++
			default:
				keep(npmEntry{name, d.Version, d.Integrity})
			}
			walk(d.Dependencies)
		}
	}
	walk(l.Dependencies)
	return out, dev, local
}

// npmNameFromPath recovers a package name from its install path. Transitive
// packages that could not be deduplicated to the top nest further node_modules
// directories, and the name is whatever follows the last one.
func npmNameFromPath(installPath string) string {
	idx := strings.LastIndex(installPath, "node_modules/")
	if idx < 0 {
		return ""
	}
	return installPath[idx+len("node_modules/"):]
}

// fromNpmRegistry reports whether an entry resolves to a published tarball.
//
// The https prefix is the whole test, and it is enough: a workspace link
// resolves to a relative path, a git dependency to "git+ssh://" or
// "git+https://", and a bundled or root-adjacent entry to nothing at all. None
// of those is a component a registry can answer for.
func fromNpmRegistry(resolved string) bool {
	return strings.HasPrefix(resolved, "https://")
}
