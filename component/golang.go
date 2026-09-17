/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/chainguard-dev/clog"
)

// GoPURL renders a module path and version as a purl. Module paths are already
// lowercase-normalized by the toolchain, so they need no further
// canonicalization.
func GoPURL(modulePath, version string) string {
	if version == "" {
		return "pkg:golang/" + modulePath
	}
	return "pkg:golang/" + modulePath + "@" + version
}

// enumerateGo lists the Go modules a package links, as identities rather than
// resolved licenses. Go binaries statically link their whole build graph, so
// every module in it is in scope.
//
// Go modules carry no declared license anywhere in their metadata - there is
// no license field in go.mod - so a Go module's license can only ever come
// from classifying the content of the published module zip. The h1 hash
// recorded in go.sum is that content's identity, and is verifiable against
// sum.golang.org.
//
// Two sources, preferred in this order:
//
//   - vendor/modules.txt, which lists exactly the modules the build uses.
//   - go.sum, which is over-inclusive: it records hashes for the full module
//     graph including modules pruned from the build. Over-inclusion costs a
//     determination some other package would have needed anyway, so it is
//     preferred over missing modules entirely.
func enumerateGo(ctx context.Context, fsys fs.FS) (out Enumeration) {
	modFile, ok := findShallowest(fsys, "go.mod")
	if !ok {
		return out
	}
	modDir := path.Dir(modFile)
	clog.DebugContextf(ctx, "found go.mod under %s", modDir)

	// go.sum carries the h1 content hashes whichever module list is used, so
	// read it first when it is there.
	digests := map[string]string{}
	switch data, err := readBounded(fsys, path.Join(modDir, "go.sum"), maxLockfileBytes); {
	case err == nil:
		digests = parseGoSum(data)
	case !errors.Is(err, fs.ErrNotExist):
		out.Failures = append(out.Failures, Failure{
			Ecosystem: EcosystemGo,
			Path:      path.Join(modDir, "go.sum"),
			Detail:    err.Error(),
		})
	}

	if data, err := readBounded(fsys, path.Join(modDir, "vendor", "modules.txt"), maxLockfileBytes); err == nil {
		for _, m := range parseVendorModules(data) {
			out.Components = append(out.Components, goComponent(m.path, m.version, digests, path.Join(modDir, "vendor/modules.txt")))
		}
		return out
	}

	if len(digests) == 0 {
		out.Notes = append(out.Notes, "go: neither vendor/modules.txt nor go.sum found; no module identities enumerated")
		return out
	}
	from := path.Join(modDir, "go.sum")
	for key := range digests {
		modulePath, version, ok := strings.Cut(key, "@")
		if !ok {
			continue
		}
		out.Components = append(out.Components, goComponent(modulePath, version, digests, from))
	}
	out.Notes = append(out.Notes, fmt.Sprintf("go: %d module identities from go.sum, which covers the full module graph and may include modules pruned from the build", len(out.Components)))
	return out
}

// goComponent builds a component for a module path and version, attaching the
// h1 digest and its scheme when go.sum recorded one.
//
// It often has not: the vendor list is read whether or not go.sum is present,
// and go.sum does not cover a module the build no longer requires.
func goComponent(modulePath, version string, digests map[string]string, from string) Component {
	return Component{
		PURL:           GoPURL(modulePath, version),
		Name:           modulePath,
		Version:        version,
		Ecosystem:      EcosystemGo,
		Kind:           KindEcosystem,
		DiscoveredFrom: from,
		Linkage:        LinkageStatic,
	}.withContentDigest(digests[modulePath+"@"+version], DigestGoModule)
}

// parseGoSum maps "<module>@<version>" to the h1 hash of the module zip.
//
// go.sum carries two lines per module: one for the zip and one for the go.mod
// file alone, distinguished by a "/go.mod" suffix on the version. Only the zip
// hash identifies the content whose licensing is in question.
func parseGoSum(data []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 || strings.HasSuffix(f[1], "/go.mod") {
			continue
		}
		out[f[0]+"@"+f[1]] = f[2]
	}
	return out
}

// vendorModule is one module line of a modules.txt.
type vendorModule struct {
	path    string
	version string
}

// parseVendorModules extracts module path and version pairs from a modules.txt
// body.
//
// Module lines look like "# <path> <version>"; a replace directive looks like
// "# <orig> <ver> => <replacement> <ver>". The vendored directory is named by
// the original path, so that is the component, carrying the effective version.
func parseVendorModules(data []byte) []vendorModule {
	var mods []vendorModule
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		spec := strings.TrimSpace(strings.TrimPrefix(line, "# "))
		modulePath, version := spec, ""
		if before, after, replaced := strings.Cut(spec, " => "); replaced {
			left := strings.Fields(before)
			right := strings.Fields(after)
			if len(left) > 0 {
				modulePath = left[0]
			}
			if len(right) > 0 {
				version = right[len(right)-1]
			}
		} else if f := strings.Fields(spec); len(f) >= 2 {
			modulePath, version = f[0], f[1]
		} else if len(f) == 1 {
			modulePath = f[0]
		}
		if modulePath != "" {
			mods = append(mods, vendorModule{path: modulePath, version: version})
		}
	}
	return mods
}

// VendorRoot locates the directory a Go build vendors dependency source into,
// or reports false when the tree has no Go module at all.
//
// It is found the same way enumeration finds its module list, so the two cannot
// disagree about where a vendored copy lives.
func VendorRoot(fsys fs.FS) (string, bool) {
	modFile, ok := findShallowest(fsys, "go.mod")
	if !ok {
		return "", false
	}
	return path.Join(path.Dir(modFile), "vendor"), true
}
