/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"fmt"
	"io"
	"io/fs"
)

const (
	// maxManifestBytes bounds a manifest read into memory: a package.json, a
	// Cargo.toml, a pom.xml. These declare a handful of fields, and one far
	// past this bound is not a manifest.
	maxManifestBytes = 4 << 20

	// maxLockfileBytes bounds a lockfile read into memory. Lockfiles are
	// legitimately large - a package-lock.json for a real application runs to
	// several megabytes, and a go.sum for a wide dependency graph is not much
	// smaller - so the bound is looser than a manifest's while still being a
	// bound.
	maxLockfileBytes = 64 << 20
)

// readBounded reads a file, refusing one larger than limit.
//
// Every file read here comes from a tree somebody else wrote: a checkout of an
// upstream repository, an expanded archive, a build's own output. A manifest is
// small, so a caller has no reason to hold a large one in memory, and reading
// whatever it is handed would let one tree decide how much memory the process
// takes.
//
// The size is checked by reading one byte past the limit rather than by
// trusting Stat, because a filesystem is free to report a size that does not
// match what it then serves.
func readBounded(fsys fs.FS, name string, limit int64) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%q is larger than the %d byte limit", name, limit)
	}
	return data, nil
}
