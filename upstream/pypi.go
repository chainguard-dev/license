/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing/fstest"

	"chainguard.dev/license/component"
)

// PyPI serves the index metadata that names a release's files and their hashes.
// The files themselves live on files.pythonhosted.org, which the index links to.
const PyPI = "https://pypi.org"

// PyPIResolver retrieves published Python distribution content.
//
// Python components are enumerated from what the build installed, which records
// a name and a version but no hash: an installed tree is unpacked files, not the
// archive they came from. The index supplies both the archive and the hash it
// recorded for it, so the determination is keyed to the release every other
// package installing this dependency also gets, rather than to one rebuild.
type PyPIResolver struct {
	// opts are the caller-tunable bounds this resolver applies.
	opts   options
	client *http.Client
	base   string
}

// NewPyPIResolver returns a resolver reading from the public index.
func NewPyPIResolver(client *http.Client, opts ...Option) *PyPIResolver {
	return &PyPIResolver{client: client, base: PyPI, opts: newOptions(opts)}
}

// Ecosystem implements Resolver.
func (r *PyPIResolver) Ecosystem() component.Ecosystem { return component.EcosystemPyPI }

// Fetch implements Resolver, retrieving a release's archive and verifying it
// against the hash the index recorded.
func (r *PyPIResolver) Fetch(ctx context.Context, c component.Component) (*Artifact, error) {
	if c.Name == "" || c.Version == "" {
		return nil, fmt.Errorf("pypi: component needs both a name and a version, got %q@%q", c.Name, c.Version)
	}

	// The index accepts any spelling of a name and redirects, but asking for the
	// normalized one avoids the redirect and matches the purl we keyed on.
	segments, err := pathSegments(component.NormalizePyPIName(c.Name), c.Version)
	if err != nil {
		return nil, fmt.Errorf("pypi: %s@%s: %w", c.Name, c.Version, err)
	}
	src := fmt.Sprintf("%s/pypi/%s/%s/json", r.base, segments[0], segments[1])
	body, err := fetchBytes(ctx, r.client, src)
	if err != nil {
		return nil, err
	}

	var release pypiRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, fmt.Errorf("pypi: parsing index metadata for %s@%s: %w", c.Name, c.Version, err)
	}
	file, ok := release.preferred()
	if !ok {
		// A release with an index entry but no downloadable file is not coming
		// back: the files were removed and the version was left in place.
		return nil, fmt.Errorf("%w: %s@%s has no downloadable archive", ErrGone, c.Name, c.Version)
	}

	art, err := fetch(ctx, r.client, file.URL, r.opts.maxArtifact)
	if err != nil {
		return nil, err
	}
	defer art.Close()

	digest, err := art.Digest(sha256.New())
	if err != nil {
		return nil, fmt.Errorf("pypi: %s@%s: %w", c.Name, c.Version, err)
	}

	fsys, err := file.expand(art)
	if err != nil {
		return nil, fmt.Errorf("pypi: expanding %s for %s@%s: %w", file.Filename, c.Name, c.Version, err)
	}

	return &Artifact{
		FS:         fsys,
		Digest:     digest,
		DigestAlgo: component.DigestSHA256,
		// Unlike a lockfile digest, the expected hash comes from the same index
		// as the bytes, so this establishes that the archive arrived intact and
		// is the file the index names - not that an independent witness agrees.
		Matched: file.Digests.SHA256 != "" && file.Digests.SHA256 == digest,
		Source:  file.URL,
	}, nil
}

// pypiRelease is the part of the index's release metadata that names the files
// published for one version.
type pypiRelease struct {
	URLs []pypiFile `json:"urls"`
}

// pypiFile is one published archive.
type pypiFile struct {
	Filename    string `json:"filename"`
	URL         string `json:"url"`
	PackageType string `json:"packagetype"`
	Size        int64  `json:"size"`
	Digests     struct {
		SHA256 string `json:"sha256"`
	} `json:"digests"`
}

// preferred picks the archive to determine the license from.
//
// A source distribution is preferred: it carries the project's LICENSE, its
// README and its pyproject.toml at the root, which is what the classification
// and relationship readers expect to find. A wheel is the fallback, since many
// projects publish nothing else; it carries the same declared metadata under
// .dist-info, and PEP 639 wheels carry their license files there too.
//
// Among wheels the smallest is taken. Wheels of one release differ only in
// their compiled extensions, never in their licensing, and a pure-Python wheel
// avoids downloading a hundred megabytes of platform binaries to read a LICENSE.
func (r pypiRelease) preferred() (pypiFile, bool) {
	var wheel pypiFile
	var found bool
	for _, f := range r.URLs {
		switch {
		case f.PackageType == "sdist":
			return f, true
		case f.isWheel() && (!found || f.smallerThan(wheel)):
			wheel, found = f, true
		}
	}
	return wheel, found
}

// smallerThan orders wheels by size, falling back to the filename so that two
// wheels of equal size always order the same way and the bundle stays
// reproducible.
func (f pypiFile) smallerThan(other pypiFile) bool {
	if f.Size != other.Size {
		return f.Size < other.Size
	}
	return f.Filename < other.Filename
}

// isWheel reports whether the file is a wheel, by the index's own type rather
// than by extension.
func (f pypiFile) isWheel() bool {
	return f.PackageType == "bdist_wheel" || strings.HasSuffix(f.Filename, ".whl")
}

// expand reads the archive into a filesystem, stripping the directory a source
// distribution nests its contents under.
//
// The prefix is derived from the filename the index published rather than from
// the component's name, because an sdist keeps the project's own spelling of
// itself: "zope.interface-8.0.1" and "Django-5.0", not the normalized purl name.
func (f pypiFile) expand(art *fetched) (fstest.MapFS, error) {
	if f.isWheel() {
		// A wheel has no wrapping directory; its contents sit at the root.
		return zipFS(art.ReaderAt(), art.Size(), "")
	}
	switch {
	case strings.HasSuffix(f.Filename, ".tar.gz"):
		body, err := art.Reader()
		if err != nil {
			return nil, err
		}
		return tarGzFS(body, strings.TrimSuffix(f.Filename, ".tar.gz"))
	case strings.HasSuffix(f.Filename, ".zip"):
		return zipFS(art.ReaderAt(), art.Size(), strings.TrimSuffix(f.Filename, ".zip"))
	}
	return nil, fmt.Errorf("unsupported archive format %q", f.Filename)
}
