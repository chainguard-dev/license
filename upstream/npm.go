/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"context"
	"crypto/sha1" //nolint:gosec // older lockfiles record sha1 integrity; the algorithm is the lockfile's, not a choice made here.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"

	"chainguard.dev/license/component"
)

// NpmRegistry serves the immutable tarballs for published package versions.
const NpmRegistry = "https://registry.npmjs.org"

// NpmResolver retrieves published npm package content.
//
// npm is the one ecosystem here where the lockfile is a genuinely independent
// witness to the content. It records a Subresource Integrity hash written when
// the dependency was first installed, so comparing the registry's bytes against
// it verifies the two agree rather than just verifying the registry against
// itself. That is the same footing Go and Rust are on, and stronger than what
// PyPI or Maven Central can offer.
type NpmResolver struct {
	// opts are the caller-tunable bounds this resolver applies.
	opts   options
	client *http.Client
	base   string
}

// NewNpmResolver returns a resolver reading from the public registry.
func NewNpmResolver(client *http.Client, opts ...Option) *NpmResolver {
	return &NpmResolver{client: client, base: NpmRegistry, opts: newOptions(opts)}
}

// Ecosystem implements Resolver.
func (r *NpmResolver) Ecosystem() component.Ecosystem { return component.EcosystemNpm }

// Fetch implements Resolver, retrieving and verifying the package tarball.
func (r *NpmResolver) Fetch(ctx context.Context, c component.Component) (*Artifact, error) {
	if c.Name == "" || c.Version == "" {
		return nil, fmt.Errorf("npm: component needs both a name and a version, got %q@%q", c.Name, c.Version)
	}

	src, err := r.tarballURL(c.Name, c.Version)
	if err != nil {
		return nil, err
	}
	art, err := fetch(ctx, r.client, src, r.opts.maxArtifact)
	if err != nil {
		return nil, err
	}
	defer art.Close()

	body, err := art.Reader()
	if err != nil {
		return nil, err
	}
	// A tarball nests everything under a fixed directory, whatever the package
	// is called.
	fsys, err := tarGzFS(body, "package")
	if err != nil {
		return nil, fmt.Errorf("npm: expanding tarball for %s@%s: %w", c.Name, c.Version, err)
	}

	digest, err := integrityOf(c.Digest, art)
	if err != nil {
		return nil, fmt.Errorf("npm: %s@%s: %w", c.Name, c.Version, err)
	}

	return &Artifact{
		FS:         fsys,
		Digest:     digest,
		DigestAlgo: component.DigestNpmIntegrity,
		Matched:    c.Digest != "" && c.Digest == digest,
		Source:     src,
	}, nil
}

// tarballURL renders where the registry publishes a version's tarball. A scoped
// package keeps its scope in the path but not in the filename.
func (r *NpmResolver) tarballURL(name, version string) (string, error) {
	scope, rest, scoped := strings.Cut(name, "/")
	values := []string{name, version}
	if scoped {
		values = []string{scope, rest, version}
	}
	escaped, err := pathSegments(values...)
	if err != nil {
		return "", fmt.Errorf("npm: %s@%s: %w", name, version, err)
	}

	pathName, base := escaped[0], escaped[0]
	if scoped {
		pathName, base = escaped[0]+"/"+escaped[1], escaped[1]
	}
	return fmt.Sprintf("%s/%s/-/%s-%s.tgz", r.base, pathName, base, escaped[len(escaped)-1]), nil
}

// integrityOf renders the content's Subresource Integrity string in whatever
// algorithm the lockfile used, so the two are directly comparable.
//
// Matching the recorded algorithm rather than always using the strongest one is
// what makes the comparison possible at all: a lockfile written years ago
// records sha1, and hashing with sha512 would produce a value that cannot
// disagree or agree with it. Where nothing was recorded, sha512 is used, which
// is what npm writes today.
func integrityOf(recorded string, art *fetched) (string, error) {
	algo, _, found := strings.Cut(recorded, "-")
	if !found || recorded == "" {
		algo = "sha512"
	}
	var h hash.Hash
	switch algo {
	case "sha512":
		h = sha512.New()
	case "sha256":
		h = sha256.New()
	case "sha1":
		h = sha1.New() //nolint:gosec // reproducing what the lockfile recorded, not authenticating anything.
	default:
		return "", fmt.Errorf("unsupported integrity algorithm %q", algo)
	}
	r, err := art.Reader()
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hashing artifact: %w", err)
	}
	return algo + "-" + base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}
