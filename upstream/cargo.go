/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"

	"chainguard.dev/license/component"
)

// CratesIO serves the immutable .crate archives for published crate versions.
const CratesIO = "https://static.crates.io"

// CargoResolver retrieves published crate content.
//
// Cargo.lock records a crate's name, version and sha256 checksum but no
// license: the license field lives in the crate's Cargo.toml, which the
// lockfile does not contain. Fetching the .crate archive recovers both - the
// declared license from its Cargo.toml, and the concluded license from the
// license files it ships.
type CargoResolver struct {
	// opts are the caller-tunable bounds this resolver applies.
	opts   options
	client *http.Client
	base   string
}

// NewCargoResolver returns a resolver reading from crates.io.
func NewCargoResolver(client *http.Client, opts ...Option) *CargoResolver {
	return &CargoResolver{client: client, base: CratesIO, opts: newOptions(opts)}
}

// Ecosystem implements Resolver.
func (r *CargoResolver) Ecosystem() component.Ecosystem { return component.EcosystemCargo }

// Fetch implements Resolver, retrieving and hashing the .crate archive.
func (r *CargoResolver) Fetch(ctx context.Context, c component.Component) (*Artifact, error) {
	if c.Name == "" || c.Version == "" {
		return nil, fmt.Errorf("cargo: component needs both a name and a version, got %q@%q", c.Name, c.Version)
	}

	segments, err := pathSegments(c.Name, c.Version)
	if err != nil {
		return nil, fmt.Errorf("cargo: %s@%s: %w", c.Name, c.Version, err)
	}
	src := fmt.Sprintf("%s/crates/%s/%s-%s.crate", r.base, segments[0], segments[0], segments[1])
	art, err := fetch(ctx, r.client, src, r.opts.maxArtifact)
	if err != nil {
		return nil, err
	}
	defer art.Close()

	digest, err := art.Digest(sha256.New())
	if err != nil {
		return nil, fmt.Errorf("cargo: %s@%s: %w", c.Name, c.Version, err)
	}

	body, err := art.Reader()
	if err != nil {
		return nil, err
	}
	fsys, err := tarGzFS(body, c.Name+"-"+c.Version)
	if err != nil {
		return nil, fmt.Errorf("cargo: expanding crate archive for %s@%s: %w", c.Name, c.Version, err)
	}

	return &Artifact{
		FS:         fsys,
		Digest:     digest,
		DigestAlgo: component.DigestSHA256,
		Matched:    c.Digest != "" && c.Digest == digest,
		Source:     src,
	}, nil
}
