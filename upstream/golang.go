/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"

	"chainguard.dev/license/component"
)

// GoProxy is the module proxy artifacts are fetched from. The proxy serves
// immutable, checksum-verifiable zips for every published version.
const GoProxy = "https://proxy.golang.org"

// GoResolver retrieves published Go module content.
//
// Go is the ecosystem with the largest license gap and the one where metadata
// cannot help at all: there is no license field in go.mod, so nothing short of
// reading the module's own files can answer the question. The h1 hash recorded
// in go.sum identifies exactly the bytes the proxy serves, which is what makes
// a determination drawn from them shareable with every package depending on
// that version.
type GoResolver struct {
	// opts are the caller-tunable bounds this resolver applies.
	opts   options
	client *http.Client
	proxy  string
}

// NewGoResolver returns a resolver reading from the default module proxy.
func NewGoResolver(client *http.Client, opts ...Option) *GoResolver {
	return &GoResolver{client: client, proxy: GoProxy, opts: newOptions(opts)}
}

// Ecosystem implements Resolver.
func (r *GoResolver) Ecosystem() component.Ecosystem { return component.EcosystemGo }

// Fetch implements Resolver, retrieving and hashing the module zip.
func (r *GoResolver) Fetch(ctx context.Context, c component.Component) (*Artifact, error) {
	if c.Name == "" || c.Version == "" {
		return nil, fmt.Errorf("go: component needs both a module path and a version, got %q@%q", c.Name, c.Version)
	}

	// Module paths are case-sensitive but filesystems are not, so the proxy
	// protocol escapes uppercase letters. Getting this wrong silently fetches
	// a different module.
	escapedPath, err := module.EscapePath(c.Name)
	if err != nil {
		return nil, fmt.Errorf("go: escaping module path %q: %w", c.Name, err)
	}
	escapedVersion, err := module.EscapeVersion(c.Version)
	if err != nil {
		return nil, fmt.Errorf("go: escaping version %q: %w", c.Version, err)
	}

	src := fmt.Sprintf("%s/%s/@v/%s.zip", r.proxy, escapedPath, escapedVersion)
	art, err := fetch(ctx, r.client, src, r.opts.maxArtifact)
	if err != nil {
		return nil, err
	}
	defer art.Close()

	// dirhash works over a file on disk, which the download already is, so
	// nothing is staged twice.
	digest, err := dirhash.HashZip(art.Path(), dirhash.Hash1)
	if err != nil {
		return nil, fmt.Errorf("go: hashing module zip for %s@%s: %w", c.Name, c.Version, err)
	}

	fsys, err := zipFS(art.ReaderAt(), art.Size(), c.Name+"@"+c.Version)
	if err != nil {
		return nil, fmt.Errorf("go: expanding module zip for %s@%s: %w", c.Name, c.Version, err)
	}

	return &Artifact{
		FS:         fsys,
		Digest:     digest,
		DigestAlgo: component.DigestGoModule,
		Matched:    c.Digest != "" && c.Digest == digest,
		Source:     src,
	}, nil
}
