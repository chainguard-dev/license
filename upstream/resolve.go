/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"context"
	"fmt"
	"net/http"

	"chainguard.dev/license/component"
)

// Resolver retrieves the published content of components in one ecosystem.
type Resolver interface {
	// Ecosystem is the purl type this resolver handles.
	Ecosystem() component.Ecosystem
	// Fetch retrieves the component's published artifact. A component whose
	// content is permanently gone from the registry returns an error wrapping
	// ErrGone; anything else the caller may retry.
	Fetch(ctx context.Context, c component.Component) (*Artifact, error)
}

// Option tunes a resolver for the environment it runs in.
type Option func(*options)

// options are the tunable bounds a resolver applies. The zero value means the
// package defaults.
type options struct{ maxArtifact int64 }

func newOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// WithMaxArtifactBytes bounds one staged artifact, in place of
// MaxArtifactBytes.
//
// A caller sets it when its temporary directory is tighter than the default
// assumes, or when it fetches enough artifacts at once that the product is
// what matters: the bound times the number in flight is what has to fit, and
// only the caller knows the second term.
func WithMaxArtifactBytes(n int64) Option {
	return func(o *options) { o.maxArtifact = n }
}

// Set dispatches components to the resolver for their ecosystem.
type Set struct {
	byEcosystem map[component.Ecosystem]Resolver
}

// NewSet builds a resolver set. A later resolver for the same ecosystem
// replaces an earlier one, so a caller can substitute one without rebuilding
// the rest.
func NewSet(resolvers ...Resolver) *Set {
	s := &Set{byEcosystem: make(map[component.Ecosystem]Resolver, len(resolvers))}
	for _, r := range resolvers {
		s.byEcosystem[r.Ecosystem()] = r
	}
	return s
}

// DefaultSet returns the resolver set for every ecosystem with content
// retrieval implemented, reading from the public registries.
func DefaultSet(client *http.Client, opts ...Option) *Set {
	return NewSet(
		NewGoResolver(client, opts...),
		NewCargoResolver(client, opts...),
		NewPyPIResolver(client, opts...),
		NewMavenResolver(client, opts...),
		NewNpmResolver(client, opts...),
	)
}

// Ecosystems lists the ecosystems the set can retrieve content for. A caller
// measuring coverage needs to distinguish a component nobody looked at from one
// this module cannot yet fetch.
func (s *Set) Ecosystems() []component.Ecosystem {
	out := make([]component.Ecosystem, 0, len(s.byEcosystem))
	for e := range s.byEcosystem {
		out = append(out, e)
	}
	return out
}

// Fetch retrieves a component's content, or reports ErrUnsupported when its
// ecosystem has no resolver.
func (s *Set) Fetch(ctx context.Context, c component.Component) (*Artifact, error) {
	r, ok := s.byEcosystem[c.Ecosystem]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, c.Ecosystem)
	}
	return r.Fetch(ctx, c)
}
