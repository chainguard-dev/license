/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package evidence

import (
	"context"
	"io/fs"

	"chainguard.dev/license/component"
	"chainguard.dev/license/detect"
)

// Subject is what a bundle is collected about.
//
// The two trees answer different questions and neither substitutes for the
// other. The source tree is what the component's own licensing is read from.
// The installed trees are where the components that exist nowhere else are
// named: a Python application's resolved dependency versions do not exist until
// pip has run, and neither do the jars a Java package bundles.
type Subject interface {
	// Describe returns the subject's coordinates and what it already declares.
	Describe() Description
	// Source returns the tree the component was built from. An error is
	// recorded in the bundle as incomplete evidence rather than failing the
	// collection: the installed trees may still be readable, and half a bundle
	// with the gap named beats no bundle at all.
	Source(ctx context.Context) (fs.FS, error)
	// Installed returns the trees the build installed into. A subject with no
	// build output returns none, which is not an error - collecting evidence
	// about a tree that was never built is a supported way to run this.
	Installed(ctx context.Context) ([]component.Tree, error)
}

// Description is a subject's own account of itself.
type Description struct {
	// Package and Version are the coordinates of the thing being built.
	Package string `json:"package"`
	Version string `json:"version,omitempty"`
	// Source locates the upstream source and the patches applied to it, which
	// together identify the component the package is built from.
	Source component.Source `json:"source"`
	// Declared is what the build configuration says the licensing is. It is
	// recorded for comparison only: a declaration is a claim about content,
	// and the content is what a bundle carries.
	Declared []detect.Declaration `json:"declared,omitempty"`
	// Origin names where the description came from, such as the path of the
	// build configuration, so a surprising bundle can be traced back.
	Origin string `json:"origin,omitempty"`
}

// Trees is a Subject over filesystems the caller already holds.
//
// It is the subject for a caller that has done its own acquisition - an
// expanded archive, a test fixture, a directory already on disk - and for
// every test in this module, which is why no test here needs a real
// filesystem.
type Trees struct {
	Description Description
	// SourceFS is the tree the component was built from. A nil SourceFS is
	// recorded as unavailable source rather than as an empty tree.
	SourceFS fs.FS
	// InstalledFS are the trees the build installed into, if any.
	InstalledFS []component.Tree
}

var _ Subject = (*Trees)(nil)

// Describe implements Subject.
func (t *Trees) Describe() Description { return t.Description }

// Source implements Subject.
func (t *Trees) Source(context.Context) (fs.FS, error) {
	if t.SourceFS == nil {
		return nil, ErrNoSource
	}
	return t.SourceFS, nil
}

// Installed implements Subject.
func (t *Trees) Installed(context.Context) ([]component.Tree, error) {
	return t.InstalledFS, nil
}
