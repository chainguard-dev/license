/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"cmp"
	"context"
	"crypto/sha1" //nolint:gosec // Maven Central publishes sha1 checksums; the algorithm is theirs, not a choice made here.
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing/fstest"

	"chainguard.dev/license/component"
)

// MavenCentral serves the released artifacts for published Maven coordinates.
const MavenCentral = "https://repo1.maven.org/maven2"

// MavenResolver retrieves published Java artifact content.
//
// Java differs from the other ecosystems in where its licensing lives. Only 44
// of the 109 jars in a representative package carry a license file at all, so
// the jar is a weak source of a conclusion; the POM's <licenses> block is the
// strong one. That block is also frequently inherited: of the 65 POMs in that
// same package, 29 declare licenses directly and 36 declare them only through a
// <parent>, so following the chain is most of the coverage rather than a
// refinement of it.
//
// Both are fetched. The jar supplies whatever license files it ships, and the
// POM chain supplies the declaration, written into the returned filesystem so
// the declared-license reader finds it the same way it finds any other manifest.
type MavenResolver struct {
	// opts are the caller-tunable bounds this resolver applies.
	opts   options
	client *http.Client
	base   string
}

// NewMavenResolver returns a resolver reading from Maven Central.
func NewMavenResolver(client *http.Client, opts ...Option) *MavenResolver {
	return &MavenResolver{client: client, base: MavenCentral, opts: newOptions(opts)}
}

// Ecosystem implements Resolver.
func (r *MavenResolver) Ecosystem() component.Ecosystem { return component.EcosystemMaven }

// Fetch implements Resolver, retrieving the POM chain and the jar.
func (r *MavenResolver) Fetch(ctx context.Context, c component.Component) (*Artifact, error) {
	groupID, artifactID, ok := component.MavenCoordinates(c.Name)
	if !ok || c.Version == "" {
		return nil, fmt.Errorf("maven: component needs group:artifact and a version, got %q@%q", c.Name, c.Version)
	}

	// A POM chain the registry does not hold is tolerated the same way a
	// missing jar is: the jar still ships license files, and refusing the whole
	// component would write off one that has them. Anything other than a gone
	// POM is a real failure and reaches the caller, which can retry it. When
	// the jar turns out to be gone as well, the component is gone and the
	// error below reports that.
	poms, err := r.pomChain(ctx, gav{groupID, artifactID, c.Version})
	pomGone := err != nil
	if pomGone && !errors.Is(err, ErrGone) {
		return nil, err
	}

	// The jar is optional. A packaging=pom artifact has none by definition, and
	// an aar or a bundle is published under another extension; the declaration
	// still resolves, which is the part Java most depends on.
	pomSource, err := r.artifactURL(gav{groupID, artifactID, c.Version}, "pom")
	if err != nil {
		return nil, err
	}
	jarURL, err := r.artifactURL(gav{groupID, artifactID, c.Version}, "jar")
	if err != nil {
		return nil, err
	}
	var notes []string
	fsys, digest, matched, err := r.jarContent(ctx, jarURL)
	if err != nil {
		if !errors.Is(err, ErrGone) {
			return nil, err
		}
		if pomGone {
			// Neither half exists, so these coordinates name nothing the
			// registry holds. Retrying will not change that.
			return nil, fmt.Errorf("maven: %s:%s has neither a POM nor a jar: %w", c.Name, c.Version, ErrGone)
		}
		// A component with no jar is not a failure to resolve: its declaration
		// is still there, and for Java that is the stronger half of the answer.
		fsys = fstest.MapFS{}
		notes = append(notes, "no jar published for these coordinates; the declaration resolves from the POM chain alone")
	}
	if len(poms) == 0 {
		notes = append(notes, "no POM could be fetched; the licensing rests on what the jar ships")
	}

	for depth, pom := range poms {
		fsys[component.POMName(depth)] = &fstest.MapFile{Data: pom}
	}

	return &Artifact{
		FS:         fsys,
		Digest:     digest,
		DigestAlgo: component.DigestSHA1,
		Matched:    matched,
		Source:     pomSource,
		Notes:      notes,
	}, nil
}

// pomChain retrieves a POM and its ancestors, nearest first, stopping as soon as
// one declares a license because nothing further up can override it.
func (r *MavenResolver) pomChain(ctx context.Context, coords gav) ([][]byte, error) {
	var chain [][]byte
	seen := make(map[gav]struct{}, component.MaxPOMAncestry)
	for range component.MaxPOMAncestry {
		if _, repeated := seen[coords]; repeated {
			break
		}
		seen[coords] = struct{}{}

		pomURL, err := r.artifactURL(coords, "pom")
		if err != nil {
			// Coordinates a POM named that cannot be turned into a URL are a
			// gap in the declaration, handled the same way as an ancestor the
			// registry does not hold.
			if len(chain) > 0 {
				break
			}
			return nil, err
		}

		body, err := fetchBytes(ctx, r.client, pomURL)
		if err != nil {
			// An ancestor the registry does not hold is a gap in the
			// declaration, and what was already fetched still holds. Any other
			// failure is reported: a 5xx or a stall on the ancestor that
			// declares the license would otherwise resolve the component as
			// declaring nothing, with no error for the caller to retry and no
			// record that anything went wrong.
			if errors.Is(err, ErrGone) && len(chain) > 0 {
				break
			}
			return nil, err
		}
		chain = append(chain, body)

		var doc pomDoc
		if xml.Unmarshal(body, &doc) != nil {
			break
		}
		if doc.declaresLicense() {
			break
		}
		parent, ok := doc.parentCoords(coords)
		if !ok {
			break
		}
		coords = parent
	}
	return chain, nil
}

// jarContent retrieves the jar and verifies it against the checksum published
// beside it.
func (r *MavenResolver) jarContent(ctx context.Context, jarURL string) (fstest.MapFS, string, bool, error) {
	art, err := fetch(ctx, r.client, jarURL, r.opts.maxArtifact)
	if err != nil {
		return nil, "", false, err
	}
	defer art.Close()

	digest, err := art.Digest(sha1.New()) //nolint:gosec // matching Maven Central's published checksum, not authenticating anything.
	if err != nil {
		return nil, "", false, fmt.Errorf("maven: %s: %w", jarURL, err)
	}

	// A jar is a zip with no wrapping directory.
	fsys, err := zipFS(art.ReaderAt(), art.Size(), "")
	if err != nil {
		return nil, "", false, fmt.Errorf("maven: expanding %s: %w", jarURL, err)
	}

	// Central publishes the checksum as a sibling file. Its absence leaves the
	// content unverified rather than unusable.
	expected := ""
	if body, err := fetchBytes(ctx, r.client, jarURL+".sha1"); err == nil {
		// The file is the hex digest, sometimes followed by a filename.
		if fields := strings.Fields(string(body)); len(fields) > 0 {
			expected = strings.ToLower(fields[0])
		}
	}
	return fsys, digest, expected != "" && expected == digest, nil
}

// artifactURL renders the repository layout: the group's dots become path
// separators, and the file is named for the artifact and version.
//
// The group is split before its parts are checked, because the dots are what
// turn one coordinate into several path segments: a groupId of "org..example"
// renders an empty segment, which collapses the path rather than naming
// anything in it. The traversal forms reach the path through artifactId and
// version instead, which are single segments and are checked as they stand.
func (r *MavenResolver) artifactURL(coords gav, ext string) (string, error) {
	values := strings.Split(coords.groupID, ".")
	values = append(values, coords.artifactID, coords.version)
	escaped, err := pathSegments(values...)
	if err != nil {
		return "", fmt.Errorf("maven: %s:%s:%s: %w", coords.groupID, coords.artifactID, coords.version, err)
	}

	group := escaped[:len(escaped)-2]
	artifact, version := escaped[len(escaped)-2], escaped[len(escaped)-1]
	return fmt.Sprintf("%s/%s/%s/%s/%s-%s.%s",
		r.base,
		strings.Join(group, "/"),
		artifact,
		version,
		artifact,
		version,
		ext), nil
}

// gav is a Maven coordinate triple.
type gav struct{ groupID, artifactID, version string }

// pomDoc is the part of a POM that bears on licensing and inheritance.
type pomDoc struct {
	Licenses struct {
		License []struct {
			Name string `xml:"name"`
			URL  string `xml:"url"`
		} `xml:"license"`
	} `xml:"licenses"`
	Parent struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"parent"`
}

// declaresLicense reports whether the POM names a license itself.
func (d pomDoc) declaresLicense() bool {
	for _, l := range d.Licenses.License {
		if strings.TrimSpace(l.Name) != "" || strings.TrimSpace(l.URL) != "" {
			return true
		}
	}
	return false
}

// parentCoords resolves the parent's coordinates, inheriting the child's group
// and version where the POM leaves them implicit.
func (d pomDoc) parentCoords(child gav) (gav, bool) {
	if strings.TrimSpace(d.Parent.ArtifactID) == "" {
		return gav{}, false
	}
	parent := gav{
		groupID:    cmp.Or(strings.TrimSpace(d.Parent.GroupID), child.groupID),
		artifactID: strings.TrimSpace(d.Parent.ArtifactID),
		version:    cmp.Or(strings.TrimSpace(d.Parent.Version), child.version),
	}
	if parent.groupID == "" || parent.version == "" {
		return gav{}, false
	}
	return parent, true
}
