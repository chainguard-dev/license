/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/mod/module"

	"chainguard.dev/license/component"
)

// The checksum databases each ecosystem publishes independently of its
// artifacts.
const (
	// SumGolangOrg is the Go checksum database. Its records are what "go mod
	// verify" checks against, and they are transparency-log backed.
	SumGolangOrg = "https://sum.golang.org"
	// CratesIOAPI serves crates.io's own record of a version's checksum.
	CratesIOAPI = "https://crates.io"
	// MavenCentralChecksums is where Central publishes a checksum beside every
	// artifact.
	MavenCentralChecksums = MavenCentral
)

// ChecksumResult is what an ecosystem's checksum database says about a
// component version.
type ChecksumResult struct {
	// Recorded is the digest the database holds for this version, empty when
	// the database has no record of it.
	Recorded string
	// Matched reports that Recorded equals the digest the caller asked about.
	Matched bool
	// Source is the URL the record came from, so a result can be re-checked by
	// hand.
	Source string
}

// Checksums queries the checksum databases the ecosystems publish.
type Checksums struct {
	client *http.Client
	// The database endpoints, held rather than referenced as constants so a
	// caller behind a mirror can point them elsewhere and so tests can serve
	// them locally.
	goSumDB, cratesAPI, mavenBase string
}

// NewChecksums returns a client reading from the public databases.
func NewChecksums(client *http.Client) *Checksums {
	return &Checksums{
		client:    client,
		goSumDB:   SumGolangOrg,
		cratesAPI: CratesIOAPI,
		mavenBase: MavenCentralChecksums,
	}
}

// Lookup asks the ecosystem's own checksum database what digest it recorded for
// a component version, and whether the digest the caller holds matches.
//
// This is a second, independent witness, which is the whole reason the check
// exists. A digest computed from bytes a registry served says only that the
// download arrived intact; the same registry could serve different bytes
// tomorrow. A digest that also matches what the ecosystem's own database
// recorded says these are the bytes the ecosystem published, so an answer drawn
// from them is safe to share with every package depending on that version.
//
// What a match does not say: anything about licensing, and nothing about
// provenance beyond content identity. Each caller decides what its own policy
// requires of the result.
//
// An ecosystem with no independent database returns ErrUnsupported. PyPI and
// npm are in that position: their digests come from the same service as the
// bytes, so asking again corroborates nothing.
func (c *Checksums) Lookup(ctx context.Context, comp component.Component) (*ChecksumResult, error) {
	switch comp.Ecosystem {
	case component.EcosystemGo:
		return c.goSum(ctx, comp)
	case component.EcosystemCargo:
		return c.cargoSum(ctx, comp)
	case component.EcosystemMaven:
		return c.mavenSum(ctx, comp)
	default:
		return nil, fmt.Errorf("%w: %s has no checksum database independent of its artifacts", ErrUnsupported, comp.Ecosystem)
	}
}

// goSum reads the module's record from the Go checksum database.
//
// The lookup endpoint returns the signed tree head along with the module's
// hashes; only the module's own zip hash is read here. Verifying the
// transparency-log signature is a stronger check that belongs to a caller
// holding the log's public key, and is deliberately not attempted: reporting a
// match as if it had been signature-verified would overstate what was done.
func (c *Checksums) goSum(ctx context.Context, comp component.Component) (*ChecksumResult, error) {
	escapedPath, err := module.EscapePath(comp.Name)
	if err != nil {
		return nil, fmt.Errorf("go: escaping module path %q: %w", comp.Name, err)
	}
	escapedVersion, err := module.EscapeVersion(comp.Version)
	if err != nil {
		return nil, fmt.Errorf("go: escaping version %q: %w", comp.Version, err)
	}

	src := fmt.Sprintf("%s/lookup/%s@%s", c.goSumDB, escapedPath, escapedVersion)
	body, err := fetchBytes(ctx, c.client, src)
	if err != nil {
		return nil, err
	}

	// Each record line is "<module> <version> <hash>", with the "/go.mod" line
	// covering the go.mod file alone rather than the content.
	want := comp.Name + " " + comp.Version
	for line := range strings.SplitSeq(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || strings.HasSuffix(fields[1], "/go.mod") {
			continue
		}
		if fields[0]+" "+fields[1] != want {
			continue
		}
		return &ChecksumResult{
			Recorded: fields[2],
			Matched:  comp.Digest != "" && comp.Digest == fields[2],
			Source:   src,
		}, nil
	}
	return &ChecksumResult{Source: src}, nil
}

// cargoSum reads the crate version's checksum from the crates.io API.
func (c *Checksums) cargoSum(ctx context.Context, comp component.Component) (*ChecksumResult, error) {
	segments, err := pathSegments(comp.Name, comp.Version)
	if err != nil {
		return nil, fmt.Errorf("cargo: %s@%s: %w", comp.Name, comp.Version, err)
	}
	src := fmt.Sprintf("%s/api/v1/crates/%s/%s", c.cratesAPI, segments[0], segments[1])
	body, err := fetchBytes(ctx, c.client, src)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Version struct {
			Checksum string `json:"checksum"`
		} `json:"version"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("cargo: parsing the crates.io record for %s@%s: %w", comp.Name, comp.Version, err)
	}
	return &ChecksumResult{
		Recorded: doc.Version.Checksum,
		Matched:  comp.Digest != "" && comp.Digest == doc.Version.Checksum,
		Source:   src,
	}, nil
}

// mavenSum reads the sha1 Central publishes beside the artifact.
//
// This is the weakest of the three: the checksum sits on the same host as the
// jar rather than in a separate database. It is reported anyway because it is
// what Maven itself verifies, and because a caller comparing a locally bundled
// jar against Central is comparing against something it did not produce.
func (c *Checksums) mavenSum(ctx context.Context, comp component.Component) (*ChecksumResult, error) {
	groupID, artifactID, ok := component.MavenCoordinates(comp.Name)
	if !ok {
		return nil, fmt.Errorf("maven: component needs group:artifact, got %q", comp.Name)
	}
	// Coordinates come out of a POM the registry served or a jar's
	// pom.properties, so they are refused rather than interpolated: a version
	// carrying ".." walks the path to a different artifact, and this would
	// report that artifact's digest as the one Central recorded for this one.
	values := append(strings.Split(groupID, "."), artifactID, comp.Version)
	escaped, err := pathSegments(values...)
	if err != nil {
		return nil, fmt.Errorf("maven: %s:%s: %w", comp.Name, comp.Version, err)
	}
	group := escaped[:len(escaped)-2]
	artifact, version := escaped[len(escaped)-2], escaped[len(escaped)-1]
	src := fmt.Sprintf("%s/%s/%s/%s/%s-%s.jar.sha1",
		c.mavenBase, strings.Join(group, "/"), artifact, version, artifact, version)
	body, err := fetchBytes(ctx, c.client, src)
	if err != nil {
		return nil, err
	}
	// The file is the hex digest, sometimes followed by a filename.
	recorded := ""
	if fields := strings.Fields(string(body)); len(fields) > 0 {
		recorded = strings.ToLower(fields[0])
	}
	return &ChecksumResult{
		Recorded: recorded,
		Matched:  recorded != "" && recorded == strings.ToLower(comp.Digest),
		Source:   src,
	}, nil
}
