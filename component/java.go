/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/chainguard-dev/clog"
)

const (
	// maxJarBytes bounds how much of a jar is read. Only its metadata is
	// wanted, but a zip's index is at the end of the file, so the whole thing
	// has to be readable. A jar past this is shipping something other than Java
	// classes.
	maxJarBytes = 256 << 20
	// maxPomPropertiesBytes bounds one pom.properties. They are four short
	// lines.
	maxPomPropertiesBytes = 8 << 10
)

// MavenPURL renders Maven coordinates as a purl, where the groupId is the
// namespace and the artifactId is the name.
func MavenPURL(groupID, artifactID, version string) string {
	base := "pkg:maven/" + groupID + "/" + artifactID
	if version == "" {
		return base
	}
	return base + "@" + version
}

// MavenCoordinates splits the "group:artifact" name a Maven component carries.
// It is exported because a caller resolving one has to address the repository
// by its parts.
func MavenCoordinates(name string) (groupID, artifactID string, ok bool) {
	groupID, artifactID, ok = strings.Cut(name, ":")
	return groupID, artifactID, ok && groupID != "" && artifactID != ""
}

// enumerateJava lists the jars a package ships, as identities rather than
// resolved licenses.
//
// A jar records the coordinates it was published under in
// META-INF/maven/<groupId>/<artifactId>/pom.properties, written by Maven at
// build time. That is the only self-description in the format that maps cleanly
// onto a purl, so it is the only one read here: OSGi headers name a bundle
// rather than a groupId and an artifactId, and splitting one back into the
// other is guesswork that would mint identities nothing can resolve.
//
// A jar may declare several. Shaded and uber jars fold their dependencies in
// and keep each one's metadata, and every one of those genuinely ships, so each
// becomes a component.
func enumerateJava(ctx context.Context, trees []Tree, _ string) (out Enumeration) {
	var scanned, unidentified int
	for _, tree := range trees {
		for _, jarPath := range jarPaths(tree.FS) {
			scanned++
			coords, err := jarCoordinates(tree.FS, jarPath)
			if err != nil {
				clog.DebugContextf(ctx, "java: %s: %v", path.Join(tree.Name, jarPath), err)
				unidentified++
				continue
			}
			if len(coords) == 0 {
				unidentified++
				continue
			}
			for _, c := range coords {
				out.Components = append(out.Components, Component{
					PURL:           MavenPURL(c.groupID, c.artifactID, c.version),
					Name:           c.groupID + ":" + c.artifactID,
					Version:        c.version,
					Ecosystem:      EcosystemMaven,
					Kind:           KindEcosystem,
					DiscoveredFrom: path.Join(tree.Name, jarPath),
					Linkage:        LinkageBundled,
				})
			}
		}
	}

	if len(out.Components) > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("java: %d jar components enumerated from %d jars in the output tree", len(out.Components), scanned))
	}
	if unidentified > 0 {
		// Worth naming rather than dropping: a build's own jars land here
		// because Gradle writes no Maven metadata, and so do a handful of
		// published libraries. The first are covered by the package source, and
		// the second are a coverage gap, so this is reported as a failure
		// rather than a remark.
		out.Failures = append(out.Failures, Failure{
			Ecosystem: EcosystemMaven,
			Detail:    fmt.Sprintf("%d of %d jars carry no Maven coordinates", unidentified, scanned),
		})
	}
	return out
}

// jarPaths finds every jar in a tree, in lexical order so the result is stable.
func jarPaths(fsys fs.FS) []string {
	var out []string
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // an unreadable subtree is skipped, not fatal
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".jar") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// gav is a Maven coordinate triple.
type gav struct{ groupID, artifactID, version string }

// jarCoordinates reads every Maven coordinate a jar records.
func jarCoordinates(fsys fs.FS, p string) ([]gav, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// A zip is read by seeking to the index at its end, so the reader has to
	// support it. Files coming out of an apk or an in-memory tree do not always,
	// which is why the bytes are taken first.
	data, err := io.ReadAll(io.LimitReader(f, maxJarBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxJarBytes {
		return nil, fmt.Errorf("jar exceeds the %d byte limit", maxJarBytes)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("reading jar: %w", err)
	}

	var out []gav
	for _, e := range zr.File {
		if path.Base(e.Name) != "pom.properties" || !strings.HasPrefix(e.Name, "META-INF/maven/") {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			return nil, fmt.Errorf("opening %q: %w", e.Name, err)
		}
		coord, ok := readPomProperties(rc)
		rc.Close()
		if ok {
			out = append(out, coord)
		}
	}
	return out, nil
}

// readPomProperties parses the key=value coordinates Maven writes beside a
// jar's bundled pom.xml.
func readPomProperties(r io.Reader) (gav, bool) {
	var c gav
	sc := bufio.NewScanner(io.LimitReader(r, maxPomPropertiesBytes))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "groupId":
			c.groupID = strings.TrimSpace(value)
		case "artifactId":
			c.artifactID = strings.TrimSpace(value)
		case "version":
			c.version = strings.TrimSpace(value)
		}
	}
	return c, c.groupID != "" && c.artifactID != "" && c.version != ""
}
