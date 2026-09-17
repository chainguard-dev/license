/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/chainguard-dev/clog"
)

const (
	// maxMetadataHeaderBytes bounds how much of a METADATA file is read. The
	// fields wanted here are in its leading headers; everything past the blank
	// line is the project's long description, which is frequently a whole
	// README.
	maxMetadataHeaderBytes = 64 << 10
	// distInfoSuffix marks an installed distribution's metadata directory.
	distInfoSuffix = ".dist-info"
)

// pyNameSeparators is the run of characters PEP 503 collapses when comparing
// distribution names, so that "zope.interface", "zope_interface" and
// "zope-interface" are one component rather than three.
var pyNameSeparators = regexp.MustCompile(`[-_.]+`)

// pyPackagePrefix is the naming convention that turns a distribution into an
// apk: "cassandra-medusa" ships as "py3-cassandra-medusa", and its
// interpreter-versioned subpackages as "py3.11-cassandra-medusa".
var pyPackagePrefix = regexp.MustCompile(`^py3(\.[0-9]+)?-`)

// PyPIMetadataFiles are the names Python core metadata is written under: an
// installed distribution and a wheel use METADATA, a source distribution uses
// PKG-INFO. Both hold the same RFC 822-shaped fields.
var PyPIMetadataFiles = []string{"METADATA", "PKG-INFO"}

// NormalizePyPIName renders a distribution name in PEP 503 normalized form,
// which is what identifies it on the index.
//
// It is exported because a caller asking the index for a distribution has to
// ask for exactly the name the purl was keyed on; two spellings of one
// distribution would be two determinations of the same thing.
func NormalizePyPIName(s string) string {
	return strings.ToLower(pyNameSeparators.ReplaceAllString(strings.TrimSpace(s), "-"))
}

// PyPIPURL renders a distribution name and version as a purl. purl requires the
// pypi type to carry the normalized name, so the same distribution written
// three ways resolves to one determination.
func PyPIPURL(name, version string) string {
	normalized := NormalizePyPIName(name)
	if version == "" {
		return "pkg:pypi/" + normalized
	}
	return "pkg:pypi/" + normalized + "@" + version
}

// enumeratePython lists the Python distributions a package ships, as identities
// rather than resolved licenses.
//
// Python is why the installed tree has to be read at all. A Python
// application's dependencies are pip-installed into site-packages during the
// build, and the source tree names them only as loose requirements, if at all:
// the resolved versions exist nowhere until the build has run. Reading what was
// installed reports what actually ships rather than what was asked for.
//
// Only the coordinates are taken. The licensing is determined later from the
// distribution published under those coordinates, which is the copy every other
// package installing this dependency also gets.
func enumeratePython(ctx context.Context, trees []Tree, own string) (out Enumeration) {
	var unreadable, ownCount int
	for _, tree := range trees {
		for _, dir := range distInfoDirs(tree.FS) {
			metaPath := path.Join(dir, "METADATA")
			name, version, err := readDistMetadata(tree.FS, metaPath)
			if err != nil {
				clog.DebugContextf(ctx, "python: %s: %v", path.Join(tree.Name, metaPath), err)
				unreadable++
				continue
			}
			// The package's own project is installed alongside its dependencies
			// and is already covered by the source component, which is
			// determined from the source tree rather than from a release.
			if isOwnDistribution(name, own) {
				ownCount++
				continue
			}
			out.Components = append(out.Components, Component{
				PURL:           PyPIPURL(name, version),
				Name:           name,
				Version:        version,
				Ecosystem:      EcosystemPyPI,
				Kind:           KindEcosystem,
				DiscoveredFrom: path.Join(tree.Name, metaPath),
				Linkage:        LinkageBundled,
			})
		}
	}

	if len(out.Components) > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("python: %d installed distributions enumerated from the output tree", len(out.Components)))
	}
	if ownCount > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("python: %d installed distributions are the package's own project, covered by the package source", ownCount))
	}
	if unreadable > 0 {
		// A dist-info directory with no readable METADATA is a distribution
		// that ships and was not enumerated, which is a gap in the closure
		// rather than a remark about it.
		out.Failures = append(out.Failures, Failure{
			Ecosystem: EcosystemPyPI,
			Detail:    fmt.Sprintf("%d dist-info directories had no readable METADATA", unreadable),
		})
	}
	return out
}

// distInfoDirs finds every installed distribution's metadata directory.
//
// The whole tree is searched rather than a known interpreter path: a package
// that installs into a virtualenv puts site-packages somewhere of its own
// choosing, and several do. WalkDir visits in lexical order, so the result is
// stable across runs.
//
// The source tree's location rules deliberately do not apply. A distribution
// under setuptools/_vendor/ was vendored by setuptools, but it ships in the apk
// and its obligations are real, so it is a component like any other - which is
// also a distribution a lockfile-only scanner never sees.
func distInfoDirs(fsys fs.FS) []string {
	var dirs []string
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil //nolint:nilerr // an unreadable subtree is skipped, not fatal
		}
		if strings.HasSuffix(d.Name(), distInfoSuffix) {
			// Nothing below a dist-info directory is another distribution.
			dirs = append(dirs, p)
			return fs.SkipDir
		}
		return nil
	})
	return dirs
}

// ReadPyPIMetadata reads the core-metadata headers of a Python distribution.
//
// The format is RFC 822-shaped: headers, a blank line, then the long
// description. Only the headers are read - the description is frequently a
// whole README, and it can contain header-shaped lines that would otherwise be
// taken for metadata. Keys are lowercased, and the first value of a repeated
// key wins.
//
// It is exported because the same headers are read out of a published sdist or
// wheel as out of an installed tree.
func ReadPyPIMetadata(fsys fs.FS, p string) (map[string]string, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	headers := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(f, maxMetadataHeaderBytes))
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			break
		}
		// A folded continuation belongs to the previous header. None of the
		// fields read here is ever folded, so it is skipped rather than joined.
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if _, seen := headers[key]; !seen {
			headers[key] = strings.TrimSpace(value)
		}
	}
	return headers, nil
}

// maxDeclaredLicenseChars is the longest a declared license value may be before
// it is treated as pasted license text rather than an identifier. The longest
// real SPDX expression in the corpus is well under this.
const maxDeclaredLicenseChars = 120

// PyPIMetadataLicense reports the license a distribution declares in its core
// metadata headers, or empty when it declares nothing usable.
//
// License-Expression is preferred because PEP 639 defines it as an SPDX
// expression, so it means exactly one thing. The legacy License field is free
// text and is still the only one present in most of the corpus, but projects
// routinely paste an entire license text into it, so an implausibly long or
// multi-line value is ignored: the file it came from is classified anyway, and
// a paragraph recorded as a declared identifier is worse than no declaration.
//
// Trove classifiers are deliberately not read. They name a license family
// without a version ("License :: OSI Approved :: GNU General Public License
// (GPL)"), which is the ambiguity a declared expression exists to remove.
func PyPIMetadataLicense(headers map[string]string) string {
	if expr := strings.TrimSpace(headers["license-expression"]); expr != "" {
		return expr
	}
	legacy := strings.TrimSpace(headers["license"])
	if legacy == "" || len(legacy) > maxDeclaredLicenseChars || strings.ContainsAny(legacy, "\n\r") {
		return ""
	}
	return legacy
}

// readDistMetadata reads a distribution's name and version from its METADATA.
func readDistMetadata(fsys fs.FS, p string) (name, version string, err error) {
	headers, err := ReadPyPIMetadata(fsys, p)
	if err != nil {
		return "", "", err
	}
	if headers["name"] == "" {
		return "", "", fmt.Errorf("no Name header")
	}
	if headers["version"] == "" {
		return "", "", fmt.Errorf("no Version header for %q", headers["name"])
	}
	return headers["name"], headers["version"], nil
}

// isOwnDistribution reports whether an installed distribution is the project
// the package is built from.
//
// Matching is on the name alone: if the names agree, a version disagreement
// means the build installed a different revision of its own project, not that
// it depends on itself. The comparison is deliberately exact after
// normalization - a distribution wrongly treated as the package's own
// disappears from the result entirely, whereas one wrongly kept costs a
// duplicate determination that agrees with the source component.
func isOwnDistribution(dist, own string) bool {
	if own == "" {
		return false
	}
	return NormalizePyPIName(dist) == NormalizePyPIName(pyPackagePrefix.ReplaceAllString(own, ""))
}
