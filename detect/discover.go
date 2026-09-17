/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// The license-file name patterns and weights in this file are adapted from the
// Licensee project (https://github.com/licensee/licensee),
// Copyright (c) 2014-2021 Ben Balter and Licensee contributors, MIT licensed.

package detect

import (
	"cmp"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
)

var (
	preferredExtRe = regexp.MustCompile(`\.(?:md|markdown|txt|html)$`)
	anyExtRe       = regexp.MustCompile(`(\.[^./]+$)`)
	licenseRe      = regexp.MustCompile(`(?i)(un)?licen[sc]e`)
	copyingRe      = regexp.MustCompile(`(?i)copy(ing|right)`)
	oflRe          = regexp.MustCompile(`(?i)ofl`)
	patentsRe      = regexp.MustCompile(`(?i)patents`)

	// filenameWeights scores how likely a filename is to hold the component's
	// own license text; higher weights are more canonical names.
	//
	// This is the shared license-filename table. Changing it changes which
	// files are discovered, and therefore the license-content hash of every
	// component whose selected files change - which is intended, because a
	// determination that missed a license file rested on incomplete evidence
	// and should be reached again.
	filenameWeights = map[*regexp.Regexp]float64{
		regexp.MustCompile(`(?i)^` + licenseRe.String() + `$`):                                       1.00, // LICENSE
		regexp.MustCompile(`(?i)^` + licenseRe.String() + preferredExtRe.String() + `$`):             0.95, // LICENSE.md
		regexp.MustCompile(`(?i)^` + copyingRe.String() + `$`):                                       0.90, // COPYING
		regexp.MustCompile(`(?i)^` + copyingRe.String() + preferredExtRe.String() + `$`):             0.85, // COPYING.md
		regexp.MustCompile(`(?i)^` + licenseRe.String() + anyExtRe.String() + `$`):                   0.80, // LICENSE.textile
		regexp.MustCompile(`(?i)^` + copyingRe.String() + anyExtRe.String() + `$`):                   0.75, // COPYING.textile
		regexp.MustCompile(`(?i)^` + licenseRe.String() + `[-_][^.]*` + anyExtRe.String() + `?$`):    0.70, // LICENSE-MIT
		regexp.MustCompile(`(?i)^` + copyingRe.String() + `[-_][^.]*` + anyExtRe.String() + `?$`):    0.65, // COPYING-MIT
		regexp.MustCompile(`(?i)^\w+[-_]` + licenseRe.String() + `[^.]*` + anyExtRe.String() + `?$`): 0.60, // MIT-LICENSE
		regexp.MustCompile(`(?i)^\w+[-_]` + copyingRe.String() + `[^.]*` + anyExtRe.String() + `?$`): 0.55, // MIT-COPYING
		regexp.MustCompile(`(?i)^` + oflRe.String() + preferredExtRe.String()):                       0.50, // OFL.md
		regexp.MustCompile(`(?i)^` + oflRe.String() + anyExtRe.String()):                             0.45, // OFL.textile
		regexp.MustCompile(`(?i)^` + oflRe.String() + `$`):                                           0.40, // OFL
		regexp.MustCompile(`(?i)^` + patentsRe.String() + `$`):                                       0.35, // PATENTS
		regexp.MustCompile(`(?i)^` + patentsRe.String() + anyExtRe.String() + `$`):                   0.30, // PATENTS.txt
	}

	// ignoredExtensions are extensions whose files carry license-like names but
	// hold code or metadata rather than license text, as license.go and
	// LICENSE.spdx do.
	ignoredExtensions = []string{".xml", ".go", ".gemspec", ".spdx", ".header"}
)

// RootWeightBonus is added to a file in the component root, so that the
// project's own license outranks every file below it however the two are named.
const RootWeightBonus = 0.5

// Scope bounds which files discovery considers.
type Scope int

const (
	// ScopeProject looks for the component's own license: the root and one
	// directory below it, with the trees belonging to other components skipped.
	// It is what a build-time check and an upstream evaluation want, and it is
	// bounded so that scanning a large tree stays cheap.
	ScopeProject Scope = iota
	// ScopeTree walks the whole filesystem, vendored subdirectories included,
	// and records why each file is out of the component's own scope rather than
	// leaving it out. It is what evidence collection wants: a vendored license
	// belongs to the component that vendored it, and is needed to say so.
	ScopeTree
)

// projectDepth is how far ScopeProject descends. Two segments is the root plus
// one directory below it, which covers projects that keep their license out of
// the root, as a LICENSES/ directory does, without reaching the dependencies
// deeper in the tree.
const projectDepth = 2

// Discovery is what a scan of a filesystem found.
type Discovery struct {
	// Candidates are the discovered license files, ordered by descending
	// weight with ties broken by path.
	Candidates []Candidate
	// Unreadable are the paths the scan could not read or descend into.
	//
	// They are reported rather than fatal, because a tree with one unreadable
	// directory still has evidence in the rest of it - but they are reported
	// rather than ignored, because a component that appears to have no license
	// and a component whose license directory could not be read mean opposite
	// things.
	Unreadable []string
}

// Candidate is a discovered license file, before anything has been read.
type Candidate struct {
	// Path is the file's path within the scanned filesystem, slash-separated.
	Path string
	// Weight scores how likely the file is to hold the component's own license.
	// Files in the root carry RootWeightBonus on top of their filename weight.
	Weight float64
	// Excluded says why the file is not evidence about this component, and is
	// empty for a file that is. ScopeProject never returns a file excluded as
	// vendored or build-output, since it does not descend into those trees.
	Excluded ExclusionReason
}

// IsLicenseFile reports whether a name is a license file, and how canonical the
// name is.
//
// The test is on the name alone, deliberately. Where a file sits is a separate
// question that ClassifyExclusion answers, because the two are needed
// separately: the license-content hash selects files by name with no regard to
// depth, while discovery wants both.
//
// Where several patterns match, the highest weight wins, so the answer does not
// depend on map iteration order.
func IsLicenseFile(name string) (bool, float64) {
	base := path.Base(normalizePath(name))
	if slices.Contains(ignoredExtensions, path.Ext(base)) {
		return false, 0
	}
	var best float64
	for re, weight := range filenameWeights {
		if re.MatchString(base) {
			best = max(best, weight)
		}
	}
	return best > 0, best
}

// Find discovers the license files on a filesystem, ordered by descending
// weight with ties broken by path so the order is deterministic.
//
// A symlink is followed when it resolves within fsys, since repositories
// commonly symlink LICENSE at the root to the real text. A link escaping the
// filesystem fails to resolve and is skipped rather than read, which is why
// callers scanning a directory should pass an os.Root filesystem.
func Find(fsys fs.FS, scope Scope) (Discovery, error) {
	var found Discovery
	err := fs.WalkDir(fsys, ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			// The walk continues past an unreadable entry. Returning the error
			// would discard every candidate found so far, which is the wrong
			// trade for a tree that is being read for evidence: what could be
			// read is worth more than the certainty that nothing was missed,
			// as long as the gap is named.
			found.Unreadable = append(found.Unreadable, p)
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		depth := len(strings.Split(p, "/"))
		if entry.IsDir() {
			if p == "." {
				return nil
			}
			if scope == ScopeProject && (depth >= projectDepth || outsideComponent(p)) {
				return fs.SkipDir
			}
			return nil
		}
		if scope == ScopeProject && depth > projectDepth {
			return nil
		}
		switch mode := entry.Type(); {
		case mode.IsRegular():
		case mode&fs.ModeSymlink != 0:
			info, err := fs.Stat(fsys, p)
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
		default:
			return nil
		}

		is, weight := IsLicenseFile(p)
		if !is {
			return nil
		}
		if path.Dir(p) == "." {
			weight += RootWeightBonus
		}
		found.Candidates = append(found.Candidates, Candidate{Path: p, Weight: weight, Excluded: ClassifyExclusion(p)})
		return nil
	})
	if err != nil {
		return Discovery{}, err
	}

	slices.SortFunc(found.Candidates, func(a, b Candidate) int {
		return cmp.Or(cmp.Compare(b.Weight, a.Weight), strings.Compare(a.Path, b.Path))
	})
	slices.Sort(found.Unreadable)
	return found, nil
}

// outsideComponent reports whether a directory belongs to another component
// altogether, which is the one exclusion ScopeProject applies by skipping
// rather than by recording.
func outsideComponent(dir string) bool {
	switch ClassifyDirExclusion(dir) {
	case ExclusionVendored, ExclusionBuildOutput:
		return true
	default:
		return false
	}
}
