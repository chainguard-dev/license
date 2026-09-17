/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"bufio"
	"io/fs"
	"regexp"
	"strings"
)

var (
	// proseFileRe matches the files upstreams state their licensing in when
	// they state it in prose rather than shipping a license file.
	proseFileRe = regexp.MustCompile(`(?i)^(readme|copyright|copying|notice|authors)(\.[a-z0-9]+)?$`)
	// licenseMentionRe is the filter that makes a matched line a licensing
	// statement rather than an arbitrary sentence.
	licenseMentionRe = regexp.MustCompile(`(?i)licen[sc]e`)
)

const (
	// maxProseExcerpt bounds one retained line, so a minified README cannot
	// decide how large the result is.
	maxProseExcerpt = 300
	// maxProseHintsPerFile bounds how many lines one file contributes. A
	// project states its licensing once or twice; past that the file is
	// discussing the licensing of something else.
	maxProseHintsPerFile = 10
)

// ProseHint is a license mention found in a prose file.
type ProseHint struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Excerpt string `json:"excerpt"`
}

// IsProseFile reports whether a name is a file upstreams state licensing in
// prose in. It is exported because a caller deciding what to retain from a
// fetched artifact needs the same rule that reads a source tree.
func IsProseFile(name string) bool {
	return proseFileRe.MatchString(name)
}

// Prose scans the top-level README, COPYRIGHT, NOTICE and AUTHORS files for
// lines that mention a license.
//
// It exists because a license file is not the only place licensing is written
// down. Upstreams frequently state their license only in prose, and prose is
// also where a choice between several licenses is usually spelled out: whole
// ecosystems have no manifest field to declare one in, so for a Go module
// shipping two license texts the README is the only thing that says whether
// they compose with AND or with OR.
//
// Only the top level is read. A license statement in a subdirectory's README
// is describing that subdirectory, and a component's own licensing is stated
// where a reader would look for it.
func Prose(fsys fs.FS) []ProseHint {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil
	}
	var hints []ProseHint
	for _, e := range entries {
		if e.IsDir() || !IsProseFile(e.Name()) {
			continue
		}
		hints = append(hints, proseHints(fsys, e.Name())...)
	}
	return hints
}

// proseHints reads the license-mentioning lines of one file.
func proseHints(fsys fs.FS, name string) []ProseHint {
	f, err := fsys.Open(name)
	if err != nil {
		return nil
	}
	defer f.Close()

	var hints []ProseHint
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 0; sc.Scan(); {
		line++
		text := strings.TrimSpace(sc.Text())
		if !licenseMentionRe.MatchString(text) {
			continue
		}
		if len(text) > maxProseExcerpt {
			text = text[:maxProseExcerpt] + "..."
		}
		hints = append(hints, ProseHint{Path: name, Line: line, Excerpt: text})
		if len(hints) >= maxProseHintsPerFile {
			break
		}
	}
	return hints
}
