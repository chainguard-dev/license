/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"cmp"
	"io/fs"
	"path"
	"slices"
	"strings"

	"chainguard.dev/license/spdx"
)

const (
	// MaxNoticeBytes is how much of a source file is read when looking for a
	// license notice. The notice sits at the top of the file or not at all.
	MaxNoticeBytes = 2 << 10
	// MaxNoticeFiles bounds the sample. A project that uses a notice repeats it
	// in every file, so a spread of a couple of dozen establishes it; the count
	// exists to catch a tree that is not uniform, not to be thorough.
	MaxNoticeFiles = 24
)

// noticeExtensions are the file kinds that carry license notices. Restricting
// by extension keeps binaries and generated data out of the sample.
var noticeExtensions = map[string]struct{}{
	".c": {}, ".h": {}, ".cc": {}, ".cpp": {}, ".cxx": {}, ".hpp": {}, ".hh": {},
	".go": {}, ".rs": {}, ".py": {}, ".rb": {}, ".pl": {}, ".pm": {}, ".sh": {},
	".java": {}, ".js": {}, ".ts": {}, ".cs": {}, ".kt": {}, ".swift": {},
	".m": {}, ".mm": {}, ".lua": {}, ".php": {}, ".el": {}, ".scm": {},
	".ac": {}, ".am": {}, ".cmake": {}, ".s": {}, ".asm": {},
}

// Notice is the leading bytes of one source file.
//
// It exists because a license text cannot express the version grant a
// GPL-family license depends on: SPDX ships identical text for the -only and
// -or-later forms, and that text states "any later version" three times in its
// own body, so no amount of reading the license settles which grant the author
// made. Only the notice at the top of their own source does.
type Notice struct {
	Path string `json:"path"`
	// Text is the first MaxNoticeBytes of the file.
	Text      string `json:"text"`
	Truncated bool   `json:"truncated,omitempty"`
}

// Notices retains a deterministic sample of source-file heads, and reports how
// many of them were read.
//
// The count matters as much as the sample: it is what distinguishes "the
// notices were read and none granted later versions", which is itself the
// answer, from "nobody looked", which is not. So it counts files actually
// read, not candidates found. A tree whose sources cannot be opened yields
// zero, and the caller reports an unknown grant rather than an absent one.
//
// The sample is chosen by a fixed stride over sorted paths rather than by
// taking the first few, so a subtree licensed differently from the root is
// represented instead of being alphabetically excluded, and so the same tree
// always yields the same sample - evidence is content-addressed downstream,
// and a sample that varied between runs would defeat that.
//
// License files are deliberately excluded, for the reason above: sampling
// COPYING would report a later-version grant for every GPL project in
// existence.
func Notices(fsys fs.FS) (notices []Notice, sampled int) {
	var candidates []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree contributes nothing and is not fatal
		}
		if d.IsDir() {
			if p != "." && ClassifyDirExclusion(p) != ExclusionNone {
				return fs.SkipDir
			}
			return nil
		}
		if _, ok := noticeExtensions[strings.ToLower(path.Ext(p))]; !ok {
			return nil
		}
		if is, _ := IsLicenseFile(p); is {
			return nil
		}
		candidates = append(candidates, p)
		return nil
	})
	if err != nil || len(candidates) == 0 {
		return nil, 0
	}
	slices.Sort(candidates)

	stride := 1
	if len(candidates) > MaxNoticeFiles {
		stride = len(candidates) / MaxNoticeFiles
	}
	for i := 0; i < len(candidates) && len(notices) < MaxNoticeFiles; i += stride {
		n, ok := readNotice(fsys, candidates[i])
		if !ok {
			continue
		}
		notices = append(notices, n)
	}
	return notices, len(notices)
}

// readNotice reads the leading bytes of one file, reporting whether there was
// more to it.
func readNotice(fsys fs.FS, p string) (Notice, bool) {
	f, err := fsys.Open(p)
	if err != nil {
		return Notice{}, false
	}
	defer f.Close()

	buf := make([]byte, MaxNoticeBytes+1)
	n, _ := readAsFarAsPossible(f, buf)
	if n == 0 {
		return Notice{}, false
	}
	truncated := n > MaxNoticeBytes
	if truncated {
		n = MaxNoticeBytes
	}
	body := buf[:n]
	// A file with NUL bytes is not text, whatever its extension claims.
	if slices.Contains(body, 0) {
		return Notice{}, false
	}
	return Notice{Path: p, Text: string(body), Truncated: truncated}, true
}

// readAsFarAsPossible fills buf as far as the file allows, tolerating the short
// reads an fs.File is entitled to return.
func readAsFarAsPossible(f fs.File, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := f.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			break
		}
	}
	return total, nil
}

// Grant is a version grant stated in a source notice.
type Grant struct {
	// Expression is the SPDX expression the notice states, suffix included.
	Expression string `json:"expression"`
	// Source is "spdx-tag" for a machine-readable SPDX-License-Identifier, or
	// "header" for a matched notice. The tag is exact; the header is a match.
	Source string `json:"source"`
	// Path locates the grant, and Files says how many sampled files agreed.
	Path  string `json:"path"`
	Files int    `json:"files"`
}

// GrantEvidence is what a tree's notices said about version grants.
type GrantEvidence struct {
	// Grants are the distinct grants stated, most-agreed first.
	Grants []Grant
	// Sampled is how many source files the grants were read from, which is
	// what Notices returns rather than how many it found. Zero means nobody
	// looked, which is a weaker claim than looking and finding none, so
	// counting a file that failed to open would settle a grant on no evidence.
	Sampled int
}

// GrantBasis records how a version grant was established. It exists because a
// license text cannot express one, so a reader deserves to know where the
// suffix came from.
type GrantBasis string

const (
	// GrantNotApplicable means no license involved has a version grant.
	GrantNotApplicable GrantBasis = ""
	// GrantFromNotice means a notice in the component's own source stated it.
	GrantFromNotice GrantBasis = "notice"
	// GrantAbsent means the notices were read and none granted later versions,
	// which is itself the answer: the grant has to be explicit.
	GrantAbsent GrantBasis = "absent"
	// GrantUnknown means no source was read, so the suffix rests on the
	// convention that a grant must be explicit rather than on evidence.
	GrantUnknown GrantBasis = "unknown"
	// GrantMixed means the tree stated both grants for one license.
	GrantMixed GrantBasis = "mixed"
)

// Grants derives the version grants stated across a sample of source notices.
//
// A single entry is the ordinary case: a project states its grant the same way
// in every file. Two or more mean the tree is genuinely mixed, which is a
// finding rather than noise, and the caller escalates rather than picking.
//
// Both mechanisms are needed because they cover disjoint conventions: modern
// projects carry an SPDX-License-Identifier tag, which the classifier does not
// recognize at all, while older ones carry a prose notice, which the classifier
// matches well but reports under the bare license name with the grant hidden in
// the variant.
func Grants(c Classifier, notices []Notice) []Grant {
	byExpr := map[string]*Grant{}
	record := func(expr, source, p string) {
		if g, ok := byExpr[expr]; ok {
			g.Files++
			return
		}
		byExpr[expr] = &Grant{Expression: expr, Source: source, Path: p, Files: 1}
	}

	for _, n := range notices {
		if expr, ok := spdx.Tag(n.Text); ok {
			record(expr, "spdx-tag", n.Path)
			continue
		}
		if c == nil {
			continue
		}
		for _, m := range c.IdentifyHeader([]byte(n.Text)) {
			if expr, ok := spdx.HeaderGrant(m.Name, m.Variant); ok {
				record(expr, "header", n.Path)
				break
			}
		}
	}

	out := make([]Grant, 0, len(byExpr))
	for _, g := range byExpr {
		out = append(out, *g)
	}
	// Most-agreed first, then by expression so the order is stable.
	slices.SortFunc(out, func(a, b Grant) int {
		return cmp.Or(cmp.Compare(b.Files, a.Files), strings.Compare(a.Expression, b.Expression))
	})
	return out
}

// GrantFor reports the grant resolving a GPL-family identifier, and how many
// distinct grants the notices stated for it.
//
// A grant only counts when it names the same base license that was detected: a
// tree whose notices say GPL-3.0 does not resolve the suffix of an LGPL-3.0
// license file, and quietly letting it would turn a real disagreement into a
// confident wrong answer.
//
// A count above one means the tree stated both grants for the same license.
// That is a finding rather than a tie to break, and the caller escalates.
//
// Conclude calls this to settle the component's own license. It is exported for
// the caller resolving a grant itself - one composing an expression from
// several identifiers, say, where which grant applies to which is the caller's
// question rather than this package's.
func GrantFor(r spdx.Resolution, grants []Grant) (expr string, matched int) {
	if !r.NeedsGrant() {
		return "", 0
	}
	seen := map[string]struct{}{}
	for _, g := range grants {
		if g.Expression != r.Only && g.Expression != r.OrLater {
			continue
		}
		if _, repeated := seen[g.Expression]; repeated {
			continue
		}
		seen[g.Expression] = struct{}{}
		expr = g.Expression
	}
	return expr, len(seen)
}
