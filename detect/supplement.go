/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package detect

import (
	"embed"
	"io/fs"
	"path"
	"strings"
)

// supplementFS holds canonical SPDX license texts the classifier's own corpus
// does not contain.
//
// The classifier covers 151 of the 727 current SPDX identifiers, and a license
// it has never seen does not come back unrecognized - it comes back as the
// nearest thing the classifier does know, confidently. Unicode-3.0 is the
// measured case: absent from the corpus, so every ICU crate in a sweep
// concluded Unicode-DFS-2016, a different license, at full confidence. No
// heuristic fixes that; the missing texts do.
//
// Entries are chosen by what the corpus we scan actually declares, rather than
// by walking the SPDX list, so this stays small and every addition is justified
// by occurrences.
//
//go:embed supplement/*.txt
var supplementFS embed.FS

// Supplement returns canonical license texts keyed by SPDX identifier, for
// loading into a classifier that would otherwise misidentify them.
func Supplement() map[string][]byte {
	entries, err := fs.ReadDir(supplementFS, "supplement")
	if err != nil {
		// The directory is embedded, so a failure here is a build defect rather
		// than a runtime condition.
		panic("detect: reading embedded supplement: " + err.Error())
	}
	out := make(map[string][]byte, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		body, err := supplementFS.ReadFile(path.Join("supplement", e.Name()))
		if err != nil {
			panic("detect: reading embedded supplement " + e.Name() + ": " + err.Error())
		}
		out[strings.TrimSuffix(e.Name(), ".txt")] = body
	}
	return out
}
