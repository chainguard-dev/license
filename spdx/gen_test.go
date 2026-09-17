/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package spdx

import (
	"os"
	"testing"

	"chainguard.dev/license/spdx/internal/gen"
)

// TestTablesAreCurrent regenerates the tables and fails if they differ from
// what is checked in.
//
// The tables are a diff between two vocabularies that both move: upgrading
// licenseclassifier changes the names it can emit, and refreshing the SPDX list
// changes what those names map onto. Either would otherwise rot the table
// silently, and a stale entry does not fail loudly - it quietly publishes the
// wrong identifier.
//
// Regeneration runs in-process rather than through the go tool, so the test
// does not depend on the caller's module mode.
func TestTablesAreCurrent(t *testing.T) {
	want, err := gen.Generate("licenses.json", "")
	if err != nil {
		t.Fatalf("regenerating tables: %v", err)
	}
	got, err := os.ReadFile("tables.go")
	if err != nil {
		t.Fatalf("reading checked-in tables: %v", err)
	}
	if string(got) != string(want) {
		t.Error("tables.go is stale; run 'go generate ./...' in spdx")
	}
}

// TestTablesRegenerateFromColdModuleCache pins the generator's cold-cache
// path. Nothing on this module's build path imports the classifier, so a
// runner whose module cache lacks it is a reachable state; go list then
// prints an empty Dir with exit 0, and joining "assets" onto it degraded to
// the relative path "assets/License" and a confusing open error (the main
// canary hit exactly this, run 34598337570). The empty GOMODCACHE forces
// that state; Generate must download the classifier and still succeed.
// -modcacherw keeps the throwaway cache writable so t.TempDir can remove it.
func TestTablesRegenerateFromColdModuleCache(t *testing.T) {
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GOFLAGS", "-modcacherw")
	if _, err := gen.Generate("licenses.json", ""); err != nil {
		t.Fatalf("regenerating tables with a cold module cache: %v", err)
	}
}
