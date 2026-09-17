/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"context"
	"path"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
)

// tree builds an in-memory filesystem from a map of path to contents.
//
// Enumeration takes an fs.FS, so no test here needs a directory on disk: a
// fixture is a map literal, and the same fixture exercises the code path a
// build workspace, an expanded archive and an unpacked package all take.
func tree(files map[string]string) fstest.MapFS {
	fsys := make(fstest.MapFS, len(files))
	for p, content := range files {
		fsys[p] = &fstest.MapFile{Data: []byte(content)}
	}
	return fsys
}

// split unpacks an enumeration into the components and notes most of these
// tests assert on. Failures are asserted on with hasFailureContaining.
func split(e Enumeration) ([]Component, []string) { return e.Components, e.Notes }

// hasFailureContaining reports whether some failure's detail mentions substr.
func hasFailureContaining(failures []Failure, substr string) bool {
	for _, f := range failures {
		if strings.Contains(f.Detail, substr) {
			return true
		}
	}
	return false
}

// byPURL indexes components for assertion without depending on slice order.
func byPURL(comps []Component) map[string]Component {
	out := make(map[string]Component, len(comps))
	for _, c := range comps {
		out[c.PURL] = c
	}
	return out
}

const goSum = `github.com/google/uuid v1.6.0 h1:NIvaJDMOsjJZ2wPCH3sHXTKbA==
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/cespare/xxhash/v2 v2.3.0 h1:UL815xU9SqsFlibzuggzjXhog7bL6oX9BbNZnL2UFvs=
github.com/cespare/xxhash/v2 v2.3.0/go.mod h1:VGX0DQ3Q6kWi7AoAeZDth3/j3BFtOZR5XLFGgcrjCOs=
`

func TestEnumerateGoComponentsFromGoSum(t *testing.T) {
	fsys := tree(map[string]string{
		"go.mod": "module example.com/x\n\ngo 1.26\n",
		"go.sum": goSum,
	})

	comps, notes := split(enumerateGo(t.Context(), fsys))
	if len(comps) != 2 {
		t.Fatalf("components: got = %d, want = 2 (%+v)", len(comps), comps)
	}

	got := byPURL(comps)
	uuid, ok := got["pkg:golang/github.com/google/uuid@v1.6.0"]
	if !ok {
		t.Fatalf("missing uuid component in %v", got)
	}
	if uuid.Digest != "h1:NIvaJDMOsjJZ2wPCH3sHXTKbA==" {
		t.Errorf("digest: got = %q, want the h1 zip hash", uuid.Digest)
	}
	if uuid.DigestAlgo != "h1" {
		t.Errorf("digest algo: got = %q, want = %q", uuid.DigestAlgo, "h1")
	}
	if uuid.Ecosystem != "golang" || uuid.Kind != KindEcosystem {
		t.Errorf("ecosystem/kind: got = %q/%q", uuid.Ecosystem, uuid.Kind)
	}
	if uuid.Linkage != "static" {
		t.Errorf("linkage: got = %q, want = %q", uuid.Linkage, "static")
	}
	// The over-inclusiveness of go.sum must be stated, not silently assumed.
	if len(notes) == 0 {
		t.Error("notes: got none, want a note about go.sum covering the full module graph")
	}
}

func TestEnumerateGoComponentsPrefersVendorModules(t *testing.T) {
	fsys := tree(map[string]string{
		"go.mod": "module example.com/x\n\ngo 1.26\n",
		"go.sum": goSum,
		// modules.txt lists only what the build actually uses.
		"vendor/modules.txt": "# github.com/google/uuid v1.6.0\n## explicit\ngithub.com/google/uuid\n",
	})

	comps, _ := split(enumerateGo(t.Context(), fsys))
	if len(comps) != 1 {
		t.Fatalf("components: got = %d, want = 1 (vendor list is authoritative): %+v", len(comps), comps)
	}
	if comps[0].DiscoveredFrom != "vendor/modules.txt" {
		t.Errorf("discovered from: got = %q, want = %q", comps[0].DiscoveredFrom, "vendor/modules.txt")
	}
	// The h1 digest still comes from go.sum even when the list comes from vendor.
	if comps[0].Digest == "" {
		t.Error("digest: got empty, want the h1 digest carried over from go.sum")
	}
}

func TestEnumerateGoComponentsNoModule(t *testing.T) {
	comps, notes := split(enumerateGo(t.Context(), tree(map[string]string{"README": "no go here"})))
	if len(comps) != 0 || len(notes) != 0 {
		t.Errorf("components/notes: got = %+v, %v, want none for a non-Go tree", comps, notes)
	}
}

func TestParseGoSumSkipsGoModHashes(t *testing.T) {
	got := parseGoSum([]byte(goSum))
	if len(got) != 2 {
		t.Fatalf("entries: got = %d, want = 2 (the /go.mod lines are not content): %v", len(got), got)
	}
	for k := range got {
		if path.Ext(k) == ".mod" {
			t.Errorf("unexpected /go.mod entry %q", k)
		}
	}
}

const cargoLockContent = `version = 3

[[package]]
name = "mycrate"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.219"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "5f0e2c6ed6606019b4e29e69dbaba95b11854410e5347d525002456dbbb786b6"
`

func TestEnumerateCargoComponents(t *testing.T) {
	fsys := tree(map[string]string{"Cargo.lock": cargoLockContent})

	comps, notes := split(enumerateCargo(t.Context(), fsys))
	if len(comps) != 1 {
		t.Fatalf("components: got = %d, want = 1 (workspace-local crate excluded): %+v", len(comps), comps)
	}
	c := comps[0]
	if c.PURL != "pkg:cargo/serde@1.0.219" {
		t.Errorf("purl: got = %q, want = %q", c.PURL, "pkg:cargo/serde@1.0.219")
	}
	if c.Digest != "5f0e2c6ed6606019b4e29e69dbaba95b11854410e5347d525002456dbbb786b6" {
		t.Errorf("digest: got = %q, want the registry checksum", c.Digest)
	}
	if c.DigestAlgo != "sha256" {
		t.Errorf("digest algo: got = %q, want = %q", c.DigestAlgo, "sha256")
	}
	// The workspace-local crate is accounted for rather than dropped silently.
	if len(notes) == 0 {
		t.Error("notes: got none, want a note about the workspace-local crate")
	}
}

func TestEnumerateComponentsAcrossEcosystems(t *testing.T) {
	fsys := tree(map[string]string{
		"go.mod":     "module example.com/x\n\ngo 1.26\n",
		"go.sum":     goSum,
		"Cargo.lock": cargoLockContent,
	})

	comps, _ := split(EnumerateSource(t.Context(), fsys))
	if len(comps) != 3 {
		t.Fatalf("components: got = %d, want = 3 across both ecosystems: %+v", len(comps), comps)
	}
	found := map[Ecosystem]struct{}{}
	for _, c := range comps {
		found[c.Ecosystem] = struct{}{}
	}
	for _, want := range []Ecosystem{EcosystemGo, EcosystemCargo} {
		if _, ok := found[want]; !ok {
			t.Errorf("no %s component enumerated from a tree that has one: %+v", want, comps)
		}
	}
	// Stable ordering keeps bundles reproducible.
	for i := 1; i < len(comps); i++ {
		if comps[i-1].PURL > comps[i].PURL {
			t.Errorf("components are not sorted by purl: %q before %q", comps[i-1].PURL, comps[i].PURL)
		}
	}
}

func TestDedupeComponents(t *testing.T) {
	c := Component{PURL: "pkg:golang/x@v1", Digest: "h1:a"}
	other := Component{PURL: "pkg:golang/x@v1", Digest: "h1:b"}
	got := dedupe([]Component{c, c, other})
	if len(got) != 2 {
		t.Errorf("components: got = %d, want = 2 (same purl, different content is two variants)", len(got))
	}
}

// TestEnumerateSourceReportsAnUnreadableLockfile covers the difference between
// a package with no dependencies and one whose lockfile could not be read. A
// consumer measuring coverage has to be able to tell those apart, which a note
// in prose does not let it do.
func TestEnumerateSourceReportsAnUnreadableLockfile(t *testing.T) {
	got := EnumerateSource(t.Context(), tree(map[string]string{
		"Cargo.lock": "[[package]\nthis is not toml",
	}))
	if len(got.Components) != 0 {
		t.Errorf("components: got = %v, want none from an unparseable lockfile", got.Components)
	}
	if len(got.Failures) != 1 {
		t.Fatalf("failures: got = %v, want exactly one", got.Failures)
	}
	if got.Failures[0].Ecosystem != EcosystemCargo || got.Failures[0].Path != "Cargo.lock" {
		t.Errorf("failure: got = %+v, want it attributed to the cargo lockfile", got.Failures[0])
	}
}

// TestEnumerateSourceStopsOnACancelledContext verifies a cancellation is
// reported rather than ignored, so a caller does not read a truncated closure
// as a complete one.
func TestEnumerateSourceStopsOnACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	got := EnumerateSource(ctx, tree(map[string]string{
		"go.mod": "module example.com/x\n",
		"go.sum": goSum,
	}))
	if len(got.Components) != 0 {
		t.Errorf("components: got = %v, want none from a cancelled enumeration", got.Components)
	}
	if len(got.Failures) == 0 {
		t.Error("failures: got none, want the cancellation recorded")
	}
}

// TestEnumerateCargoReadsVersion1Checksums covers the older lockfile schema
// still in the wild: version 1 recorded checksums in a metadata table rather
// than on the package entries, and reading only the newer form left every
// crate with no content digest to verify a fetch against.
func TestEnumerateCargoReadsVersion1Checksums(t *testing.T) {
	const v1 = `[root]
name = "app"
version = "0.1.0"

[[package]]
name = "libc"
version = "0.2.155"
source = "registry+https://github.com/rust-lang/crates.io-index"

[metadata]
"checksum libc 0.2.155 (registry+https://github.com/rust-lang/crates.io-index)" = "97b3888a4aecf77e811145cadf6eef5901f4782c53886191b2f693f24761847c"
`

	comps, _ := split(enumerateCargo(t.Context(), tree(map[string]string{"Cargo.lock": v1})))
	got := byPURL(comps)
	libc, ok := got["pkg:cargo/libc@0.2.155"]
	if !ok {
		t.Fatalf("missing the crate in %v", got)
	}
	if libc.Digest != "97b3888a4aecf77e811145cadf6eef5901f4782c53886191b2f693f24761847c" {
		t.Errorf("digest: got = %q, want the checksum from the metadata table", libc.Digest)
	}
	if libc.DigestAlgo != DigestSHA256 {
		t.Errorf("digest algo: got = %q, want = %q", libc.DigestAlgo, DigestSHA256)
	}
}

// TestEnumerateCargoNamesNoAlgorithmWithoutADigest keeps a scheme from being
// recorded beside an empty digest, which would claim a verification nobody can
// perform.
func TestEnumerateCargoNamesNoAlgorithmWithoutADigest(t *testing.T) {
	const noChecksum = `[[package]]
name = "libc"
version = "0.2.155"
source = "registry+https://github.com/rust-lang/crates.io-index"
`

	comps, _ := split(enumerateCargo(t.Context(), tree(map[string]string{"Cargo.lock": noChecksum})))
	if len(comps) != 1 {
		t.Fatalf("components: got = %v, want one", comps)
	}
	if comps[0].Digest != "" || comps[0].DigestAlgo != "" {
		t.Errorf("got digest %q algo %q, want both empty", comps[0].Digest, comps[0].DigestAlgo)
	}
}

// TestFinalizeLeavesTheCallersSliceAlone pins the contract Finalize's doc makes
// when it invites a caller to pass a union of two enumerations.
//
// Filtering into the caller's own backing array would sort their slice and
// silently shorten what they still hold, so a caller finalizing a union and
// then reading one of its halves would find it rearranged.
func TestFinalizeLeavesTheCallersSliceAlone(t *testing.T) {
	original := []Component{
		{PURL: "pkg:npm/zebra@1.0.0"},
		{PURL: "pkg:cargo/serde@1.0.0"},
		{PURL: "pkg:npm/broken name@1.0.0"},
		{PURL: "pkg:golang/example.com/a@v1.0.0"},
	}
	held := slices.Clone(original)

	got := Finalize(Enumeration{Components: held})

	if diff := cmp.Diff(original, held); diff != "" {
		t.Errorf("the caller's slice was modified (-want +got):\n%s", diff)
	}
	if len(got.Components) != 3 {
		t.Errorf("Components: got = %d, want the malformed purl dropped from 4", len(got.Components))
	}
	if !slices.IsSortedFunc(got.Components, func(a, b Component) int { return strings.Compare(a.PURL, b.PURL) }) {
		t.Errorf("Components: got = %v, want them sorted by purl", got.Components)
	}
}

// TestEnumerateGoNamesNoAlgorithmWithoutADigest covers the vendor path, which
// is read whether or not go.sum is present. A scheme recorded beside an empty
// digest claims a verification nobody can perform.
func TestEnumerateGoNamesNoAlgorithmWithoutADigest(t *testing.T) {
	fsys := tree(map[string]string{
		"go.mod":             "module example.com/x\n\ngo 1.26\n",
		"vendor/modules.txt": "# github.com/google/uuid v1.6.0\n## explicit\ngithub.com/google/uuid\n",
	})

	comps, _ := split(enumerateGo(t.Context(), fsys))
	if len(comps) != 1 {
		t.Fatalf("components: got = %+v, want one", comps)
	}
	if comps[0].Digest != "" || comps[0].DigestAlgo != "" {
		t.Errorf("got digest %q algo %q, want both empty with no go.sum to read", comps[0].Digest, comps[0].DigestAlgo)
	}
}

// TestEnumerateCargoChecksumsAreScopedToTheirSource covers a crate resolved
// twice, once from the registry and once from git.
//
// Only the registry copy is checksummed. Matching a metadata checksum on name
// and version alone hands that digest to the git copy, and since dedupe keys
// on purl and digest the two then collapse into one, reporting arbitrary git
// code as content verified against crates.io.
func TestEnumerateCargoChecksumsAreScopedToTheirSource(t *testing.T) {
	const twoSources = `[[package]]
name = "libc"
version = "0.2.155"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "libc"
version = "0.2.155"
source = "git+https://github.com/example/libc?rev=deadbeef#deadbeef"

[metadata]
"checksum libc 0.2.155 (registry+https://github.com/rust-lang/crates.io-index)" = "97b3888a4aecf77e811145cadf6eef5901f4782c53886191b2f693f24761847c"
`

	comps, _ := split(enumerateCargo(t.Context(), tree(map[string]string{"Cargo.lock": twoSources})))
	if len(comps) != 2 {
		t.Fatalf("components: got = %+v, want both copies", comps)
	}
	digested := 0
	for _, c := range comps {
		if c.Digest != "" {
			digested++
		}
	}
	if digested != 1 {
		t.Errorf("copies carrying a digest: got = %d, want = 1, the registry one: %+v", digested, comps)
	}
	if kept := Finalize(Enumeration{Components: comps}).Components; len(kept) != 2 {
		t.Errorf("after Finalize: got = %+v, want both copies; equal digests would collapse them", kept)
	}
}
