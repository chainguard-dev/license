/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package contenthash_test

import (
	"fmt"
	"strings"
	"testing/fstest"

	"chainguard.dev/license/contenthash"
)

// Compute keys a determination on what a component's licensing evidence is.
// The order the files were found in does not change the key, which is what lets
// two producers store one answer rather than two.
func ExampleCompute() {
	files := []contenthash.File{
		{Path: "LICENSE", Digest: "sha256:aaa"},
		{Path: "s2/LICENSE", Digest: "sha256:bbb"},
	}
	reversed := []contenthash.File{files[1], files[0]}

	fmt.Println(contenthash.Compute(files) == contenthash.Compute(reversed))
	// Output: true
}

// ComputeFS is the same key over a filesystem rooted at the component, which is
// the form a fetched artifact arrives in. Line endings are normalized, so one
// license checked out two ways is one key.
func ExampleComputeFS() {
	unix := fstest.MapFS{"LICENSE": &fstest.MapFile{Data: []byte("MIT License\n\nPermission is granted.\n")}}
	windows := fstest.MapFS{"LICENSE": &fstest.MapFile{Data: []byte("MIT License\r\n\r\nPermission is granted.\r\n")}}

	first, err := contenthash.ComputeFS(unix)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	second, err := contenthash.ComputeFS(windows)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(first == second)
	// Output: true
}

// Verify decides which key an in-tree copy is answered under. It is a subset
// test, because "go mod vendor" copies only the packages a build imports and a
// pristine copy therefore holds fewer license files than the module it came
// from.
func ExampleVerify() {
	published := []contenthash.File{
		{Path: "LICENSE", Digest: "sha256:aaa"},
		{Path: "s2/LICENSE", Digest: "sha256:bbb"},
	}

	for _, local := range [][]contenthash.File{
		{{Path: "LICENSE", Digest: "sha256:aaa"}},
		{{Path: "LICENSE", Digest: "sha256:edited"}},
		{{Path: "LICENSE", Digest: "sha256:aaa"}, {Path: "LICENSE-EXTRA", Digest: "sha256:added"}},
	} {
		verification, reason := contenthash.Verify(local, published)
		fmt.Println(strings.TrimSpace(verification.String() + " " + reason))
	}
	// Output:
	// pristine
	// diverged LICENSE differs from the published artifact
	// diverged LICENSE-EXTRA is not in the published artifact
}

// LicenseRef names a license nothing recognizes, so a proprietary EULA is
// recorded rather than dropped. The name is a digest of the text, so the same
// text yields the same name wherever it turns up.
func ExampleLicenseRef() {
	const eula = "End User License Agreement\n\nYou may not redistribute.\n"
	fmt.Println(contenthash.LicenseRef([]byte(eula)))
	// Output: LicenseRef-v1-dcdd9a5852d852c5
}

// Covers is the file-selection rule both sides of a comparison use, which is
// what makes them comparable: license files only, no manifests.
func ExampleCovers() {
	for _, path := range []string{"LICENSE", "s2/COPYING", "package.json", "README.md"} {
		fmt.Printf("%-14s %v\n", path, contenthash.Covers(path))
	}
	// Output:
	// LICENSE        true
	// s2/COPYING     true
	// package.json   false
	// README.md      false
}
