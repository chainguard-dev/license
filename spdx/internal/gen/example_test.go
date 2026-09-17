/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package gen_test

import (
	"fmt"
	"os"
	"path/filepath"

	"chainguard.dev/license/spdx/internal/gen"
)

// Generate produces the Go source for the SPDX normalization tables from the
// SPDX license list JSON and the licenseclassifier asset directory. Pass an
// empty assets path to let Generate locate the assets automatically via the
// module cache.
func ExampleGenerate() {
	// Write a minimal SPDX license list to a temp file.
	spdxPath := filepath.Join(os.TempDir(), "spdx-licenses.json")
	if err := os.WriteFile(spdxPath, []byte(`{"licenseListVersion":"3.0","licenses":[]}`), 0o600); err != nil {
		fmt.Println("setup:", err)
		return
	}
	defer os.Remove(spdxPath)

	// assets must point to the licenseclassifier asset directory.
	src, err := gen.Generate(spdxPath, "/path/to/licenseclassifier/assets")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("generated %d bytes\n", len(src))
}
