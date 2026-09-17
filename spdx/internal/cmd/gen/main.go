/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Command gen writes the generated SPDX normalization tables.
package main

import (
	"flag"
	"fmt"
	"os"

	"chainguard.dev/license/spdx/internal/gen"
)

func main() {
	out := flag.String("out", "tables.go", "file to write")
	spdxPath := flag.String("spdx", "licenses.json", "vendored SPDX license list")
	assets := flag.String("assets", "", "licenseclassifier assets dir (auto-detected when empty)")
	flag.Parse()

	src, err := gen.Generate(*spdxPath, *assets)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	// A generated source file, world-readable like every other file in the
	// repository.
	if err := os.WriteFile(*out, src, 0o644); err != nil { //nolint:gosec // generated source, not a secret
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}
