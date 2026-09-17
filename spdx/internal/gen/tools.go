//go:build tools

/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package gen

// findAssets locates the licenseclassifier asset directory by asking "go list
// -m" for the module's checkout, so the module has to be in the build list
// without any package importing it. This blank import is what keeps it there.
import _ "github.com/google/licenseclassifier/v2"
