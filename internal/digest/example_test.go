/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package digest_test

import (
	"fmt"
	"strings"

	"chainguard.dev/license/internal/digest"
)

// Line endings are normalized before hashing, so the same license text checked
// out with CRLF and with LF is one digest rather than two.
func ExampleBytes() {
	unix := digest.Bytes([]byte("MIT License\n\nPermission is granted.\n"))
	windows := digest.Bytes([]byte("MIT License\r\n\r\nPermission is granted.\r\n"))

	fmt.Println(unix == windows)
	fmt.Println(strings.HasPrefix(unix, digest.Prefix))
	// Output:
	// true
	// true
}

// File is the streaming form, for a file whose size should not decide how much
// memory the process holds.
func ExampleFile() {
	got, err := digest.File(strings.NewReader("MIT License\r\n"))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(got == digest.Bytes([]byte("MIT License\n")))
	// Output: true
}

// Hex is for a caller rendering the digest into a name of its own rather than
// an "<algo>:<hex>" digest.
func ExampleHex() {
	fmt.Println(len(digest.Hex([]byte("MIT License\n"))))
	// Output: 64
}
