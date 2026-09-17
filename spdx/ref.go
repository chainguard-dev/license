/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package spdx

import "strings"

// RefPrefix is the SPDX prefix for a license with no SPDX identifier. See
// https://spdx.github.io/spdx-spec/SPDX-license-expressions/.
//
// Deriving the name for an unrecognized license text is contenthash's
// LicenseRef, not this package's: the name is a digest, and it is one of two
// durable keys that have to share one normalization and be versioned together
// with the other. What lives here is the vocabulary - the prefix, and what
// counts as a ref.
const RefPrefix = "LicenseRef-"

// IsRef reports whether an identifier is a LicenseRef rather than a listed
// SPDX license.
//
// It is the test that keeps a real license from being forced onto the nearest
// listed one. A proprietary EULA has no SPDX identifier and never will, and
// classifying it as the closest match would state terms its author never
// granted.
func IsRef(id string) bool {
	return strings.HasPrefix(strings.TrimSpace(id), RefPrefix)
}

// Ref renders a name as a LicenseRef identifier, adding the prefix only when it
// is not already there, so that a curated name and a bare one both arrive in
// the same form.
func Ref(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || IsRef(name) {
		return name
	}
	return RefPrefix + name
}
