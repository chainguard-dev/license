/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package contenthash

import (
	"chainguard.dev/license/internal/digest"
	"chainguard.dev/license/spdx"
)

// RefScheme names the version of the LicenseRef derivation. See Scheme for why
// the two keys are versioned apart.
const RefScheme = "v1"

// refDigestChars is how much of the digest a LicenseRef name carries. Sixteen
// hexadecimal characters is 64 bits, which is ample against collision among the
// licenses a fleet carries while keeping the name short enough to read in a
// table.
const refDigestChars = 16

// LicenseRef mints the SPDX name for a license whose text nothing recognized.
//
// The name is a digest of one license file, not of a component: identical text
// therefore yields the same name in every component carrying it, which is what
// makes a single curation entry able to name a EULA once for the whole fleet.
// Line endings are normalized first, so the same text checked out two ways is
// one license rather than two.
//
// The name is internal plumbing, not a customer-facing answer. It says only
// "this exact license text", and a consumer serving it to anyone should map it
// to a name a human wrote first.
func LicenseRef(text []byte) string {
	if len(text) == 0 {
		return ""
	}
	return spdx.RefPrefix + RefScheme + "-" + digest.Hex(text)[:refDigestChars]
}
