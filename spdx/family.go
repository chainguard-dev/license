/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package spdx

import (
	"regexp"
	"strings"
)

// versionSegmentRe matches a path segment that is entirely a version or a date:
// the point at which an identifier stops naming a family and starts naming a
// particular license.
//
// Entirely numeric is the whole test, and it has to be. "3D-Slicer-1.0" begins
// with a digit without being versioned there, and truncating at the first
// segment that merely starts with one would reduce it to nothing.
var versionSegmentRe = regexp.MustCompile(`^\d+(\.\d+)*$`)

// irregularFamilies are identifiers whose family the segment rule cannot
// derive, because the version is not a segment of its own.
//
// Kept deliberately short: an entry here is a claim that two identifiers name
// the same body of terms, which is a judgment rather than a spelling rule.
var irregularFamilies = map[string]string{
	"0BSD": "BSD",
}

// Family reports the license family an identifier belongs to, or "" for an
// identifier with no family: a LicenseRef, whose terms are whatever its text
// says, or an unparseable string.
//
// The family is the identifier up to its first version segment, so
// BSD-3-Clause, BSD-2-Clause-Views and 0BSD are all BSD, and GPL-2.0-only and
// GPL-3.0-or-later are both GPL. An identifier carrying a WITH exception takes
// the family of the license, since an exception narrows terms rather than
// replacing them.
//
// Families are deliberately unordered. A consumer deciding that a change from
// one family to another is worth stopping a merge over is applying a policy,
// and this package holds no policy: it says which family, never which is worse.
func Family(id string) string {
	license, _, _ := strings.Cut(strings.TrimSpace(id), " "+OperatorWith+" ")
	license = strings.TrimSuffix(strings.TrimSpace(license), "+")
	if license == "" || IsRef(license) {
		return ""
	}
	if family, ok := irregularFamilies[license]; ok {
		return family
	}

	segments := strings.Split(license, "-")
	for i, seg := range segments {
		if versionSegmentRe.MatchString(seg) {
			if i == 0 {
				// Nothing precedes the version, so there is no family to name.
				return ""
			}
			return strings.Join(segments[:i], "-")
		}
	}
	return license
}
