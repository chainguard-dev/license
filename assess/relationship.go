/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package assess

import (
	"regexp"

	"chainguard.dev/license/detect"
)

// choiceOfLicenseRes match statements that a project offers a choice between
// its licenses rather than imposing all of them.
//
// Only the choice direction is inferred, and only from wording that states it
// outright. Inferring the wrong direction is not symmetric: reading a
// conjunction as a choice tells a consumer they may pick the permissive license
// and ignore the other's obligations, while the reverse merely overstates what
// they owe. So a conjunction is never inferred from prose - several licenses
// with nothing authoritative composing them stay uncertain, which is what sends
// them to be read by something that can weigh the whole document.
var choiceOfLicenseRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bat your option\b`),
	regexp.MustCompile(`(?i)\bat the user'?s option\b`),
	// "triple-licensed" is what rustix and friends actually write, so the count
	// prefixes are spelled out rather than assumed to be abbreviated.
	regexp.MustCompile(`(?i)\b(dual|tri|triple|quad|multi)[\s-]*licen[sc]ed\b`),
	// "under either" rather than a bare "either ... or": the hints are already
	// filtered to license-mentioning lines, so "either the LICENSE file or the
	// COPYING file applies" would otherwise read as a choice of licenses.
	regexp.MustCompile(`(?i)\bunder either\b`),
	regexp.MustCompile(`(?i)\byour choice\b`),
	regexp.MustCompile(`(?i)\bchoice of (either|any|the following)\b`),
	regexp.MustCompile(`(?i)\bany of the following licen[sc]es\b`),
}

// ChoiceOfLicense reports whether a component's prose states a choice between
// its licenses, returning the line that says so.
//
// The hints it reads are already filtered to lines mentioning a license, so a
// match is a licensing statement rather than an unrelated sentence that happens
// to contain "either".
func ChoiceOfLicense(hints []detect.ProseHint) (detect.ProseHint, bool) {
	for _, h := range hints {
		for _, re := range choiceOfLicenseRes {
			if re.MatchString(h.Excerpt) {
				return h, true
			}
		}
	}
	return detect.ProseHint{}, false
}
