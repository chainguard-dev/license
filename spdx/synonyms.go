/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package spdx

// textSynonyms are license phrasings common in ecosystem metadata that SPDX's
// own name field does not carry verbatim. Keys are normalizeText output.
//
// Hand-curated rather than generated, because each entry is a judgment that two
// differently-worded strings name the same license. Kept deliberately short and
// drawn from wordings measured in the corpus rather than invented: pom
// <name> fields and npm license strings account for nearly all of it.
//
// Bare family names are deliberately absent. "GPL", "BSD" and "PROPRIETARY"
// name no particular license, and resolving them to a guess would invent a fact
// the metadata does not contain - they stay unresolved and travel as a
// LicenseRef.
var textSynonyms = map[string]string{
	// Apache, by far the most-mangled in the corpus.
	"the apache software license version 2 0": "Apache-2.0",
	"apache software license version 2 0":     "Apache-2.0",
	"apache license version 2 0":              "Apache-2.0",
	"the apache license version 2 0":          "Apache-2.0",
	"apache public license 2 0":               "Apache-2.0",
	"apache 2":                                "Apache-2.0",
	"apache 2 0":                              "Apache-2.0",
	"asl 2 0":                                 "Apache-2.0",

	// MIT and BSD, where the metadata usually spells out "License".
	"the mit license":          "MIT",
	"mit license":              "MIT",
	"the bsd 3 clause license": "BSD-3-Clause",
	"bsd 3 clause license":     "BSD-3-Clause",
	"new bsd license":          "BSD-3-Clause",
	"the new bsd license":      "BSD-3-Clause",
	"modified bsd license":     "BSD-3-Clause",
	"bsd 2 clause license":     "BSD-2-Clause",
	"simplified bsd license":   "BSD-2-Clause",
	"the bsd 2 clause license": "BSD-2-Clause",

	// Eclipse, which the corpus carries mostly as URLs but also as prose.
	"eclipse public license v2 0":       "EPL-2.0",
	"eclipse public license 2 0":        "EPL-2.0",
	"eclipse public license v1 0":       "EPL-1.0",
	"eclipse public license 1 0":        "EPL-1.0",
	"eclipse distribution license v1 0": "BSD-3-Clause",

	// Mozilla and the CDDL family.
	"mozilla public license version 2 0":                    "MPL-2.0",
	"mozilla public license 2 0":                            "MPL-2.0",
	"common development and distribution license 1 0 cddl":  "CDDL-1.0",
	"common development and distribution license cddl v1 0": "CDDL-1.0",

	// Python, whose metadata predates SPDX naming.
	"python software foundation license": "PSF-2.0",
	"psf license":                        "PSF-2.0",
	"python license":                     "Python-2.0",
	"zope public license":                "ZPL-2.1",

	// Eclipse and Jakarta poms, whose abbreviations SPDX carries under quite
	// different names. EDL is the Eclipse Distribution License, which is
	// BSD-3-Clause word for word.
	//
	// The GPL abbreviation that travels beside these - "GPL2 w/ CPE" - is
	// deliberately absent. It names no version grant, and resolving it to
	// GPL-2.0-only or -or-later would be guessing at exactly the distinction a
	// declaration is supposed to settle.
	"edl 1 0":                              "BSD-3-Clause",
	"eclipse distribution license edl 1 0": "BSD-3-Clause",
	"eclipse distribution license v 1 0":   "BSD-3-Clause",
	"eclipse public license v 2 0":         "EPL-2.0",
	"epl 2 0":                              "EPL-2.0",
	"epl 1 0":                              "EPL-1.0",
	"cddl 1 0":                             "CDDL-1.0",
	"cddl 1 1":                             "CDDL-1.1",

	// The MIT wording npm and pom metadata carries most often.
	"the mit license mit": "MIT",
}
