/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package spdx

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
)

//go:generate go run ./internal/cmd/gen -out tables.go

// licensesJSON is the SPDX license list, reduced to the fields we consult and
// vendored so that neither a build nor a determination depends on network
// access to spdx.org. Refresh it deliberately with the generator.
//
//go:embed licenses.json
var licensesJSON []byte

// licenseList is the parsed shape of licenses.json.
type licenseList struct {
	Version  string `json:"licenseListVersion"`
	Licenses []struct {
		ID         string   `json:"id"`
		Name       string   `json:"name"`
		Deprecated bool     `json:"deprecated"`
		URLs       []string `json:"urls"`
	} `json:"licenses"`
	Exceptions []string `json:"exceptions"`
}

var (
	loadOnce sync.Once
	listVer  string
	current  map[string]string // lowercased id -> canonical id, current ids only
	deprecat map[string]string // lowercased id -> canonical id, deprecated ids
	byName   map[string]string // normalized name -> canonical id
	byURL    map[string]string // normalized url -> canonical id
	exceptID map[string]string // lowercased exception id -> canonical
)

func load() {
	loadOnce.Do(func() {
		var l licenseList
		if err := json.Unmarshal(licensesJSON, &l); err != nil {
			// The file is vendored and generated; a parse failure is a build
			// defect rather than a runtime condition.
			panic("spdx: parsing vendored license list: " + err.Error())
		}
		listVer = l.Version
		current = make(map[string]string, len(l.Licenses))
		deprecat = make(map[string]string, 32)
		byName = make(map[string]string, len(l.Licenses))
		byURL = make(map[string]string, len(l.Licenses)*2)
		exceptID = make(map[string]string, len(l.Exceptions))
		for _, lic := range l.Licenses {
			if lic.Deprecated {
				deprecat[strings.ToLower(lic.ID)] = lic.ID
			} else {
				current[strings.ToLower(lic.ID)] = lic.ID
			}
			// A deprecated entry must never win a name or URL lookup away from
			// the current identifier that replaced it.
			if k := normalizeText(lic.Name); k != "" && !lic.Deprecated {
				byName[k] = lic.ID
			}
			for _, u := range lic.URLs {
				if k := normalizeURL(u); k != "" && !lic.Deprecated {
					byURL[k] = lic.ID
				}
			}
		}
		for _, e := range l.Exceptions {
			exceptID[strings.ToLower(e)] = e
		}
	})
}

// ListVersion reports the SPDX license list release the vendored data came from.
func ListVersion() string { load(); return listVer }

// Resolution is what a license identifier normalizes to. Exactly one of ID,
// GrantBase and Ref is set.
type Resolution struct {
	// ID is a current SPDX identifier or expression.
	ID string
	// GrantBase names a GPL-family license whose SPDX identifier depends on a
	// version grant the license text cannot express. Only and OrLater are the
	// two identifiers it could be; the caller decides between them from the
	// notice in the component's own source.
	GrantBase string
	Only      string
	OrLater   string
	// Ref is a real license with no SPDX identifier. It travels as a
	// LicenseRef- rather than being forced onto the nearest listed license.
	Ref string
}

// NeedsGrant reports whether the identifier is a GPL-family form whose -only or
// -or-later suffix is still undecided.
func (r Resolution) NeedsGrant() bool { return r.GrantBase != "" }

// Known reports whether the identifier resolved to SPDX at all.
func (r Resolution) Known() bool { return r.ID != "" || r.GrantBase != "" }

// Normalize maps a license name produced by a classifier onto SPDX.
//
// Names that are already current SPDX identifiers pass through. The rest are
// resolved through the generated table, which is derived from the classifier's
// own vocabulary rather than hand-written, so it cannot drift silently when the
// dependency is upgraded.
func Normalize(name string) Resolution {
	load()
	name = strings.TrimSpace(name)
	if name == "" {
		return Resolution{}
	}
	if id, ok := current[strings.ToLower(name)]; ok {
		return Resolution{ID: id}
	}
	if r, ok := classifierNames[name]; ok {
		return r
	}
	// Not a name the classifier is known to emit. Try the SPDX data directly
	// before giving up, so a caller normalizing declared metadata is served too.
	if id, ok := FromText(name); ok {
		return Resolution{ID: id}
	}
	return Resolution{Ref: name}
}

// FromText maps a free-text license string or a license URL onto an SPDX
// identifier, using SPDX's own name and seeAlso data rather than a hand-written
// synonym list.
//
// Ecosystem metadata is full of these: a pom naming "The Apache Software
// License, Version 2.0", an npm field carrying a bare URL. What it deliberately
// will not do is resolve a bare family name - "GPL", "BSD" - because those
// name no particular license and guessing one would invent a fact.
func FromText(s string) (string, bool) {
	load()
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if id, ok := current[strings.ToLower(s)]; ok {
		return id, true
	}
	if id, ok := byURL[normalizeURL(s)]; ok {
		return id, true
	}
	if id, ok := byName[normalizeText(s)]; ok {
		return id, true
	}
	// Common metadata phrasings that SPDX's own name field does not carry
	// verbatim, kept small and only for wordings the corpus actually contains.
	if id, ok := textSynonyms[normalizeText(s)]; ok {
		return id, true
	}
	return "", false
}

// IsDeprecated reports whether an identifier is a deprecated SPDX identifier.
func IsDeprecated(id string) bool {
	load()
	_, ok := deprecat[strings.ToLower(id)]
	return ok
}

// tagRe matches the SPDX-License-Identifier convention used in source headers.
// The classifier does not recognize these at all - a file whose only notice is
// a tag matches nothing - so they are read directly.
var tagRe = regexp.MustCompile(`SPDX-License-Identifier:\s*([A-Za-z0-9.+()\-]+(?:\s+(?:WITH|AND|OR)\s+[A-Za-z0-9.+()\-]+)*)`)

// Tag extracts an SPDX-License-Identifier expression from source text.
func Tag(s string) (string, bool) {
	m := tagRe.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return strings.TrimSpace(m[1]), true
}

// HeaderGrant reports the version grant a classifier header match states.
//
// The classifier names every variant of a GPL header after the license alone,
// so a match on the "or later" wording and a match on the bare-version wording
// both come back as "GPL-2.0". The variant is what distinguishes them, and the
// generated table records which is which.
func HeaderGrant(name, variant string) (string, bool) {
	id, ok := headerVariants[headerKey{Name: name, Variant: variant}]
	return id, ok
}

// nonAlnum collapses everything that is not a letter or digit, so that
// "Apache License, Version 2.0" and "apache-license-version-2.0" compare equal.
var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func normalizeText(s string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(s), " "), " ")
}

// normalizeURL reduces a license URL to a comparable form: scheme, "www." and
// any trailing slash or file extension carry no meaning for identity.
func normalizeURL(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, p := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, p)
	}
	s = strings.TrimPrefix(s, "www.")
	s = strings.TrimSuffix(s, "/")
	for _, e := range []string{".txt", ".html", ".htm", ".php"} {
		s = strings.TrimSuffix(s, e)
	}
	if !strings.Contains(s, "/") && !strings.Contains(s, ".") {
		return ""
	}
	return s
}
