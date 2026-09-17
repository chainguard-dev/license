/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package component

import (
	"testing"

	"chainguard.dev/license/spdx"
	"github.com/google/go-cmp/cmp"
)

func TestManifests(t *testing.T) {
	fsys := tree(map[string]string{
		"package.json":   `{"name":"x","license":"MIT"}`,
		"Cargo.toml":     "[package]\nname=\"x\"\nlicense=\"MIT OR Apache-2.0\"\n",
		"pom.xml":        `<project><licenses><license><name>Apache-2.0</name></license></licenses></project>`,
		"pyproject.toml": "[project]\nname=\"x\"\nlicense=\"ISC\"\n",
		// A manifest with no license field contributes nothing rather than an
		// empty declaration, which would read as "declared nothing" when the
		// truth is "this format cannot declare".
		"go.mod": "module example.com/x\n",
	})

	got := map[string]string{}
	for _, m := range Manifests(fsys) {
		got[m.Path] = m.License
	}
	want := map[string]string{
		"package.json":   "MIT",
		"Cargo.toml":     "MIT OR Apache-2.0",
		"pom.xml":        "Apache-2.0",
		"pyproject.toml": "ISC",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Manifests (-want, +got):\n%s", diff)
	}
}

// TestManifestsOnlyReadsTheRoot keeps a dependency's manifest from declaring
// the licensing of the component that vendored it.
func TestManifestsOnlyReadsTheRoot(t *testing.T) {
	fsys := tree(map[string]string{
		"package.json":                       `{"license":"MIT"}`,
		"node_modules/left-pad/package.json": `{"license":"WTFPL"}`,
	})
	got := Manifests(fsys)
	if len(got) != 1 || got[0].License != "MIT" {
		t.Errorf("Manifests: got = %+v, want only the root declaration", got)
	}
}

// TestNpmLicenseShapes covers the forms the field has been written in over the
// years. The deprecated array form was a choice, so it composes with OR.
func TestNpmLicenseShapes(t *testing.T) {
	for _, tt := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "string", content: `{"license":"MIT"}`, want: "MIT"},
		{name: "object with a type", content: `{"license":{"type":"BSD-2-Clause"}}`, want: "BSD-2-Clause"},
		{name: "legacy array", content: `{"licenses":[{"type":"MIT"},{"type":"Apache-2.0"}]}`, want: "MIT OR Apache-2.0"},
		{name: "array of strings", content: `{"license":["MIT","ISC"]}`, want: "MIT OR ISC"},
		{name: "url only", content: `{"license":{"url":"https://example.com/terms"}}`, want: "https://example.com/terms"},
		{name: "absent", content: `{"name":"x"}`, want: ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fsys := tree(map[string]string{"package.json": tt.content})
			if got := DeclaredLicense(fsys, EcosystemNpm); got != tt.want {
				t.Errorf("DeclaredLicense: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// TestCargoLicenseFileIsNotAnIdentifier verifies that a crate pointing at a
// bundled license file is recorded as declaring nothing machine-readable, with
// the pointer kept out of the identifier field entirely.
//
// A filename in that field would be published as a license, and shaping it as a
// LicenseRef would put it in the namespace that names license texts by digest,
// where a curation entry could never match it.
func TestCargoLicenseFileIsNotAnIdentifier(t *testing.T) {
	fsys := tree(map[string]string{"Cargo.toml": "[package]\nlicense-file = \"LICENSE.custom\"\n"})

	if got := DeclaredLicense(fsys, EcosystemCargo); got != "" {
		t.Errorf("DeclaredLicense: got = %q, want no declared identifier", got)
	}

	manifests := Manifests(fsys)
	if len(manifests) != 1 {
		t.Fatalf("Manifests: got = %d, want the pointer recorded", len(manifests))
	}
	if got := manifests[0].LicenseFile; got != "LICENSE.custom" {
		t.Errorf("LicenseFile: got = %q, want = %q", got, "LICENSE.custom")
	}
	if got := manifests[0].License; got != "" {
		t.Errorf("License: got = %q, want empty", got)
	}
	if spdx.IsRef(manifests[0].LicenseFile) {
		t.Error("a license-file pointer must not land in the LicenseRef namespace")
	}
}

// TestDeclaredMavenPrefersTheNearestPOM covers Maven inheritance, where most
// POMs declare nothing themselves. Nearest to furthest is Maven's own
// precedence.
func TestDeclaredMavenPrefersTheNearestPOM(t *testing.T) {
	fsys := tree(map[string]string{
		POMName(0): `<project><parent><groupId>g</groupId><artifactId>p</artifactId><version>1</version></parent></project>`,
		POMName(1): `<project><licenses><license><name>Apache-2.0</name></license></licenses></project>`,
	})
	if got := DeclaredLicense(fsys, EcosystemMaven); got != "Apache-2.0" {
		t.Errorf("DeclaredLicense: got = %q, want the inherited declaration", got)
	}
}

// TestDeclaredMavenSeveralLicensesComposeWithOr pins the direction Maven's own
// reference states. Getting it backwards reports an obligation nobody has.
func TestDeclaredMavenSeveralLicensesComposeWithOr(t *testing.T) {
	fsys := tree(map[string]string{
		POMName(0): `<project><licenses>` +
			`<license><name>EPL-2.0</name></license>` +
			`<license><name>GPL-2.0-only WITH Classpath-exception-2.0</name></license>` +
			`</licenses></project>`,
	})
	want := "EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0"
	if got := DeclaredLicense(fsys, EcosystemMaven); got != want {
		t.Errorf("DeclaredLicense: got = %q, want = %q", got, want)
	}
}

// TestDeclaredPyPIPrefersTheExpressionField covers PEP 639: License-Expression
// means exactly one thing, while the legacy field is free text that projects
// paste whole license bodies into.
func TestDeclaredPyPIPrefersTheExpressionField(t *testing.T) {
	for _, tt := range []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "expression wins over legacy",
			content: "Name: x\nVersion: 1\nLicense: see LICENSE\nLicense-Expression: MIT\n\nbody",
			want:    "MIT",
		},
		{
			name:    "legacy is read when it is the only one",
			content: "Name: x\nVersion: 1\nLicense: BSD-3-Clause\n\nbody",
			want:    "BSD-3-Clause",
		},
		{
			name:    "a pasted license body is not a declaration",
			content: "Name: x\nVersion: 1\nLicense: " + longLicenseText + "\n\nbody",
			want:    "",
		},
		{
			name:    "headers stop at the blank line",
			content: "Name: x\nVersion: 1\n\nLicense: MIT\n",
			want:    "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fsys := tree(map[string]string{"PKG-INFO": tt.content})
			if got := DeclaredLicense(fsys, EcosystemPyPI); got != tt.want {
				t.Errorf("DeclaredLicense: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// longLicenseText stands in for the license body projects paste into the legacy
// License field, which is longer than any real identifier.
var longLicenseText = func() string {
	s := "Permission is hereby granted free of charge to any person obtaining a copy of this software"
	for len(s) <= maxDeclaredLicenseChars {
		s += " and associated documentation files"
	}
	return s
}()

func TestIsManifestFile(t *testing.T) {
	for _, tt := range []struct {
		name string
		want bool
	}{
		{"package.json", true},
		{"Cargo.toml", true},
		{"pom.xml", true},
		{"go.mod", true},
		{"METADATA", true},
		{"PKG-INFO", true},
		// Ruby and PHP are non-goals, so their manifests are not recognized
		// even though the formats are well known.
		{"rails.gemspec", false},
		{"composer.json", false},
		{"README.md", false},
		{"LICENSE", false},
		{"Cargo.lock", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsManifestFile(tt.name); got != tt.want {
				t.Errorf("IsManifestFile(%q): got = %v, want = %v", tt.name, got, tt.want)
			}
		})
	}
}
