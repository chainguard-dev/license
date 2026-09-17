/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package evidence

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"chainguard.dev/license/detect"
)

// TestEncodeIsCanonical pins the property consumers store bundles under: the
// same observations encode to the same bytes, so rebuilding unchanged source is
// a storage no-op rather than a second copy of the same evidence.
func TestEncodeIsCanonical(t *testing.T) {
	fsys := tree(map[string]string{
		"LICENSE":      mitText,
		"README.md":    "Licensed under the MIT license.\n",
		"package.json": `{"name":"example","license":"MIT"}`,
		"main.go":      "// SPDX-License-Identifier: MIT\npackage main\n",
	})

	first, err := Collect(t.Context(), subject(fsys), Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Collect(t.Context(), subject(fsys), Options{})
	if err != nil {
		t.Fatal(err)
	}

	a, err := first.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	b, err := second.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two collections over the same tree encoded to different bytes")
	}

	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Errorf("digests differ: %s and %s", firstDigest, secondDigest)
	}

	// Encoding the same bundle twice is stable too, which is what makes the
	// digest safe to compute more than once.
	again, err := first.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, again) {
		t.Error("encoding one bundle twice produced different bytes")
	}
}

// TestEncodeCarriesTheSchemaVersion keeps a reader from having to infer which
// rules produced a stored bundle.
func TestEncodeCarriesTheSchemaVersion(t *testing.T) {
	b, err := Collect(t.Context(), subject(tree(map[string]string{"LICENSE": mitText})), Options{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}

	var decoded struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decoding the encoded bundle: %v", err)
	}
	if decoded.SchemaVersion != SchemaVersion {
		t.Errorf("schema version: got = %d, want = %d", decoded.SchemaVersion, SchemaVersion)
	}
}

// TestEncodeChangesWithTheObservations is the other half of canonical
// encoding: a bundle that recorded something different has to encode
// differently, or a changed observation would read as a cache hit.
func TestEncodeChangesWithTheObservations(t *testing.T) {
	first, err := Collect(t.Context(), subject(tree(map[string]string{"LICENSE": mitText})), Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Collect(t.Context(), subject(tree(map[string]string{"LICENSE": eulaText})), Options{})
	if err != nil {
		t.Fatal(err)
	}

	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest == secondDigest {
		t.Error("bundles over different license texts share a digest")
	}
}

// TestEncodeLeavesLicenseTextReadable verifies the encoder does not escape the
// punctuation license texts are full of, so a stored bundle stays readable by
// anything that reads JSON.
func TestEncodeLeavesLicenseTextReadable(t *testing.T) {
	b, err := Collect(t.Context(), subject(tree(map[string]string{
		"LICENSE": "Copyright (c) 2026 <holder> & contributors\n" + mitText,
	})), Options{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `\u003c`) {
		t.Error("the encoding escaped the angle brackets in a license text")
	}
	if !strings.Contains(string(encoded), "<holder>") {
		t.Error("the license text did not survive encoding verbatim")
	}
}

// TestEncodeUsesStableFieldNames guards the wire format. A bundle is stored and
// read back by other tools, so a Go field name leaking into the JSON - which is
// what happens the moment a type reachable from here is missing its tags - is a
// format break dressed as a refactor.
func TestEncodeUsesStableFieldNames(t *testing.T) {
	b, err := Collect(t.Context(), subject(tree(map[string]string{"LICENSE": mitText})), Options{})
	if err != nil {
		t.Fatal(err)
	}
	b.Subject.Source.Repository = "https://github.com/example/project"
	b.Subject.Declared = []detect.Declaration{{License: "MIT"}}

	encoded, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}

	// Every key in the document, at every depth.
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			for key, child := range v {
				if key != strings.ToLower(key) {
					t.Errorf("key %q is not snake_case, so a Go field name reached the wire format", key)
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(decoded)

	// And the two that were missing tags, by name.
	for _, want := range []string{`"repository"`, `"license"`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("encoded bundle is missing %s", want)
		}
	}
}
