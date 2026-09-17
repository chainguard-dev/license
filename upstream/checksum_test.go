/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"chainguard.dev/license/component"
)

// goSumResponse is the shape sum.golang.org's lookup endpoint answers with: the
// module's records, then the signed tree head. Only the records are read.
const goSumResponse = `4321
github.com/example/mod v1.2.3 h1:GENUINEHASH=
github.com/example/mod v1.2.3/go.mod h1:GOMODHASHONLY=

go.sum database tree
5678
`

func TestChecksumLookupGo(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/lookup/") {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, goSumResponse)
	}))
	defer srv.Close()

	sums := &Checksums{client: serverClient(t, srv), goSumDB: serverURL()}

	for _, tt := range []struct {
		name        string
		digest      string
		wantMatched bool
	}{
		{
			name:        "the digest the database recorded",
			digest:      "h1:GENUINEHASH=",
			wantMatched: true,
		},
		{
			// The case the check exists for: bytes that hash to something the
			// ecosystem never published.
			name:   "a digest the database does not know",
			digest: "h1:TAMPERED=",
		},
		{
			// Nothing to compare against is not a match. A caller that needs to
			// tell this from a mismatch checks whether it supplied a digest.
			name:   "no digest to compare",
			digest: "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sums.Lookup(t.Context(), component.Component{
				Ecosystem: component.EcosystemGo,
				Name:      "github.com/example/mod",
				Version:   "v1.2.3",
				Digest:    tt.digest,
			})
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			// The go.mod-only line covers the manifest rather than the content,
			// so it must never be the recorded digest.
			if got.Recorded != "h1:GENUINEHASH=" {
				t.Errorf("recorded: got = %q, want the module zip's hash", got.Recorded)
			}
			if got.Matched != tt.wantMatched {
				t.Errorf("matched: got = %v, want = %v", got.Matched, tt.wantMatched)
			}
			if got.Source == "" {
				t.Error("source is empty, so the result cannot be re-checked by hand")
			}
		})
	}
}

// TestChecksumLookupGoUnknownVersion covers a module the database has no record
// of, which is reported as no record rather than as a mismatch.
func TestChecksumLookupGoUnknownVersion(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "4321\nother.example/mod v1.0.0 h1:OTHER=\n")
	}))
	defer srv.Close()

	sums := &Checksums{client: serverClient(t, srv), goSumDB: serverURL()}

	got, err := sums.Lookup(t.Context(), component.Component{
		Ecosystem: component.EcosystemGo,
		Name:      "github.com/example/mod",
		Version:   "v1.2.3",
		Digest:    "h1:ANYTHING=",
	})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Recorded != "" || got.Matched {
		t.Errorf("got = %+v, want no record and no match", got)
	}
}

func TestChecksumLookupCargo(t *testing.T) {
	const checksum = "5f0e2c6ed6606019b4e29e69dbaba95b11854410e5347d525002456dbbb786b6"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"version":{"checksum":%q}}`, checksum)
	}))
	defer srv.Close()

	sums := &Checksums{client: serverClient(t, srv), cratesAPI: serverURL()}

	got, err := sums.Lookup(t.Context(), component.Component{
		Ecosystem: component.EcosystemCargo,
		Name:      "serde",
		Version:   "1.0.219",
		Digest:    checksum,
	})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !got.Matched || got.Recorded != checksum {
		t.Errorf("got = %+v, want a match on the recorded checksum", got)
	}
}

func TestChecksumLookupMaven(t *testing.T) {
	const sha1 = "0123456789abcdef0123456789abcdef01234567"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, ".jar.sha1") {
			http.NotFound(w, r)
			return
		}
		// Central writes the digest, sometimes followed by a filename.
		fmt.Fprintf(w, "%s  guava-33.0.0-jre.jar\n", strings.ToUpper(sha1))
	}))
	defer srv.Close()

	sums := &Checksums{client: serverClient(t, srv), mavenBase: serverURL()}

	got, err := sums.Lookup(t.Context(), component.Component{
		Ecosystem: component.EcosystemMaven,
		Name:      "com.google.guava:guava",
		Version:   "33.0.0-jre",
		Digest:    sha1,
	})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !got.Matched {
		t.Errorf("got = %+v, want a match; the comparison must not be case-sensitive", got)
	}
}

// TestChecksumLookupUnsupported covers the ecosystems with no database
// independent of their artifacts. Reporting a match there would claim
// corroboration that does not exist.
func TestChecksumLookupUnsupported(t *testing.T) {
	sums := NewChecksums(nil)
	for _, ecosystem := range []component.Ecosystem{component.EcosystemPyPI, component.EcosystemNpm, "nuget"} {
		t.Run(ecosystem, func(t *testing.T) {
			_, err := sums.Lookup(t.Context(), component.Component{Ecosystem: ecosystem, Name: "x", Version: "1"})
			if !errors.Is(err, ErrUnsupported) {
				t.Errorf("got = %v, want ErrUnsupported", err)
			}
		})
	}
}

// TestChecksumLookupMavenRefusesTraversalCoordinates covers the coordinates a
// Maven checksum URL is built from.
//
// They come out of a POM the registry served or a jar's pom.properties, so a
// version carrying ".." walks the path to a different artifact's .jar.sha1.
// The lookup would then report that artifact's digest as the one Central
// recorded for this component, which is the opposite of an independent
// witness: the caller is told a digest matched something it did not.
func TestChecksumLookupMavenRefusesTraversalCoordinates(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("a request was made for %s; the coordinate should have been refused first", r.URL.Path)
	}))
	defer srv.Close()
	sums := &Checksums{client: serverClient(t, srv), mavenBase: serverURL()}

	for _, tc := range []struct{ name, coords, version string }{
		{"version escapes the artifact directory", "com.google.guava:guava", "../../other/1.0/other-1.0"},
		{"artifact escapes the group directory", "com.google.guava:..", "33.0.0"},
		{"a group segment is empty", "com.google..guava:guava", "33.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sums.Lookup(t.Context(), component.Component{
				Ecosystem: component.EcosystemMaven,
				Name:      tc.coords,
				Version:   tc.version,
			}); err == nil {
				t.Fatal("Lookup: got nil error, want the coordinate to be refused")
			}
		})
	}
}

// TestChecksumLookupReportsAMismatch covers the answer the lookup exists to
// give. Reporting a match is not the security-critical direction: reporting
// one where the database recorded a different digest is, and a regression
// flipping the comparison for cargo or maven would otherwise pass the suite.
//
// Recorded stays populated either way, so a caller can see what the database
// holds rather than only that it disagreed.
func TestChecksumLookupReportsAMismatch(t *testing.T) {
	const recorded = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const theirs = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	t.Run("cargo", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, `{"version":{"checksum":%q}}`, recorded)
		}))
		defer srv.Close()
		sums := &Checksums{client: serverClient(t, srv), cratesAPI: serverURL()}

		got, err := sums.Lookup(t.Context(), component.Component{
			Ecosystem: component.EcosystemCargo, Name: "serde", Version: "1.0.200", Digest: theirs,
		})
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if got.Matched {
			t.Error("a digest the database did not record was reported as matched")
		}
		if got.Recorded != recorded {
			t.Errorf("recorded: got = %q, want %q", got.Recorded, recorded)
		}
	})

	t.Run("maven", func(t *testing.T) {
		const sha1 = "0123456789abcdef0123456789abcdef01234567"
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, ".jar.sha1") {
				http.NotFound(w, r)
				return
			}
			fmt.Fprintf(w, "%s  guava-33.0.0-jre.jar\n", sha1)
		}))
		defer srv.Close()
		sums := &Checksums{client: serverClient(t, srv), mavenBase: serverURL()}

		got, err := sums.Lookup(t.Context(), component.Component{
			Ecosystem: component.EcosystemMaven, Name: "com.google.guava:guava",
			Version: "33.0.0-jre", Digest: "ffffffffffffffffffffffffffffffffffffffff",
		})
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if got.Matched {
			t.Error("a digest Central did not record was reported as matched")
		}
		if got.Recorded != sha1 {
			t.Errorf("recorded: got = %q, want %q", got.Recorded, sha1)
		}
	})
}
