/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"chainguard.dev/license/component"
)

func sha512SRI(b []byte) string {
	sum := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// npmRegistry serves tarballs at the paths the public registry uses.
func npmRegistry(t *testing.T, files map[string][]byte) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := files[r.URL.Path]; ok {
			w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
}

func TestNpmResolverFetchVerifiesIntegrity(t *testing.T) {
	// A tarball nests everything under "package", whatever the package is named.
	tgz := makeTarGz(t, "package", map[string]string{
		"package.json": `{"name":"lodash","version":"4.17.21","license":"MIT"}`,
		"LICENSE":      "MIT License",
		"lodash.js":    "module.exports = {}",
	})
	srv := npmRegistry(t, map[string][]byte{"/lodash/-/lodash-4.17.21.tgz": tgz})
	defer srv.Close()

	r := &NpmResolver{client: serverClient(t, srv), base: serverURL()}
	art, err := r.Fetch(t.Context(), component.Component{
		Name: "lodash", Version: "4.17.21", Digest: sha512SRI(tgz), Ecosystem: "npm",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// The lockfile hash is an independent witness, so this is a real agreement
	// between two sources rather than the registry vouching for itself.
	if !art.Matched {
		t.Error("Matched: got false, want the tarball to verify against the lockfile integrity")
	}
	if got := readFile(t, art.FS, "package.json"); got == "" {
		t.Error("package.json: got empty, want it at the root once the prefix is stripped")
	}
	if _, err := fs.Stat(art.FS, "LICENSE"); err != nil {
		t.Errorf("LICENSE: got err = %v, want the file to be retained", err)
	}
	if _, err := fs.Stat(art.FS, "lodash.js"); err == nil {
		t.Error("source files should not survive expansion")
	}
}

// TestNpmResolverScopedPackageURL pins the registry's layout: the scope stays in
// the path but the filename is the bare package name.
func TestNpmResolverScopedPackageURL(t *testing.T) {
	tgz := makeTarGz(t, "package", map[string]string{"package.json": `{"name":"@babel/core"}`})
	srv := npmRegistry(t, map[string][]byte{"/@babel/core/-/core-7.24.0.tgz": tgz})
	defer srv.Close()

	r := &NpmResolver{client: serverClient(t, srv), base: serverURL()}
	if _, err := r.Fetch(t.Context(), component.Component{Name: "@babel/core", Version: "7.24.0"}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
}

// TestNpmResolverMatchesTheRecordedAlgorithm covers old lockfiles: hashing with
// sha512 when sha1 was recorded produces a value that can neither agree nor
// disagree with it.
func TestNpmResolverMatchesTheRecordedAlgorithm(t *testing.T) {
	tgz := makeTarGz(t, "package", map[string]string{"package.json": `{"name":"old"}`})
	sri, err := integrityOf("sha1-", stagedArtifact(t, tgz))
	if err != nil {
		t.Fatalf("integrityOf: %v", err)
	}
	srv := npmRegistry(t, map[string][]byte{"/old/-/old-1.0.0.tgz": tgz})
	defer srv.Close()

	r := &NpmResolver{client: serverClient(t, srv), base: serverURL()}
	art, err := r.Fetch(t.Context(), component.Component{Name: "old", Version: "1.0.0", Digest: sri})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !art.Matched {
		t.Errorf("got digest = %q, want it to verify against the recorded sha1", art.Digest)
	}
}

func TestNpmResolverDetectsTamperedTarball(t *testing.T) {
	tgz := makeTarGz(t, "package", map[string]string{"LICENSE": "MIT"})
	srv := npmRegistry(t, map[string][]byte{"/app/-/app-1.0.0.tgz": tgz})
	defer srv.Close()

	r := &NpmResolver{client: serverClient(t, srv), base: serverURL()}
	art, err := r.Fetch(t.Context(), component.Component{
		Name: "app", Version: "1.0.0", Digest: sha512SRI([]byte("something else")),
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if art.Matched {
		t.Error("Matched: got true, want false when the bytes disagree with the lockfile")
	}
}

func TestNpmResolverMissingVersionIsGone(t *testing.T) {
	srv := npmRegistry(t, nil)
	defer srv.Close()

	r := &NpmResolver{client: serverClient(t, srv), base: serverURL()}
	_, err := r.Fetch(t.Context(), component.Component{Name: "nope", Version: "1.0.0"})
	if !errors.Is(err, ErrGone) {
		t.Errorf("got = %v, want ErrGone", err)
	}
}

func TestNpmResolverRejectsIncompleteCoordinates(t *testing.T) {
	r := NewNpmResolver(nil)
	if _, err := r.Fetch(t.Context(), component.Component{Name: "lodash"}); err == nil {
		t.Error("Fetch: got nil error, want one for a component with no version")
	}
}

func TestIntegrityOfUnsupportedAlgorithm(t *testing.T) {
	if _, err := integrityOf("md5-abc", stagedArtifact(t, []byte("x"))); err == nil {
		t.Error("integrityOf: got nil error, want an unsupported algorithm to be reported")
	}
}

// stagedArtifact writes bytes to a temp file so they can be passed where a
// downloaded artifact is expected.
func stagedArtifact(t *testing.T, data []byte) *fetched {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "artifact-*")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return &fetched{f: f, size: int64(len(data))}
}
