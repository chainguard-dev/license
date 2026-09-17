/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"

	"chainguard.dev/license/component"
)

// pypiIndex serves a release's metadata and its files, mirroring the shape of
// the real index: the JSON names the archives, the archives live elsewhere.
func pypiIndex(t *testing.T, name, version string, files map[string][]byte, meta []map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := files[r.URL.Path]; ok {
			w.Write(body)
			return
		}
		if r.URL.Path != fmt.Sprintf("/pypi/%s/%s/json", name, version) {
			http.NotFound(w, r)
			return
		}
		urls := make([]map[string]any, 0, len(meta))
		for _, m := range meta {
			m["url"] = serverURL() + m["path"].(string)
			delete(m, "path")
			urls = append(urls, m)
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"urls": urls}); err != nil {
			t.Errorf("encoding index response: %v", err)
		}
	}))
}

// makeWheel builds a zip whose entries sit at the root, which is how a wheel is
// laid out. makeZip always nests under a prefix, and passing it an empty one
// yields leading slashes rather than root-level names.
func makeWheel(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := io.WriteString(w, content); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestPyPIResolverPrefersSdist(t *testing.T) {
	const pkgInfo = "Metadata-Version: 2.4\nName: zope.interface\nVersion: 8.0.1\nLicense-Expression: ZPL-2.1\n\nlong description\n"
	sdist := makeTarGz(t, "zope.interface-8.0.1", map[string]string{
		"PKG-INFO": pkgInfo,
		"LICENSE":  "Zope Public License",
		"README":   "licensed under the ZPL",
	})
	wheel := makeWheel(t, map[string]string{"zope_interface-8.0.1.dist-info/METADATA": pkgInfo})

	srv := pypiIndex(t, "zope-interface", "8.0.1",
		map[string][]byte{"/f/sdist.tar.gz": sdist, "/f/wheel.whl": wheel},
		[]map[string]any{
			{"path": "/f/wheel.whl", "filename": "zope_interface-8.0.1-cp311-cp311-linux_x86_64.whl", "packagetype": "bdist_wheel", "size": 100, "digests": map[string]any{"sha256": sha256hex(wheel)}},
			{"path": "/f/sdist.tar.gz", "filename": "zope.interface-8.0.1.tar.gz", "packagetype": "sdist", "size": 200, "digests": map[string]any{"sha256": sha256hex(sdist)}},
		})
	defer srv.Close()

	r := &PyPIResolver{client: serverClient(t, srv), base: serverURL()}
	// The component carries the name as METADATA spelled it; the index is asked
	// for the normalized form.
	art, err := r.Fetch(t.Context(), component.Component{Name: "zope.interface", Version: "8.0.1"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !art.Matched {
		t.Error("Matched: got false, want the archive to verify against the hash the index recorded")
	}

	// The sdist's wrapping directory is stripped, so the root-only readers
	// (README hints, declared metadata) find what they expect.
	if got := readFile(t, art.FS, "PKG-INFO"); got != pkgInfo {
		t.Errorf("PKG-INFO: got = %q, want the sdist metadata at the root", got)
	}
	if _, err := fs.Stat(art.FS, "LICENSE"); err != nil {
		t.Errorf("LICENSE at sdist root: got err = %v, want the file to be present", err)
	}
}

// TestPyPIResolverFallsBackToSmallestWheel covers the wheel-only releases, where
// taking the first listed file would mean downloading platform binaries to read
// a license that is identical in every one of them.
func TestPyPIResolverFallsBackToSmallestWheel(t *testing.T) {
	const meta = "Metadata-Version: 2.4\nName: cryptography\nVersion: 43.0.0\nLicense-Expression: Apache-2.0 OR BSD-3-Clause\n\nbody\n"
	small := makeWheel(t, map[string]string{
		"cryptography-43.0.0.dist-info/METADATA":         meta,
		"cryptography-43.0.0.dist-info/licenses/LICENSE": "dual licensed",
	})
	large := makeWheel(t, map[string]string{
		"cryptography-43.0.0.dist-info/METADATA": meta,
		"cryptography/_rust.so":                  "not really a binary",
	})

	srv := pypiIndex(t, "cryptography", "43.0.0",
		map[string][]byte{"/f/small.whl": small, "/f/large.whl": large},
		[]map[string]any{
			{"path": "/f/large.whl", "filename": "cryptography-43.0.0-cp39-manylinux_x86_64.whl", "packagetype": "bdist_wheel", "size": 4_000_000, "digests": map[string]any{"sha256": sha256hex(large)}},
			{"path": "/f/small.whl", "filename": "cryptography-43.0.0-py3-none-any.whl", "packagetype": "bdist_wheel", "size": 40_000, "digests": map[string]any{"sha256": sha256hex(small)}},
		})
	defer srv.Close()

	r := &PyPIResolver{client: serverClient(t, srv), base: serverURL()}
	art, err := r.Fetch(t.Context(), component.Component{Name: "cryptography", Version: "43.0.0"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if art.Digest != sha256hex(small) {
		t.Error("got the platform wheel, want the pure-Python one")
	}
	// A wheel has no wrapping directory, so its dist-info sits at the root.
	if _, err := fs.Stat(art.FS, "cryptography-43.0.0.dist-info/licenses/LICENSE"); err != nil {
		t.Errorf("PEP 639 license file: got err = %v, want the file to be retained", err)
	}
}

func TestPyPIResolverMissingReleaseIsGone(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	r := &PyPIResolver{client: serverClient(t, srv), base: serverURL()}
	_, err := r.Fetch(t.Context(), component.Component{Name: "nope", Version: "1.0"})
	if !errors.Is(err, ErrGone) {
		t.Errorf("got = %v, want ErrGone; a deleted release is unscannable, not retryable", err)
	}
}

// TestPyPIResolverReleaseWithNoFilesIsGone covers a version whose index entry
// survives its files, which retrying can never fix.
func TestPyPIResolverReleaseWithNoFilesIsGone(t *testing.T) {
	srv := pypiIndex(t, "empty", "1.0", nil, nil)
	defer srv.Close()

	r := &PyPIResolver{client: serverClient(t, srv), base: serverURL()}
	_, err := r.Fetch(t.Context(), component.Component{Name: "empty", Version: "1.0"})
	if !errors.Is(err, ErrGone) {
		t.Errorf("got = %v, want ErrGone", err)
	}
}

func TestPyPIResolverRejectsIncompleteCoordinates(t *testing.T) {
	r := NewPyPIResolver(nil)
	if _, err := r.Fetch(t.Context(), component.Component{Name: "requests"}); err == nil {
		t.Error("Fetch: got nil error, want one for a component with no version")
	}
}

func TestPyPIResolverDetectsTamperedArchive(t *testing.T) {
	sdist := makeTarGz(t, "app-1.0", map[string]string{"LICENSE": "MIT"})
	srv := pypiIndex(t, "app", "1.0",
		map[string][]byte{"/f/sdist.tar.gz": sdist},
		[]map[string]any{
			{"path": "/f/sdist.tar.gz", "filename": "app-1.0.tar.gz", "packagetype": "sdist", "size": 10, "digests": map[string]any{"sha256": sha256hex([]byte("something else"))}},
		})
	defer srv.Close()

	r := &PyPIResolver{client: serverClient(t, srv), base: serverURL()}
	art, err := r.Fetch(t.Context(), component.Component{Name: "app", Version: "1.0"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// The content is still returned so it can be judged; what it is not is
	// vouched for.
	if art.Matched {
		t.Error("Matched: got true, want false when the bytes do not match the recorded hash")
	}
}

func TestPyPIResolverIsRegisteredByDefault(t *testing.T) {
	if _, err := DefaultSet(nil).Fetch(t.Context(), component.Component{Ecosystem: "pypi"}); errors.Is(err, ErrUnsupported) {
		t.Error("pypi has no resolver in the default set; enumerated components would all be unscanned")
	}
}
