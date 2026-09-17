/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"chainguard.dev/license/component"
)

// makeZip builds a zip whose members are nested under prefix, mirroring the
// layout the module proxy serves.
func makeZip(t *testing.T, prefix string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(prefix + "/" + name)
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

// makeTarGz builds a gzipped tarball nested under prefix, mirroring a .crate.
func makeTarGz(t *testing.T, prefix string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     prefix + "/" + name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := io.WriteString(tw, content); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func readFile(t *testing.T, fsys fs.FS, name string) string {
	t.Helper()
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		t.Fatalf("reading %s from artifact: %v", name, err)
	}
	return string(data)
}

// TestFetchRefusesUnsafeURLs verifies that every fetch runs the host checks.
// The URLs here resolve publicly, so the only thing that can refuse them is
// the validation, not a resolution failure standing in for it.
func TestFetchRefusesUnsafeURLs(t *testing.T) {
	stubDNS(t, map[string][]string{"proxy.golang.org": {"142.250.187.113"}})

	for _, tt := range []struct{ name, url string }{
		{name: "plain http", url: "http://proxy.golang.org/x/@v/v1.zip"},
		{name: "embedded credentials", url: "https://user:pass@proxy.golang.org/x/@v/v1.zip"},
		{name: "an IP-literal host", url: "https://169.254.169.254/x/@v/v1.zip"},
		{name: "an internal suffix", url: "https://metadata.google.internal/x"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := fetch(t.Context(), nil, tt.url, 0); err == nil {
				t.Error("fetch: got nil error, want the fetch to be refused")
			}
		})
	}
}

// TestFetchStreamsToDiskPastTheMetadataBound pins that an artifact is staged
// rather than buffered: one far larger than the in-memory metadata bound is
// fetched fine, and the staged file is removed when the caller is done. A Go
// module zip is a whole repository at a revision and some are hundreds of
// megabytes, so the artifact bound is loose where the metadata bound is tight.
func TestFetchStreamsToDiskPastTheMetadataBound(t *testing.T) {
	const size = MaxMetadataBytes + (1 << 20)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := bytes.Repeat([]byte("a"), 1<<20)
		for written := 0; written < size; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	art, err := fetch(t.Context(), serverClient(t, srv), serverURL(), 0)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer art.Close()
	if art.Size() < int64(size) {
		t.Errorf("size: got = %d, want at least %d", art.Size(), size)
	}
	if _, err := os.Stat(art.Path()); err != nil {
		t.Errorf("artifact staged on disk: got err = %v, want the file to exist", err)
	}

	// And Close removes it, so a sweep does not fill the disk.
	path := art.Path()
	if err := art.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("staged file after Close: got stat err = %v, want the file to be removed", err)
	}
}

// TestFetchBytesBoundsMetadata keeps the one bound that is still about size:
// metadata is read into memory, so an endless response must be refused.
//
// Both sides of the boundary are pinned. The bound is enforced by reading one
// byte past it, and a document of exactly the permitted size has to survive
// that, so an off-by-one in either direction is a real failure here rather than
// a rounding detail.
func TestFetchBytesBoundsMetadata(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "at the limit", size: MaxMetadataBytes},
		{name: "one byte over", size: MaxMetadataBytes + 1, wantErr: true},
		{name: "streaming without end", size: MaxMetadataBytes + (2 << 20), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				chunk := bytes.Repeat([]byte("a"), 1<<16)
				for written := 0; written < tc.size; {
					n, err := w.Write(chunk[:min(len(chunk), tc.size-written)])
					if err != nil {
						return
					}
					written += n
				}
			}))
			defer srv.Close()

			body, err := fetchBytes(t.Context(), serverClient(t, srv), serverURL())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("fetchBytes: got nil error for %d byte response, want it to be refused", tc.size)
				}
				return
			}
			if err != nil {
				t.Fatalf("fetchBytes: %v", err)
			}
			if len(body) != tc.size {
				t.Errorf("len(body): got = %d, want = %d", len(body), tc.size)
			}
		})
	}
}

func TestSanitizeArchivePath(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{in: "LICENSE", want: "LICENSE"},
		{in: "./LICENSE", want: "LICENSE"},
		{in: "sub/LICENSE", want: "sub/LICENSE"},
		{in: "sub\\LICENSE", want: "sub/LICENSE"},
		{in: "../escape/LICENSE", want: ""},
		{in: "a/../../escape", want: ""},
		{in: "/absolute/LICENSE", want: ""},
	} {
		t.Run(tt.in, func(t *testing.T) {
			if got := sanitizeArchivePath(tt.in); got != tt.want {
				t.Errorf("got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// TestArchiveExpansionRetainsOnlyEvidence pins the retention policy: the files a
// determination is drawn from survive expansion, bulk source does not.
func TestArchiveExpansionRetainsOnlyEvidence(t *testing.T) {
	files := map[string]string{
		"LICENSE":            "MIT License ...",
		"LICENSE-APACHE":     "Apache License Version 2.0 ...",
		"Cargo.toml":         "[package]\nname = \"x\"\nlicense = \"MIT OR Apache-2.0\"\n",
		"README.md":          "Dual-licensed at your option.",
		"src/lib.rs":         "// bulk source",
		"src/generated/a.rs": "// more bulk source",
	}

	for _, tt := range []struct {
		name string
		open func() (fs.FS, error)
	}{
		{name: "zip", open: func() (fs.FS, error) {
			b := makeZip(t, "x@v1.0.0", files)
			return zipFS(bytes.NewReader(b), int64(len(b)), "x@v1.0.0")
		}},
		{name: "targz", open: func() (fs.FS, error) {
			return tarGzFS(bytes.NewReader(makeTarGz(t, "x-1.0.0", files)), "x-1.0.0")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fsys, err := tt.open()
			if err != nil {
				t.Fatalf("expanding: %v", err)
			}
			for _, want := range []string{"LICENSE", "LICENSE-APACHE", "Cargo.toml", "README.md"} {
				if _, err := fs.Stat(fsys, want); err != nil {
					t.Errorf("evidence file %q missing after expansion: %v", want, err)
				}
			}
			for _, unwanted := range []string{"src/lib.rs", "src/generated/a.rs"} {
				if _, err := fs.Stat(fsys, unwanted); err == nil {
					t.Errorf("non-evidence file %q was retained", unwanted)
				}
			}
		})
	}
}

// TestArchiveExpansionSurvivesOversizedSource is the windows-crate shape: bulk
// generated source far past the expansion limit, with the licensing in a few
// small files. Before filtering, this component could not be read at all.
func TestArchiveExpansionSurvivesOversizedSource(t *testing.T) {
	bulk := strings.Repeat("x", MaxExpandedBytes+1)
	data := makeTarGz(t, "windows-0.56.0", map[string]string{
		"LICENSE-MIT":       "MIT License ...",
		"Cargo.toml":        "[package]\nname = \"windows\"\nlicense = \"MIT OR Apache-2.0\"\n",
		"src/generated.rs":  bulk,
		"src/generated2.rs": bulk,
	})

	fsys, err := tarGzFS(bytes.NewReader(data), "windows-0.56.0")
	if err != nil {
		t.Fatalf("expanding oversized crate: %v", err)
	}
	if got := readFile(t, fsys, "LICENSE-MIT"); !strings.Contains(got, "MIT License") {
		t.Errorf("LICENSE-MIT: got = %q", got)
	}
}

// TestArchiveExpansionStopsAtTheByteLimit is the other side of that: filtering
// keeps the bulk out, and what survives filtering is still bounded, so a
// highly compressible archive of license-named members cannot expand without
// end.
func TestArchiveExpansionStopsAtTheByteLimit(t *testing.T) {
	half := strings.Repeat("x", MaxExpandedBytes/2+1)
	files := map[string]string{
		"LICENSE":       half,
		"COPYING":       half,
		"LICENSE-THIRD": half,
	}

	if _, err := tarGzFS(bytes.NewReader(makeTarGz(t, "big-1.0.0", files)), "big-1.0.0"); err == nil {
		t.Error("expanding past the byte limit: got nil error, want the expansion refused")
	}

	b := makeZip(t, "big@v1.0.0", files)
	if _, err := zipFS(bytes.NewReader(b), int64(len(b)), "big@v1.0.0"); err == nil {
		t.Error("expanding a zip past the byte limit: got nil error, want the expansion refused")
	}
}

// TestArchiveExpansionRefusesTraversal covers the attribution guard: nothing
// here is written to disk, but a member resolving outside the archive root
// would place a license file somewhere it is not, and a determination would
// then rest on evidence attributed to the wrong component.
func TestArchiveExpansionRefusesTraversal(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"pkg-1.0/../../LICENSE", "/etc/LICENSE", "pkg-1.0/LICENSE"} {
		const body = "MIT"
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	fsys, err := tarGzFS(bytes.NewReader(buf.Bytes()), "pkg-1.0")
	if err != nil {
		t.Fatalf("expanding: %v", err)
	}
	got, err := fs.Glob(fsys, "**")
	if err != nil {
		t.Fatal(err)
	}
	// Only the member inside the archive root survives, and it keeps its
	// path relative to that root.
	if diff := cmp.Diff([]string{"LICENSE"}, got); diff != "" {
		t.Errorf("expanded members (-want, +got):\n%s", diff)
	}
}

// TestFetchValidatesRedirects covers the hole that validating only the caller's
// URL would leave: a registry response is untrusted input, so a 302 toward
// link-local space is a fetch this package must refuse to make.
func TestFetchValidatesRedirects(t *testing.T) {
	var target string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/artifact" {
			w.Write([]byte("the artifact"))
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
	}))
	defer srv.Close()

	client := serverClient(t, srv)

	for _, tt := range []struct {
		name    string
		target  string
		wantErr bool
	}{
		{
			// A redirect within the validated host is what registries actually
			// do, and has to keep working.
			name:   "a redirect to a public host is followed",
			target: serverURL() + "/artifact",
		},
		{
			name:    "a redirect to a link-local address is refused",
			target:  "https://169.254.169.254/latest/meta-data",
			wantErr: true,
		},
		{
			name:    "a redirect to an internal host is refused",
			target:  "https://metadata.google.internal/computeMetadata/v1/",
			wantErr: true,
		},
		{
			// The scheme is checked on every hop too, so an https artifact URL
			// cannot be downgraded by the response.
			name:    "a redirect to cleartext is refused",
			target:  "http://" + testHost + "/artifact",
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			target = tt.target
			art, err := fetch(t.Context(), client, serverURL()+"/redirect", 0)
			if err == nil {
				defer art.Close()
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("fetch: got err = %v, want an error = %v", err, tt.wantErr)
			}
		})
	}
}

// TestTarDecompressionIsBounded covers the members this package discards: a tar
// is read as a stream, so reaching the next header means decompressing the one
// before it whether or not it is kept.
func TestTarDecompressionIsBounded(t *testing.T) {
	// Highly compressible payload under a name nothing retains, so the
	// expanded-bytes cap never sees it.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	chunk := bytes.Repeat([]byte("a"), 1<<20)
	for written := int64(0); written < MaxDecompressedBytes+(1<<20); written += int64(len(chunk)) {
		if err := tw.WriteHeader(&tar.Header{
			Name:     fmt.Sprintf("payload-%d.bin", written),
			Mode:     0o644,
			Size:     int64(len(chunk)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := tarGzFS(bytes.NewReader(buf.Bytes()), ""); err == nil {
		t.Error("expanding a tar that decompresses past the limit: got nil error, want it refused")
	}
}

// TestArchiveExpansionDropsASecondRoot covers an archive that nests its
// contents under the prefix the caller named and also carries another root
// beside it.
//
// Retaining that root's license file would attribute it to the component this
// archive is for, which is the error sanitizeArchivePath refuses for "..",
// reached without needing a traversal: a sibling directory is not a traversal.
func TestArchiveExpansionDropsASecondRoot(t *testing.T) {
	// Two roots, which makeTarGz's single prefix cannot express.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, m := range []struct{ name, content string }{
		{"serde-1.0.200/LICENSE-MIT", "MIT license text"},
		{"extras/LICENSE", "GPL-3.0 license text"},
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name: m.name, Mode: 0o644, Size: int64(len(m.content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("writing %q: %v", m.name, err)
		}
		if _, err := tw.Write([]byte(m.content)); err != nil {
			t.Fatalf("writing %q: %v", m.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip: %v", err)
	}

	fsys, err := tarGzFS(bytes.NewReader(buf.Bytes()), "serde-1.0.200")
	if err != nil {
		t.Fatalf("tarGzFS: %v", err)
	}
	if got := readFile(t, fsys, "LICENSE-MIT"); got != "MIT license text" {
		t.Errorf("LICENSE-MIT: got = %q, want the component's own license", got)
	}
	if _, err := fs.Stat(fsys, "extras/LICENSE"); err == nil {
		t.Error("extras/LICENSE was retained; a root beside the prefix is not this component's evidence")
	}
}

// TestArchiveExpansionKeepsEverythingWhenThePrefixIsWrong covers a prefix that
// matched no member. A PyPI sdist's prefix comes from the filename the index
// served, and project-name normalization means the directory inside can
// differ, so dropping those members would report a well-licensed package as
// shipping no license.
func TestArchiveExpansionKeepsEverythingWhenThePrefixIsWrong(t *testing.T) {
	// The index served Flask-2.0.1.tar.gz; the directory inside is lowercase.
	fsys, err := tarGzFS(bytes.NewReader(makeTarGz(t, "flask-2.0.1", map[string]string{
		"LICENSE.rst": "BSD-3-Clause license text",
	})), "Flask-2.0.1")
	if err != nil {
		t.Fatalf("tarGzFS: %v", err)
	}
	if got := readFile(t, fsys, "flask-2.0.1/LICENSE.rst"); got != "BSD-3-Clause license text" {
		t.Errorf("got = %q, want the license kept under its unstripped path", got)
	}
}

// TestFetchRefusesARebindingHost covers a host whose DNS answer changes
// between the check and the connection.
//
// ValidateURL resolves the host and asserts its addresses are public.
// Resolving the same name again at dial time would reach an address nothing
// checked, so the dial connects to the address the check resolved.
func TestFetchRefusesARebindingHost(t *testing.T) {
	// The first lookup answers publicly, so ValidateURL passes. Every lookup
	// after it answers with link-local space, which is what a rebinding host
	// does once the check is out of the way.
	var lookups int
	t.Cleanup(setLookupIPAddr(func(_ context.Context, host string) ([]net.IPAddr, error) {
		lookups++
		if lookups == 1 {
			return []net.IPAddr{{IP: net.ParseIP(publicAddr)}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	}))

	_, err := fetchBytes(t.Context(), nil, serverURL())
	if err == nil {
		t.Fatal("fetchBytes: got nil error, want the fetch to be refused")
	}
	if !strings.Contains(err.Error(), "non-public address") {
		t.Errorf("error: got = %v, want it to name the non-public address", err)
	}
	if lookups < 2 {
		t.Errorf("lookups: got = %d, want at least 2; the dial must resolve rather than trust the check", lookups)
	}
}

// TestFetchBoundsTheArtifact covers the caller's own bound on a staged
// artifact.
//
// A staged artifact occupies the caller's temporary directory, which is memory
// on a Cloud Run service with no volume mounted. Exceeding the bound fails the
// fetch and leaves no file behind.
func TestFetchBoundsTheArtifact(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := bytes.Repeat([]byte("a"), 1<<10)
		for range 64 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	before, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("reading temp dir: %v", err)
	}

	// A caller's own bound, well under what the server sends.
	_, err = fetch(t.Context(), serverClient(t, srv), serverURL(), 8<<10)
	if err == nil {
		t.Fatal("fetch: got nil error, want the artifact to be refused for exceeding the bound")
	}
	if !strings.Contains(err.Error(), "byte limit") {
		t.Errorf("error: got = %v, want it to name the limit", err)
	}

	after, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("reading temp dir: %v", err)
	}
	if len(after) > len(before) {
		t.Errorf("temp entries: got = %d, want no more than %d; a refused artifact must not be left staged", len(after), len(before))
	}

	// The same response inside the bound is kept.
	art, err := fetch(t.Context(), serverClient(t, srv), serverURL(), 1<<20)
	if err != nil {
		t.Fatalf("fetch within the bound: %v", err)
	}
	defer art.Close()
	if art.Size() != 64<<10 {
		t.Errorf("size: got = %d, want = %d", art.Size(), 64<<10)
	}
}

// readerFunc adapts a function to io.Reader.
type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(b []byte) (int, error) { return f(b) }

// TestArchiveExpansionDropsASecondRootWhenThePrefixHoldsNoEvidence covers an
// archive whose prefix holds only source files.
//
// The prefix was found, so a second root's license is not this component's
// evidence. Returning nothing is a gap the assessment reports as unknown.
func TestArchiveExpansionDropsASecondRootWhenThePrefixHoldsNoEvidence(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, m := range []struct{ name, content string }{
		{"serde-1.0.200/src/lib.rs", "fn main() {}"}, // inside, but not evidence
		{"extras/LICENSE", "GPL-3.0 license text"},   // evidence, but another root
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name: m.name, Mode: 0o644, Size: int64(len(m.content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("writing %q: %v", m.name, err)
		}
		if _, err := tw.Write([]byte(m.content)); err != nil {
			t.Fatalf("writing %q: %v", m.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip: %v", err)
	}

	fsys, err := tarGzFS(bytes.NewReader(buf.Bytes()), "serde-1.0.200")
	if err != nil {
		t.Fatalf("tarGzFS: %v", err)
	}
	if _, err := fs.Stat(fsys, "extras/LICENSE"); err == nil {
		t.Error("extras/LICENSE was retained; the prefix was found, so another root is not this component's evidence")
	}
}

// TestPinningRefusesAProxy covers the configuration in which address pinning
// cannot work. With a proxy the transport dials the proxy, so the guard checks
// the proxy's address while the proxy resolves the target inside CONNECT.
func TestPinningRefusesAProxy(t *testing.T) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = func(*http.Request) (*url.URL, error) {
		return url.Parse("http://proxy.invalid:3128")
	}

	pinned, ok := pinning(base).(*http.Transport)
	if !ok {
		t.Fatalf("pinning returned %T, want *http.Transport", pinning(base))
	}
	if pinned.Proxy != nil {
		t.Error("the pinned transport kept a proxy; the proxy would resolve the target instead of us")
	}
	// A transport this package cannot clone is left to its owner.
	if got := pinning(http.NewFileTransport(http.Dir("."))); got == nil {
		t.Error("pinning dropped a transport it cannot clone")
	}
}

// TestGuardStallCancelsAStoppedTransfer covers the watchdog from both sides: a
// transfer that stops is cancelled, and a slow one that keeps moving is not.
//
// The watchdog is what lets DefaultTimeout bound a stall rather than the whole
// request, so a registry dripping bytes under MaxMetadataBytes cannot hold a
// connection open.
func TestGuardStallCancelsAStoppedTransfer(t *testing.T) {
	t.Run("a stopped transfer is cancelled", func(t *testing.T) {
		release := make(chan struct{})
		var cancelled atomic.Bool
		stopped := readerFunc(func([]byte) (int, error) {
			// Bounded, so a missing watchdog fails the assertion below rather
			// than hanging until the whole test binary times out.
			select {
			case <-release:
			case <-time.After(2 * time.Second):
			}
			return 0, io.EOF
		})
		r, stop := guardStall(stopped, 20*time.Millisecond, func() {
			cancelled.Store(true)
			close(release)
		})
		defer stop()

		if _, err := io.ReadAll(r); err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if !cancelled.Load() {
			t.Error("a reader that never produced a byte was not cancelled")
		}
	})

	t.Run("a slow transfer that makes progress is not", func(t *testing.T) {
		var cancelled atomic.Bool
		remaining := 5
		// Each read resets the stall timer; no sleep needed to verify the guard
		// does not cancel a reader that keeps making progress.
		slow := readerFunc(func(b []byte) (int, error) {
			if remaining == 0 {
				return 0, io.EOF
			}
			remaining--
			b[0] = 'a'
			return 1, nil
		})
		r, stop := guardStall(slow, 50*time.Millisecond, func() { cancelled.Store(true) })
		defer stop()

		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if len(got) != 5 {
			t.Errorf("read %d bytes, want 5", len(got))
		}
		if cancelled.Load() {
			t.Error("a transfer that kept making progress was cancelled")
		}
	})
}

// TestArchiveExpansionRefusesADuplicateMember covers an archive declaring one
// name twice. Keeping the last drops a license text: a publisher can put the
// restrictive text first and the permissive one after. Identical contents
// under one name are accepted.
func TestArchiveExpansionRefusesADuplicateMember(t *testing.T) {
	build := func(t *testing.T, second string) []byte {
		t.Helper()
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		for _, content := range []string{"GPL-3.0 license text", second} {
			if err := tw.WriteHeader(&tar.Header{
				Name: "pkg-1.0/LICENSE", Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
			}); err != nil {
				t.Fatalf("writing header: %v", err)
			}
			if _, err := tw.Write([]byte(content)); err != nil {
				t.Fatalf("writing member: %v", err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatalf("closing tar: %v", err)
		}
		if err := gz.Close(); err != nil {
			t.Fatalf("closing gzip: %v", err)
		}
		return buf.Bytes()
	}

	if _, err := tarGzFS(bytes.NewReader(build(t, "MIT license text")), "pkg-1.0"); err == nil {
		t.Error("duplicate member with different contents: got nil error, want non-nil")
	}
	if _, err := tarGzFS(bytes.NewReader(build(t, "GPL-3.0 license text")), "pkg-1.0"); err != nil {
		t.Errorf("identical duplicate members are not a clash: %v", err)
	}
}

// TestArchiveExpansionDropsSymlinks covers the member-type guard. A symlink's
// data is its target path, so retaining one named like a license records a
// path where license text is expected.
func TestArchiveExpansionDropsSymlinks(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "pkg-1.0/LICENSE", Typeflag: tar.TypeSymlink, Linkname: "../elsewhere/LICENSE", Mode: 0o777,
	}); err != nil {
		t.Fatalf("writing tar symlink: %v", err)
	}
	tw.Close()
	gz.Close()
	fsys, err := tarGzFS(bytes.NewReader(buf.Bytes()), "pkg-1.0")
	if err != nil {
		t.Fatalf("tarGzFS: %v", err)
	}
	if _, err := fs.Stat(fsys, "LICENSE"); err == nil {
		t.Error("a tar symlink named LICENSE was retained")
	}

	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	hdr := &zip.FileHeader{Name: "pkg-1.0/LICENSE"}
	hdr.SetMode(os.ModeSymlink | 0o777)
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatalf("creating zip symlink: %v", err)
	}
	if _, err := w.Write([]byte("../elsewhere/LICENSE")); err != nil {
		t.Fatalf("writing zip symlink: %v", err)
	}
	zw.Close()
	zfsys, err := zipFS(bytes.NewReader(zbuf.Bytes()), int64(zbuf.Len()), "pkg-1.0")
	if err != nil {
		t.Fatalf("zipFS: %v", err)
	}
	if _, err := fs.Stat(zfsys, "LICENSE"); err == nil {
		t.Error("a zip symlink named LICENSE was retained")
	}
}

// TestExpandRoutesByFilename covers the exported entry point, which is the
// only place format selection by filename suffix lives.
func TestExpandRoutesByFilename(t *testing.T) {
	zipBytes := func() []byte {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		w, err := zw.Create("pkg-1.0/LICENSE")
		if err != nil {
			t.Fatalf("creating zip member: %v", err)
		}
		if _, err := w.Write([]byte("MIT license text")); err != nil {
			t.Fatalf("writing zip member: %v", err)
		}
		zw.Close()
		return b.Bytes()
	}()
	tarBytes := makeTarGz(t, "pkg-1.0", map[string]string{"LICENSE": "MIT license text"})

	for _, tt := range []struct {
		name string
		data []byte
	}{
		{"pkg-1.0.zip", zipBytes}, {"pkg.jar", zipBytes}, {"pkg.whl", zipBytes},
		{"pkg-1.0.tar.gz", tarBytes}, {"pkg-1.0.tgz", tarBytes}, {"pkg-1.0.crate", tarBytes},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fsys, err := Expand(tt.name, bytes.NewReader(tt.data), int64(len(tt.data)), "pkg-1.0")
			if err != nil {
				t.Fatalf("Expand: %v", err)
			}
			if got := readFile(t, fsys, "LICENSE"); got != "MIT license text" {
				t.Errorf("LICENSE: got = %q, want the license text", got)
			}
		})
	}
	if _, err := Expand("pkg-1.0.rar", bytes.NewReader(tarBytes), int64(len(tarBytes)), ""); err == nil {
		t.Error("Expand: got nil error for unsupported suffix, want it to be refused")
	}
}

// TestHTTPClientIsMemoizedSoConnectionsPool covers connection reuse across
// fetches. validating clones the transport, and a new transport has an empty
// connection pool, so wrapping per request adds a handshake to every artifact.
func TestHTTPClientIsMemoizedSoConnectionsPool(t *testing.T) {
	if a, b := httpClient(nil), httpClient(nil); a != b || a.Transport != b.Transport {
		t.Error("the default client was wrapped twice; its connection pool cannot be reused")
	}
	own := &http.Client{}
	if a, b := httpClient(own), httpClient(own); a != b || a.Transport != b.Transport {
		t.Error("a caller's client was wrapped twice")
	}
	if httpClient(own) == httpClient(nil) {
		t.Error("a caller's client must not be served the default's wrapper")
	}
}

// Moved out of upstream/fetch_test.go (lines 89-223) when shard 9 landed the
// upstream core without its resolvers. Belongs in shard 10.
func TestGoResolverFetchVerifiesDigest(t *testing.T) {
	const license = "Apache License Version 2.0"
	body := makeZip(t, "github.com/example/mod@v1.2.3", map[string]string{
		"LICENSE": license,
		"go.mod":  "module github.com/example/mod\n",
	})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/@v/v1.2.3.zip") {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	r := &GoResolver{client: serverClient(t, srv), proxy: serverURL()}

	// The expected digest is unknown to the test, so fetch once to learn it and
	// confirm the canonical flag only trips on a real match.
	art, err := r.Fetch(t.Context(), component.Component{Name: "github.com/example/mod", Version: "v1.2.3"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if art.Digest == "" || !strings.HasPrefix(art.Digest, "h1:") {
		t.Errorf("digest: got = %q, want an h1 dirhash", art.Digest)
	}
	if art.Matched {
		t.Error("canonical must be false when the component carried no expected digest")
	}
	// The proxy's "<module>@<version>/" wrapper is stripped.
	if got := readFile(t, art.FS, "LICENSE"); got != license {
		t.Errorf("LICENSE: got = %q, want = %q", got, license)
	}

	matching, err := r.Fetch(t.Context(), component.Component{
		Name: "github.com/example/mod", Version: "v1.2.3", Digest: art.Digest,
	})
	if err != nil {
		t.Fatalf("Fetch with digest: %v", err)
	}
	if !matching.Matched {
		t.Error("canonical must be true when the digest matches what the build recorded")
	}

	mismatched, err := r.Fetch(t.Context(), component.Component{
		Name: "github.com/example/mod", Version: "v1.2.3", Digest: "h1:something-else",
	})
	if err != nil {
		t.Fatalf("Fetch with wrong digest: %v", err)
	}
	if mismatched.Matched {
		t.Error("a digest mismatch must not be marked canonical: it is a diverged variant")
	}
}

func TestGoResolverEscapesUppercaseModulePaths(t *testing.T) {
	var gotPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write(makeZip(t, "x@v1.0.0", map[string]string{"LICENSE": "MIT"}))
	}))
	defer srv.Close()

	r := &GoResolver{client: serverClient(t, srv), proxy: serverURL()}
	if _, err := r.Fetch(t.Context(), component.Component{Name: "github.com/Azure/azure-sdk", Version: "v1.0.0"}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !strings.Contains(gotPath, "!azure") {
		t.Errorf("path: got = %q, want the uppercase letters bang-escaped", gotPath)
	}
}

func TestGoResolverMissingVersionIsGone(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	r := &GoResolver{client: serverClient(t, srv), proxy: serverURL()}
	_, err := r.Fetch(t.Context(), component.Component{Name: "github.com/example/gone", Version: "v9.9.9"})
	if !errors.Is(err, ErrGone) {
		t.Errorf("error: got = %v, want it to wrap ErrGone so the caller stops retrying", err)
	}
}

func TestCargoResolverFetchVerifiesChecksum(t *testing.T) {
	const manifest = "[package]\nname = \"serde\"\nlicense = \"MIT OR Apache-2.0\"\n"
	body := makeTarGz(t, "serde-1.0.219", map[string]string{
		"Cargo.toml":     manifest,
		"LICENSE-MIT":    "MIT License",
		"LICENSE-APACHE": "Apache License",
	})
	sum := sha256.Sum256(body)
	expected := hex.EncodeToString(sum[:])

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/crates/serde/serde-1.0.219.crate" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	r := &CargoResolver{client: serverClient(t, srv), base: serverURL()}
	art, err := r.Fetch(t.Context(), component.Component{Name: "serde", Version: "1.0.219", Digest: expected})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !art.Matched {
		t.Error("Matched: got false, want the crate to verify against the lockfile checksum")
	}
	if got := readFile(t, art.FS, "Cargo.toml"); got != manifest {
		t.Errorf("Cargo.toml: got = %q, want the crate manifest", got)
	}
	if _, err := fs.Stat(art.FS, "LICENSE-MIT"); err != nil {
		t.Errorf("LICENSE-MIT in crate: got err = %v, want the file to be present", err)
	}
}

func TestSetDispatchAndUnsupported(t *testing.T) {
	s := DefaultSet(nil)
	if _, err := s.Fetch(t.Context(), component.Component{Ecosystem: "nuget", Name: "x", Version: "1"}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("error: got = %v, want ErrUnsupported for an ecosystem without a resolver", err)
	}
	// Membership rather than a count, so adding a resolver does not break an
	// assertion that is not about how many there are.
	got := s.Ecosystems()
	for _, want := range []string{"golang", "cargo", "pypi", "maven"} {
		if !slices.Contains(got, want) {
			t.Errorf("ecosystems: got = %v, want it to include %q", got, want)
		}
	}
}
