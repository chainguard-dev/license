/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	// MaxExpandedBytes bounds how much an archive may expand to once its
	// members have been filtered down to the ones bearing on licensing.
	//
	// This is a decompression guard, not a size preference. Anyone can publish
	// to the registries fetched here, and a small archive that expands to
	// gigabytes is a known attack rather than a hypothetical one. It is
	// deliberately tight: after filtering, a real component's licensing
	// evidence is kilobytes.
	//
	MaxExpandedBytes = 64 << 20

	// MaxArtifactBytes is the default bound on one staged artifact, before
	// expansion.
	//
	// The bound is loose because a Go module zip is a whole repository at a
	// revision: RoaringBitmap/roaring reaches 135 MB, azure-sdk-for-go 66 MB.
	// The value matches MaxDecompressedBytes, past which a tarball cannot be
	// expanded at all.
	//
	// A staged artifact occupies the caller's temporary directory, which is
	// memory on a Cloud Run service with no volume mounted. Exceeding the
	// bound fails the fetch and the component is reported as unknown. A caller
	// passes a smaller bound when its temporary directory is smaller, or when
	// enough fetches run at once for their sum to exceed it.
	MaxArtifactBytes = 1 << 30

	// MaxMetadataBytes bounds a metadata response read into memory: a pom, a
	// checksum file, an index's JSON. These have a known modest shape, unlike
	// the artifacts they describe, so buffering them is reasonable and the
	// bound is about a hostile or broken registry rather than about size.
	MaxMetadataBytes = 16 << 20

	// DefaultTimeout bounds how long a fetch waits without progress: for the
	// response headers, and thereafter between reads of the body.
	//
	// The bound is not on the whole request. http.Client.Timeout covers the
	// body read, which makes a time limit into a bandwidth requirement: 135 MB
	// in 60 seconds needs 2.25 MB/s sustained. MaxArtifactBytes bounds size.
	DefaultTimeout = 60 * time.Second
)

// ErrUnsupported means no resolver handles a component's ecosystem, which is a
// coverage gap to report rather than a failure to retry.
var ErrUnsupported = errors.New("no resolver for ecosystem")

// ErrGone means the registry does not and will not have this version, so
// retrying is pointless: the content is permanently unavailable rather than
// merely unread.
var ErrGone = errors.New("artifact permanently unavailable")

// Artifact is the fetched content of one component version.
type Artifact struct {
	// FS is a read-only filesystem over the archive's contents, rooted at the
	// component itself.
	FS fs.FS
	// Digest is what the retrieved bytes actually hash to, in the ecosystem's
	// own scheme.
	Digest string
	// DigestAlgo names that scheme.
	DigestAlgo string
	// Matched reports that Digest is the digest the caller said to expect,
	// which for most ecosystems is what a lockfile recorded. False either
	// because they differed or because there was no expected digest to compare
	// against, so a caller that needs to tell those apart checks whether it
	// supplied one.
	Matched bool
	// Source is the URL the content came from.
	Source string
	// Notes record anything about the fetch a reader should know: a jar that
	// was not published, a parent POM that could not be fetched.
	Notes []string
}

// defaultClient is the client used when a caller supplies none. It is built
// once rather than per fetch, so that a sweep reuses connections instead of
// opening one per artifact.
//
// The timeout is on the transport rather than on the client, so it bounds how
// long the registry may take to answer without also bounding how long the
// answer may take to arrive.
var defaultClient = &http.Client{Transport: headerTimeout(http.DefaultTransport, DefaultTimeout)}

// headerTimeout returns a transport that gives up if the response headers do
// not arrive in time. A transport it cannot clone is returned unchanged, for
// the reason pinning gives.
func headerTimeout(rt http.RoundTripper, d time.Duration) http.RoundTripper {
	base, ok := rt.(*http.Transport)
	if !ok {
		return rt
	}
	cloned := base.Clone()
	cloned.ResponseHeaderTimeout = d
	return cloned
}

// maxRedirects bounds how many hops a fetch follows, matching net/http's own
// default. Registries do redirect - an index points at a CDN - so refusing
// redirects outright would refuse real artifacts.
const maxRedirects = 10

// validating returns a client that checks every redirect hop with ValidateURL
// and every address it connects to with isPublicIP.
//
// Validating only the URL the caller passed would leave the check trivially
// bypassable: a registry response is untrusted input, and a 302 toward
// link-local space is a fetch this package must not make. So every hop is
// checked, not just the first.
//
// Checking URLs alone is not enough either. ValidateURL resolves the host and
// asserts the addresses are public, and then the transport resolves that host
// again when it dials, so the address checked is not the address connected to.
// A name whose DNS answers differently between the two reaches an internal
// target the check believes it refused. The dial guard closes that by asking
// the same question of the address actually being connected to, which is the
// only one that can be answered without a race.
//
// The client is copied rather than modified so a caller's own client keeps its
// policy.
func validating(c *http.Client) *http.Client {
	copied := *c
	copied.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("refusing to follow more than %d redirects", maxRedirects)
		}
		return ValidateURL(req.Context(), req.URL.String())
	}
	copied.Transport = pinning(copied.Transport)
	return &copied
}

// pinning returns a transport that resolves a host once, refuses the request
// if any address it resolves to is non-public, and then connects to the
// address it checked rather than to the name.
//
// Connecting to the name resolves it a second time, and the second answer is
// not the one that was checked. TLS is unaffected: the transport takes the
// server name for SNI and verification from the request URL.
//
// An *http.Transport is cloned, so the caller's settings survive and the guard
// applies. Any other RoundTripper is returned unchanged, and its owner keeps
// responsibility for the dialer; ValidateURL still runs. A caller whose own
// DialContext ignores the address it is given also chooses where its
// connections go.
func pinning(rt http.RoundTripper) http.RoundTripper {
	base, ok := rt.(*http.Transport)
	if rt == nil {
		base, ok = http.DefaultTransport.(*http.Transport), true
	}
	if !ok {
		return rt
	}
	cloned := base.Clone()
	// With a proxy the transport dials the proxy, so the guard below would
	// check the proxy's address, and the proxy resolves the target inside
	// CONNECT where this package cannot see it. http.DefaultTransport takes a
	// proxy from the environment, so it is cleared here. A caller needing one
	// supplies a RoundTripper this package does not clone, and owns the
	// check.
	cloned.Proxy = nil
	inner := cloned.DialContext
	if inner == nil {
		inner = (&net.Dialer{}).DialContext
	}
	cloned.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("refusing to dial %q: %w", addr, err)
		}
		// An address literal has nothing to resolve; ValidateURL already
		// refuses IP-literal hosts, so this is a caller's own dialer at work.
		if ip := net.ParseIP(host); ip != nil {
			if !isPublicIP(ip) {
				return nil, fmt.Errorf("refusing to connect to non-public address %s", ip)
			}
			return inner(ctx, network, addr)
		}
		addrs, err := getLookupIPAddr()(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolving host %q: %w", host, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("host %q resolved to no addresses", host)
		}
		// Every address is checked, matching ValidateURL: a name that answers
		// with one public and one internal address is refused rather than
		// raced. Only the first is dialed, so a multi-homed host loses
		// failover, which is a fair price for connecting to a checked address.
		for _, a := range addrs {
			if !isPublicIP(a.IP) {
				return nil, fmt.Errorf("refusing to connect to %q: resolves to non-public address %s", host, a.IP)
			}
		}
		return inner(ctx, network, net.JoinHostPort(addrs[0].IP.String(), port))
	}
	return cloned
}

// wrappedClients memoizes the validating wrapper for each client handed in.
//
// validating clones the transport, and a new transport has an empty connection
// pool, so wrapping per request adds a TCP and TLS handshake to every artifact
// and leaves the previous pool open.
var wrappedClients sync.Map // *http.Client -> *http.Client

// httpClient returns the client to use, defaulting to one that bounds how long
// a registry may take to answer.
func httpClient(c *http.Client) *http.Client {
	base := cmp.Or(c, defaultClient)
	if v, ok := wrappedClients.Load(base); ok {
		return v.(*http.Client)
	}
	v, _ := wrappedClients.LoadOrStore(base, validating(base))
	return v.(*http.Client)
}

// get performs a validated GET and hands back the response for reading.
//
// It exists so that the two ways of consuming a response - staged to disk and
// read into memory - share one URL check, one client policy and one reading of
// the status code, rather than each carrying its own copy. The caller closes
// the body.
func get(ctx context.Context, client *http.Client, rawURL string) (*http.Response, error) {
	if err := ValidateURL(ctx, rawURL); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %q: %w", rawURL, err)
	}

	resp, err := httpClient(client).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %q: %w", rawURL, err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusNotFound, http.StatusGone:
		resp.Body.Close()
		return nil, fmt.Errorf("%w: %s returned %d", ErrGone, rawURL, resp.StatusCode)
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("fetching %q: unexpected status %d", rawURL, resp.StatusCode)
	}
}

// fetch downloads a URL to a temporary file and returns it.
//
// Streamed rather than buffered so that memory does not scale with artifact
// size: a sweep resolves several components at once, and holding each artifact
// whole meant the resident set grew with both the concurrency and the largest
// dependency in the tree. A file also gives archive/zip the random access it
// needs, which a stream alone cannot.
//
// The caller owns the result and must Close it, which removes the file.
// maxBytes of zero applies MaxArtifactBytes. A caller passes its own bound
// when its temporary directory is tighter than the default assumes, or when it
// runs enough fetches at once that the product of the two is what matters.
func fetch(ctx context.Context, client *http.Client, rawURL string, maxBytes int64) (*fetched, error) {
	limit := cmp.Or(maxBytes, int64(MaxArtifactBytes))

	// A stall is cancelled through the request context, since there is no way
	// to put a deadline on a body read from out here. The watchdog is reset by
	// every read that makes progress, so it only fires on a transfer that has
	// genuinely stopped.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resp, err := get(ctx, client, rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	f, err := os.CreateTemp("", "license-artifact-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp file for %q: %w", rawURL, err)
	}
	fail := func(err error) (*fetched, error) {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}

	// One byte past the limit, so a response at the limit succeeds and one over
	// it is distinguishable from one that ended there.
	body, stop := guardStall(io.LimitReader(resp.Body, limit+1), DefaultTimeout, cancel)
	defer stop()
	n, err := io.Copy(f, body)
	if err != nil {
		return fail(fmt.Errorf("reading %q: %w", rawURL, err))
	}
	if n > limit {
		return fail(fmt.Errorf("artifact %q exceeds the %d byte limit", rawURL, limit))
	}
	return &fetched{f: f, size: n}, nil
}

// progressReader reports every read that moved bytes, so a stall watchdog can
// tell a slow transfer from a stopped one.
type progressReader struct {
	r      io.Reader
	onRead func()
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.onRead()
	}
	return n, err
}

// guardStall wraps a body so a transfer that stops making progress is
// cancelled, and returns a stop for the caller to defer.
//
// ResponseHeaderTimeout bounds only the headers. A registry that answers a pom
// by dripping bytes stays under MaxMetadataBytes and holds a connection and a
// goroutine open.
func guardStall(r io.Reader, d time.Duration, cancel context.CancelFunc) (io.Reader, func()) {
	stall := time.AfterFunc(d, cancel)
	return &progressReader{r: r, onRead: func() { stall.Reset(d) }}, func() { stall.Stop() }
}

// fetched is a downloaded artifact held on disk.
type fetched struct {
	f    *os.File
	size int64
}

// Size is how many bytes were downloaded.
func (a *fetched) Size() int64 { return a.size }

// ReaderAt exposes the artifact for random access, which zip requires.
func (a *fetched) ReaderAt() io.ReaderAt { return a.f }

// Reader rewinds and exposes the artifact as a stream, which tar requires.
func (a *fetched) Reader() (io.Reader, error) {
	if _, err := a.f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewinding artifact: %w", err)
	}
	return a.f, nil
}

// Digest streams the artifact through h and returns the hex digest, so hashing
// does not require holding the bytes.
func (a *fetched) Digest(h hash.Hash) (string, error) {
	r, err := a.Reader()
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hashing artifact: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Path is where the artifact is staged, for a caller that needs a filename.
func (a *fetched) Path() string { return a.f.Name() }

// Close releases the artifact and removes it from disk.
func (a *fetched) Close() error {
	name := a.f.Name()
	err := a.f.Close()
	if rmErr := os.Remove(name); err == nil {
		err = rmErr
	}
	return err
}

// fetchBytes downloads a small metadata document into memory.
//
// Distinct from fetch, which streams to disk: a pom or a checksum file is read,
// parsed and discarded, and staging it on disk would cost more than it saves.
//
// MaxMetadataBytes is enforced while the body is read rather than measured once
// it has arrived, so a registry answering a pom with an endless stream is cut
// off at the bound. Measuring afterwards would have already spent the memory
// the bound exists to protect: this runs on Cloud Run, where the temporary
// directory a staged copy would land in is itself memory.
func fetchBytes(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resp, err := get(ctx, client, rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Reading one byte past the bound is what tells a document at the limit
	// apart from one over it; a read of exactly the limit cannot.
	guarded, stop := guardStall(io.LimitReader(resp.Body, MaxMetadataBytes+1), DefaultTimeout, cancel)
	defer stop()
	body, err := io.ReadAll(guarded)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", rawURL, err)
	}
	if int64(len(body)) > MaxMetadataBytes {
		return nil, fmt.Errorf("metadata %q exceeds the %d byte limit", rawURL, MaxMetadataBytes)
	}
	return body, nil
}
