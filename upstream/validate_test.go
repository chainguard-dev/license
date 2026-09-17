/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"chainguard.dev/license/component"
)

// TestValidateURL covers the cases the check exists to refuse. Upstreams are
// open-world, so what is enforced is not an allowlist of hosts but the absence
// of the internal targets a URL chosen by something untrusted could aim at.
func TestValidateURL(t *testing.T) {
	// Known public hosts resolve publicly; rebinding-style names and the
	// non-standard IP spellings a permissive resolver accepts resolve to
	// internal addresses, the way the real resolver would answer them.
	stubDNS(t, map[string][]string{
		"github.com":             {"140.82.112.3"},
		"gitlab.freedesktop.org": {"131.252.210.161"},
		"git.kernel.org":         {"139.178.84.217"},
		"proxy.golang.org":       {"142.250.187.113"},
		"127.0.0.1.nip.io":       {"127.0.0.1"},
		"127.1":                  {"127.0.0.1"},
		"0x7f000001":             {"127.0.0.1"},
		"2130706433":             {"127.0.0.1"},
		"169.254.1":              {"169.254.0.1"},
		"internal.corp.example":  {"10.1.2.3"},
		"split.example":          {"93.184.216.34", "10.0.0.1"},
	})

	for _, tt := range []struct {
		url     string
		wantErr bool
	}{
		{url: "https://github.com/istio/istio", wantErr: false},
		{url: "https://gitlab.freedesktop.org/xorg/lib/libx11", wantErr: false},
		{url: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git", wantErr: false},
		{url: "https://proxy.golang.org/example.com/mod/@v/v1.0.0.zip", wantErr: false},

		{url: "http://github.com/istio/istio", wantErr: true},            // cleartext
		{url: "git://github.com/istio/istio", wantErr: true},             // non-https scheme
		{url: "https://169.254.169.254/latest/meta-data", wantErr: true}, // IP literal
		{url: "https://[fd00::1]/repo", wantErr: true},                   // IPv6 literal
		{url: "https://metadata.google.internal/computeMetadata/v1/", wantErr: true},
		{url: "https://localhost/repo", wantErr: true},
		{url: "https://foo.localhost/repo", wantErr: true},
		{url: "https://printer.local/repo", wantErr: true},

		// String checks alone miss these, which is why the host is resolved.
		{url: "https://127.0.0.1.nip.io/repo", wantErr: true},
		{url: "https://127.1/repo", wantErr: true},
		{url: "https://0x7f000001/repo", wantErr: true},
		{url: "https://2130706433/repo", wantErr: true},
		{url: "https://169.254.1/repo", wantErr: true},
		{url: "https://internal.corp.example/x", wantErr: true},

		// Every address has to be public, not just the first: a host answering
		// with one of each is the whole point of checking them all.
		{url: "https://split.example/x", wantErr: true},

		// Resolution failure rejects, so the check fails closed.
		{url: "https://unresolvable.example/x", wantErr: true},

		{url: "https://user:secret@github.com/istio/istio", wantErr: true},
		{url: "https://", wantErr: true},
		{url: "not a url", wantErr: true},
	} {
		t.Run(tt.url, func(t *testing.T) {
			if err := ValidateURL(t.Context(), tt.url); (err != nil) != tt.wantErr {
				t.Errorf("ValidateURL(%q): got err = %v, want an error = %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

// TestValidateURLDoesNotLeakCredentials verifies that rejecting a credentialed
// URL never echoes the credential. The error flows into logs, traces and tool
// results, so a credential in it is a credential published.
func TestValidateURLDoesNotLeakCredentials(t *testing.T) {
	err := ValidateURL(t.Context(), "https://user:hunter2@github.com/istio/istio")
	if err == nil {
		t.Fatal("ValidateURL: want an error for a credentialed URL, got nil")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("the error leaks the credential: %v", err)
	}
}

func TestRedactURL(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{in: "https://user:hunter2@github.com/x/y", want: "https://github.com/x/y"},
		{in: "https://github.com/x/y", want: "https://github.com/x/y"},
		{in: "not a url", want: "not a url"},
	} {
		t.Run(tt.in, func(t *testing.T) {
			if got := RedactURL(tt.in); got != tt.want {
				t.Errorf("RedactURL: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// TestValidateURLRefusesReservedRanges covers the addresses that look routable
// but are not public. The carrier-grade NAT range is the one that matters: one
// cloud serves instance metadata from inside it, and net.IP reports it as
// public.
func TestValidateURLRefusesReservedRanges(t *testing.T) {
	stubDNS(t, map[string][]string{
		"cgnat.example":     {"100.100.100.200"},
		"protocol.example":  {"192.0.0.8"},
		"benchmark.example": {"198.18.0.1"},
		"nat64.example":     {"64:ff9b::a00:1"},
		"public.example":    {"93.184.216.34"},
	})

	for _, tt := range []struct {
		host    string
		wantErr bool
	}{
		{host: "cgnat.example", wantErr: true},
		{host: "protocol.example", wantErr: true},
		{host: "benchmark.example", wantErr: true},
		{host: "nat64.example", wantErr: true},
		{host: "public.example"},
	} {
		t.Run(tt.host, func(t *testing.T) {
			err := ValidateURL(t.Context(), "https://"+tt.host+"/repo")
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateURL: got err = %v, want an error = %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateURLRefusesAHostWithNoAddresses covers a resolver answering with
// an empty list. git and the transport resolve the name themselves, so an
// empty loop here would let them reach an address nothing checked.
func TestValidateURLRefusesAHostWithNoAddresses(t *testing.T) {
	t.Cleanup(setLookupIPAddr(func(context.Context, string) ([]net.IPAddr, error) { return nil, nil }))

	if err := ValidateURL(t.Context(), "https://example.com/x"); err == nil {
		t.Error("ValidateURL: got nil error, want a host resolving to no addresses to be refused")
	}
}

// TestValidateURLDoesNotLeakACredentialOnAParseFailure covers a URL whose
// userinfo makes url.Parse fail, which happens on a bad percent escape in the
// password. url.Parse's own error embeds the URL, so neither it nor the raw
// URL can appear in what is returned.
func TestValidateURLDoesNotLeakACredentialOnAParseFailure(t *testing.T) {
	err := ValidateURL(t.Context(), "https://user:p%zzword@example.com/x")
	if err == nil {
		t.Fatal("ValidateURL: got nil error, want a malformed URL to be refused")
	}
	if strings.Contains(err.Error(), "zzword") || strings.Contains(err.Error(), "example.com") {
		t.Errorf("error carries the URL: %v", err)
	}
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestResolversRefuseTraversalCoordinates pins that a coordinate which would
// change the shape of a URL rather than name something in it is refused before
// any request is made.
//
// Coordinates are read out of a lockfile or manifest inside a fetched archive,
// and for Maven out of a parent POM the registry served, so a resolver builds
// its URLs from strings an upstream controls. Escaping them is not enough on
// its own: a dot is unreserved, so ".." passes through url.PathEscape unchanged
// and still walks the path out of the prefix the resolver meant to stay under.
func TestResolversRefuseTraversalCoordinates(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Errorf("resolver requested %s; the coordinate should have been refused first", req.URL)
		return nil, errors.New("no request expected")
	})}
	const base = "https://example.com"

	for _, tc := range []struct {
		name      string
		resolver  Resolver
		component component.Component
	}{{
		name:      "cargo version escapes the crates prefix",
		resolver:  &CargoResolver{client: client, base: base},
		component: component.Component{Name: "serde", Version: ".."},
	}, {
		name:      "cargo name escapes the crates prefix",
		resolver:  &CargoResolver{client: client, base: base},
		component: component.Component{Name: "..", Version: "1.0.0"},
	}, {
		name:      "npm version escapes the registry prefix",
		resolver:  &NpmResolver{client: client, base: base},
		component: component.Component{Name: "left-pad", Version: ".."},
	}, {
		name:      "npm scope escapes the registry prefix",
		resolver:  &NpmResolver{client: client, base: base},
		component: component.Component{Name: "../evil", Version: "1.0.0"},
	}, {
		name:      "pypi version escapes the index prefix",
		resolver:  &PyPIResolver{client: client, base: base},
		component: component.Component{Name: "requests", Version: ".."},
	}, {
		name:      "maven version escapes the repository prefix",
		resolver:  &MavenResolver{client: client, base: base},
		component: component.Component{Name: "org.example:artifact", Version: ".."},
	}, {
		name:      "maven group renders an empty segment",
		resolver:  &MavenResolver{client: client, base: base},
		component: component.Component{Name: "org..example:artifact", Version: "1.0.0"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.resolver.Fetch(t.Context(), tc.component); err == nil {
				t.Fatal("Fetch: got nil error, want the coordinate to be refused")
			}
		})
	}
}
