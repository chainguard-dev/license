/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// testHost is the name every test server is addressed by. It matches the
// certificate httptest issues, so TLS verification stays on.
const testHost = "example.com"

// publicAddr is what testHost resolves to in tests. It has to be a public
// address, because a fetch validates the addresses its host resolves to and
// refuses a private or loopback one.
const publicAddr = "93.184.216.34"

// serverURL is the URL a test server is addressed by.
//
// Deliberately not the listener's own https://127.0.0.1:port. Every fetch runs
// ValidateURL first, and that refuses an IP-literal host and a host resolving
// to loopback - the whole point of routing fetches through it is that nothing
// gets to skip it, tests included. So a test addresses a hostname, the stubbed
// resolver says it is public, and serverClient sends the connection to the real
// listener.
func serverURL() string { return "https://" + testHost }

// serverClient returns a client that reaches srv whatever host it is asked
// for, and stubs resolution so testHost looks public.
func serverClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	stubDNS(t, map[string][]string{testHost: {publicAddr}})

	client := srv.Client()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("test server client transport is %T, want *http.Transport", client.Transport)
	}
	transport = transport.Clone()
	addr := srv.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	client.Transport = transport
	return client
}

// stubDNS replaces resolution for the duration of a test, so that the host
// checks run against known answers and no test reaches a real resolver.
func stubDNS(t *testing.T, hosts map[string][]string) {
	t.Helper()
	restore := setLookupIPAddr(func(_ context.Context, host string) ([]net.IPAddr, error) {
		ips, ok := hosts[host]
		if !ok {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		addrs := make([]net.IPAddr, 0, len(ips))
		for _, ip := range ips {
			addrs = append(addrs, net.IPAddr{IP: net.ParseIP(ip)})
		}
		return addrs, nil
	})
	t.Cleanup(restore)
}
