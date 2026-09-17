/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
)

// pathSegments escapes coordinate values for use as URL path segments,
// refusing any value that would change the shape of the path rather than name
// something in it.
//
// Coordinates are not ours. They are read out of a lockfile inside a fetched
// archive, and for Maven out of a parent POM the registry served, so a resolver
// builds its URLs from attacker-influenceable strings. Escaping alone does not
// make that safe: a dot is unreserved, so ".." survives url.PathEscape intact
// and still walks the path up out of the repository prefix it was supposed to
// stay under. The traversal forms are therefore rejected rather than encoded,
// and a separator is rejected too - no real coordinate carries one, and
// servers disagree about what an encoded one means.
func pathSegments(values ...string) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, v := range values {
		switch v {
		case "", ".", "..":
			return nil, fmt.Errorf("refusing %q as a URL path segment", v)
		}
		if strings.ContainsAny(v, `/\`) {
			return nil, fmt.Errorf("refusing %q as a URL path segment: contains a separator", v)
		}
		out = append(out, url.PathEscape(v))
	}
	return out, nil
}

// lookupIPAddrMu guards lookupIPAddr against concurrent reads and writes.
// Tests stub the variable, and the HTTP transport dials concurrently, so
// unguarded access is a data race.
var lookupIPAddrMu sync.RWMutex

// lookupIPAddr resolves a hostname. It is a variable so that tests can stub
// resolution and stay hermetic. All reads and writes must hold lookupIPAddrMu.
var lookupIPAddr = net.DefaultResolver.LookupIPAddr

// getLookupIPAddr returns the current resolver under the read lock.
func getLookupIPAddr() func(context.Context, string) ([]net.IPAddr, error) {
	lookupIPAddrMu.RLock()
	defer lookupIPAddrMu.RUnlock()
	return lookupIPAddr
}

// setLookupIPAddr replaces the resolver under the write lock and returns a
// function that restores the previous value.
func setLookupIPAddr(fn func(context.Context, string) ([]net.IPAddr, error)) func() {
	lookupIPAddrMu.Lock()
	defer lookupIPAddrMu.Unlock()
	prev := lookupIPAddr
	lookupIPAddr = fn
	return func() {
		lookupIPAddrMu.Lock()
		defer lookupIPAddrMu.Unlock()
		lookupIPAddr = prev
	}
}

// ValidateURL rejects URLs this package must not fetch.
//
// Upstreams are open-world - any public code host, any public registry - so
// rather than an allowlist this blocks the internal targets a URL chosen by
// something untrusted could aim at: non-https schemes, embedded userinfo
// credentials, IP-literal hosts such as link-local metadata services,
// localhost, and internal-only DNS suffixes.
//
// String checks alone are not enough, because they miss the non-standard IP
// spellings an OS resolver accepts (127.1, 0x7f000001) and DNS-rebinding
// hostnames (127.0.0.1.nip.io). So the host is resolved and every address it
// resolves to has to be public. Resolution failure rejects, which is to say the
// check fails closed.
//
// It is called immediately before each request rather than once when a URL is
// accepted, because a name that resolved publicly a minute ago can resolve
// somewhere else now. There is deliberately no way to fetch through this
// package without it.
func ValidateURL(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Neither the URL nor url.Parse's error, which embeds it: a parse
		// failure on a percent escape inside a password would carry the
		// credential into a log.
		return errors.New("invalid URL")
	}
	// Rejected first, and without echoing the URL: userinfo may carry a
	// credential, which must reach neither the request nor any log or error.
	if u.User != nil {
		return errors.New("URL must not contain userinfo credentials")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme: only https is allowed, got %q", rawURL)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("URL %q has no host", rawURL)
	}
	if net.ParseIP(host) != nil {
		return fmt.Errorf("URL %q: IP-literal hosts are not allowed", rawURL)
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return fmt.Errorf("URL %q: internal hosts are not allowed", rawURL)
	}
	addrs, err := getLookupIPAddr()(ctx, host)
	if err != nil {
		return fmt.Errorf("resolving host %q: %w", host, err)
	}
	// A host answering with no addresses at all is refused rather than
	// accepted by an empty loop: git and the transport resolve the name
	// themselves, and whatever they get would be an address nothing checked.
	if len(addrs) == 0 {
		return fmt.Errorf("host %q resolved to no addresses", host)
	}
	for _, addr := range addrs {
		if !isPublicIP(addr.IP) {
			return fmt.Errorf("URL %q: host resolves to non-public address %s", rawURL, addr.IP)
		}
	}
	return nil
}

// reservedRanges are address ranges that are routable-looking but not public,
// and that net.IP's own predicates do not cover.
//
// The carrier-grade NAT range is the one that matters: cloud platforms put
// internal services in it, and one cloud serves instance metadata from
// 100.100.100.200, which IsPrivate reports as public. The other two are
// protocol assignments that no upstream is ever served from, and the NAT64
// prefix is a way to write an arbitrary IPv4 address - private ranges
// included - as an IPv6 one.
var reservedRanges = func() []*net.IPNet {
	cidrs := []string{
		"100.64.0.0/10",  // RFC 6598 carrier-grade NAT
		"192.0.0.0/24",   // RFC 6890 IETF protocol assignments
		"198.18.0.0/15",  // RFC 2544 benchmarking
		"64:ff9b::/96",   // RFC 6052 NAT64
		"64:ff9b:1::/48", // RFC 8215 local-use NAT64
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("upstream: parsing reserved range " + cidr + ": " + err.Error())
		}
		out = append(out, network)
	}
	return out
}()

// isPublicIP reports whether ip is an address an upstream can legitimately be
// served from: a global-unicast address that is not loopback, link-local
// (cloud metadata services included), multicast, unspecified, private under
// RFC 1918 or RFC 4193, or in one of the reserved ranges above.
func isPublicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, network := range reservedRanges {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

// RedactURL removes any userinfo from a URL so it can be logged or returned in
// an error.
//
// Validation rejects a credentialed URL outright, so this is for the caller
// that has to name the URL it was given - in a log line, a trace, or a tool
// result - before or regardless of whether validation accepted it.
func RedactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return rawURL
	}
	u.User = nil
	return u.String()
}
