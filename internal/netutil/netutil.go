// Package netutil provides shared HTTP / network helpers used across
// preflight. The main purpose is to make outbound requests that come
// from untrusted sources (e.g. URLs harvested from scanned repo content)
// refuse to hit private / link-local / loopback / metadata endpoints.
package netutil

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrPrivateAddress is returned when a dial or redirect resolves to a
// private, loopback, link-local, or metadata-range IP and the caller
// asked for a safe client.
var ErrPrivateAddress = errors.New("refusing to connect to private or loopback address")

// MaxResponseBody is a conservative cap for bodies read from untrusted
// sources (script contents, images). Chosen to be big enough for any
// legitimate analytics/OG asset but small enough to contain a memory bomb.
const MaxResponseBody = 5 * 1024 * 1024 // 5 MiB

// IsPrivateIP reports whether ip is in a range we refuse to dial when
// called from content harvested off-disk. Covers loopback, link-local,
// RFC1918, unique local, and the cloud metadata /16.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	// 169.254.0.0/16 is covered by IsLinkLocalUnicast, but the metadata
	// endpoint 169.254.169.254 is worth calling out defensively.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 169 && ip4[1] == 254 {
		return true
	}
	return false
}

// AddrFromURL returns the "host:port" dial target rawURL points at, with
// the scheme's default port filled in so it can be compared against the
// addr strings the dialer sees. A bare "localhost:3000" (no scheme) is
// accepted and treated as http, matching how preflight.yml URLs are
// written in practice. Returns "" when rawURL has no host.
func AddrFromURL(rawURL string) string {
	candidate := rawURL
	// Schemes are case-insensitive per RFC 3986, and prepending "http://"
	// to something that already has one yields a URL whose host is the
	// literal "http", so match the prefix without regard to case.
	lower := strings.ToLower(candidate)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		candidate = "http://" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return ""
	}
	return addrForURL(parsed)
}

// addrForURL is AddrFromURL for an already-parsed URL.
func addrForURL(u *url.URL) string {
	host := u.Hostname()
	if host == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return net.JoinHostPort(strings.ToLower(host), port)
}

// exemptAddrs is a set of "host:port" targets the caller has explicitly
// vouched for, which are allowed to resolve to private addresses. It
// exists for the local-dev workflow: pointing production/staging at
// localhost is a trusted-config choice, but it must exempt only that one
// target. Anything else the scan reaches for (notably URLs harvested
// from page content, like og:image) stays behind the private-IP guard.
type exemptAddrs map[string]struct{}

func newExemptAddrs(addrs []string) exemptAddrs {
	if len(addrs) == 0 {
		return nil
	}
	set := make(exemptAddrs, len(addrs))
	for _, a := range addrs {
		if a == "" {
			continue
		}
		set[normalizeAddr(a)] = struct{}{}
	}
	return set
}

// normalizeAddr routes both sides of the comparison through the same
// JoinHostPort so bracketed IPv6 ("[::1]:80") and case differences can't
// cause a spurious miss.
func normalizeAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.ToLower(addr)
	}
	return strings.ToLower(net.JoinHostPort(host, port))
}

func (e exemptAddrs) allows(addr string) bool {
	if len(e) == 0 {
		return false
	}
	_, ok := e[normalizeAddr(addr)]
	return ok
}

func (e exemptAddrs) allowsURL(u *url.URL) bool {
	addr := addrForURL(u)
	return addr != "" && e.allows(addr)
}

// safeDialer wraps net.Dialer.DialContext and rejects any connection
// whose destination resolves to a private IP, unless the target is one
// of the caller's explicitly exempted addrs. Tries each resolved IP in
// order so dual-stack hosts with a broken AAAA still connect.
func safeDialer(timeout time.Duration, exempt exemptAddrs) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Vouched-for target: dial it as written, private or not.
		if exempt.allows(addr) {
			return d.DialContext(ctx, network, addr)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no IP addresses for %s", host)
		}
		for _, ip := range ips {
			if IsPrivateIP(ip.IP) {
				return nil, fmt.Errorf("%w: %s", ErrPrivateAddress, ip.IP)
			}
		}
		var lastErr error
		for _, ip := range ips {
			conn, dialErr := d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
}

// SafeHTTPClient returns an *http.Client that refuses to dial private
// addresses and refuses redirects to private addresses. Use this for any
// outbound HTTP whose URL came from untrusted content (repo files,
// third-party responses).
func SafeHTTPClient(timeout time.Duration) *http.Client {
	return SafeHTTPClientAllowing(timeout, nil)
}

// SafeHTTPClientAllowing is SafeHTTPClient with an escape hatch for
// specific "host:port" targets (see AddrFromURL) that the operator has
// explicitly configured and is therefore trusted to reach, even though
// they resolve to private addresses.
//
// The exemption is deliberately per-target rather than per-client: a
// developer pointing production at http://localhost:3000 should not
// thereby unlock every other private address for the rest of the scan.
// Passing no addrs yields exactly SafeHTTPClient's behavior.
func SafeHTTPClientAllowing(timeout time.Duration, allowedAddrs []string) *http.Client {
	exempt := newExemptAddrs(allowedAddrs)
	transport := &http.Transport{
		DialContext:           safeDialer(timeout, exempt),
		ResponseHeaderTimeout: timeout,
		TLSHandshakeTimeout:   timeout,
		DisableKeepAlives:     true,
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: exempt.checkRedirect,
	}
}

// SafeCheckRedirect blocks redirects past a sane count or to private
// hosts. Use with any client that can follow redirects into attacker
// territory.
func SafeCheckRedirect(req *http.Request, via []*http.Request) error {
	return exemptAddrs(nil).checkRedirect(req, via)
}

// checkRedirect is SafeCheckRedirect honoring the exemption set, so a
// redirect within an operator-configured local host still follows.
func (e exemptAddrs) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("too many redirects")
	}
	if e.allowsURL(req.URL) {
		return nil
	}
	host := req.URL.Hostname()
	if host == "" {
		return nil
	}
	// If it's already a literal IP, check directly.
	if ip := net.ParseIP(host); ip != nil {
		if IsPrivateIP(ip) {
			return fmt.Errorf("%w: %s", ErrPrivateAddress, host)
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if IsPrivateIP(ip) {
			return fmt.Errorf("%w: %s resolves to %s", ErrPrivateAddress, host, ip)
		}
	}
	return nil
}

// LimitBody wraps resp.Body in an io.LimitReader, so a huge body can't
// be silently slurped into memory by downstream decoders.
func LimitBody(body io.Reader, max int64) io.Reader {
	if max <= 0 {
		max = MaxResponseBody
	}
	return io.LimitReader(body, max)
}

// SafeTLSDial performs a TLS handshake against addr, refusing to dial
// any IP that IsPrivateIP reports. Use this for any TLS dial whose host
// came from untrusted content (e.g. a URL parsed from preflight.yml).
//
// All resolved IPs are tried until one succeeds (so dual-stack hosts
// with a broken AAAA still work). The total budget — DNS lookup + every
// dial attempt — is bounded by timeout. If cfg is nil a fresh
// tls.Config is used; if cfg.ServerName is empty it is set to the
// hostname portion of addr so SNI and cert verification still work
// after we substitute a literal IP into the dial target.
func SafeTLSDial(network, addr string, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses for %s", host)
	}
	for _, ip := range ips {
		if IsPrivateIP(ip.IP) {
			return nil, fmt.Errorf("%w: %s", ErrPrivateAddress, ip.IP)
		}
	}
	// Start with TLS 1.2 as the floor. Modern Go already defaults here,
	// but being explicit lets the linter prove it and shields us from a
	// future caller passing a Config that downgrades.
	clonedCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg != nil {
		clonedCfg = cfg.Clone()
		if clonedCfg.MinVersion == 0 {
			clonedCfg.MinVersion = tls.VersionTLS12
		}
	}
	if clonedCfg.ServerName == "" {
		clonedCfg.ServerName = host
	}
	var lastErr error
	for _, ip := range ips {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if lastErr == nil {
				lastErr = context.DeadlineExceeded
			}
			break
		}
		dialer := &net.Dialer{Timeout: remaining}
		conn, dialErr := tls.DialWithDialer(dialer, network, net.JoinHostPort(ip.IP.String(), port), clonedCfg)
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, lastErr
}
