// Package netutil provides shared HTTP / network helpers used across
// preflight. The main purpose is to make outbound requests that come
// from untrusted sources (e.g. URLs harvested from scanned repo content)
// refuse to hit private / link-local / loopback / metadata endpoints.
package netutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

// safeDialer wraps net.Dialer.DialContext and rejects any connection
// whose destination resolves to a private IP.
func safeDialer(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if IsPrivateIP(ip.IP) {
				return nil, fmt.Errorf("%w: %s", ErrPrivateAddress, ip.IP)
			}
		}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

// SafeHTTPClient returns an *http.Client that refuses to dial private
// addresses and refuses redirects to private addresses. Use this for any
// outbound HTTP whose URL came from untrusted content (repo files,
// third-party responses).
func SafeHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		DialContext:           safeDialer(timeout),
		ResponseHeaderTimeout: timeout,
		TLSHandshakeTimeout:   timeout,
		DisableKeepAlives:     true,
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: SafeCheckRedirect,
	}
}

// SafeCheckRedirect blocks redirects past a sane count or to private
// hosts. Use with any client that can follow redirects into attacker
// territory.
func SafeCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("too many redirects")
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
