package netutil

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
		why  string
	}{
		{"127.0.0.1", true, "loopback v4"},
		{"::1", true, "loopback v6"},
		{"10.0.0.1", true, "RFC1918 10/8"},
		{"172.16.0.1", true, "RFC1918 172.16/12"},
		{"192.168.1.1", true, "RFC1918 192.168/16"},
		{"169.254.169.254", true, "AWS metadata"},
		{"169.254.0.1", true, "link-local v4"},
		{"fc00::1", true, "unique local v6"},
		{"fe80::1", true, "link-local v6"},
		{"0.0.0.0", true, "unspecified"},
		{"224.0.0.1", true, "multicast"},
		{"8.8.8.8", false, "public DNS"},
		{"1.1.1.1", false, "public DNS"},
		{"2606:4700:4700::1111", false, "public v6"},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("bad test input: %q", tc.ip)
		}
		if got := IsPrivateIP(ip); got != tc.want {
			t.Errorf("IsPrivateIP(%s) = %v, want %v (%s)", tc.ip, got, tc.want, tc.why)
		}
	}

	if !IsPrivateIP(nil) {
		t.Errorf("IsPrivateIP(nil) = false, want true (nil is treated as private)")
	}
}

func TestSafeCheckRedirect(t *testing.T) {
	t.Run("blocks redirect to literal private IP", func(t *testing.T) {
		req := &http.Request{URL: mustURL(t, "http://127.0.0.1/")}
		err := SafeCheckRedirect(req, nil)
		if !errors.Is(err, ErrPrivateAddress) {
			t.Errorf("SafeCheckRedirect to 127.0.0.1 = %v, want ErrPrivateAddress", err)
		}
	})

	t.Run("blocks redirect to literal v6 loopback", func(t *testing.T) {
		req := &http.Request{URL: mustURL(t, "http://[::1]/")}
		err := SafeCheckRedirect(req, nil)
		if !errors.Is(err, ErrPrivateAddress) {
			t.Errorf("SafeCheckRedirect to ::1 = %v, want ErrPrivateAddress", err)
		}
	})

	t.Run("allows redirect to public IP", func(t *testing.T) {
		req := &http.Request{URL: mustURL(t, "http://8.8.8.8/")}
		if err := SafeCheckRedirect(req, nil); err != nil {
			t.Errorf("SafeCheckRedirect to 8.8.8.8 = %v, want nil", err)
		}
	})

	t.Run("blocks after too many hops", func(t *testing.T) {
		req := &http.Request{URL: mustURL(t, "http://8.8.8.8/")}
		via := make([]*http.Request, 10)
		err := SafeCheckRedirect(req, via)
		if err == nil || !strings.Contains(err.Error(), "too many redirects") {
			t.Errorf("SafeCheckRedirect with 10 hops = %v, want 'too many redirects'", err)
		}
	})
}

func TestSafeHTTPClientRefusesPrivateDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	// httptest binds to a loopback address, so SafeHTTPClient must refuse.
	client := SafeHTTPClient(2 * time.Second)
	resp, err := client.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("SafeHTTPClient succeeded against loopback server; want refusal")
	}
	if !strings.Contains(err.Error(), "private or loopback") {
		t.Errorf("SafeHTTPClient err = %v, want it to mention 'private or loopback'", err)
	}
}

func TestAddrFromURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"http://localhost:3000", "localhost:3000"},
		{"https://example.com", "example.com:443"},
		{"http://example.com", "example.com:80"},
		{"https://example.com:8443/some/path", "example.com:8443"},
		{"localhost:3000", "localhost:3000"},        // no scheme, as preflight.yml often writes it
		{"HTTP://LocalHost:3000", "localhost:3000"}, // case-normalized
		{"http://[::1]:8080", "[::1]:8080"},
		{"", ""},
		{"http://", ""},
	}
	for _, tc := range cases {
		if got := AddrFromURL(tc.in); got != tc.want {
			t.Errorf("AddrFromURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A local dev URL in preflight.yml is a trusted-config choice, so that
// exact target must be dialable even though it is loopback.
func TestSafeHTTPClientAllowingPermitsExemptTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := SafeHTTPClientAllowing(2*time.Second, []string{AddrFromURL(srv.URL)})
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("exempt target refused: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// The regression that matters: exempting one local target must not
// disarm the guard for anything else. Before this was scoped per-target,
// a local production URL turned off SSRF protection for the whole scan,
// so an og:image harvested from page content could reach any internal
// address (e.g. the cloud metadata endpoint).
func TestSafeHTTPClientAllowingStillBlocksOtherPrivateTargets(t *testing.T) {
	exempt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer exempt.Close()

	// A second loopback service the config never vouched for, standing in
	// for anything else reachable from the scanning host.
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secret"))
	}))
	defer internal.Close()

	client := SafeHTTPClientAllowing(2*time.Second, []string{AddrFromURL(exempt.URL)})

	resp, err := client.Get(internal.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("reached non-exempt loopback target %s; want refusal", internal.URL)
	}
	if !errors.Is(err, ErrPrivateAddress) {
		t.Errorf("err = %v, want ErrPrivateAddress", err)
	}
}

func TestSafeHTTPClientAllowingNoExemptionsMatchesSafeHTTPClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := SafeHTTPClientAllowing(2*time.Second, nil)
	resp, err := client.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("succeeded against loopback with no exemptions; want refusal")
	}
	if !errors.Is(err, ErrPrivateAddress) {
		t.Errorf("err = %v, want ErrPrivateAddress", err)
	}
}

func TestExemptCheckRedirect(t *testing.T) {
	exempt := newExemptAddrs([]string{"localhost:3000"})

	t.Run("follows redirect within the exempt target", func(t *testing.T) {
		req := &http.Request{URL: mustURL(t, "http://localhost:3000/login")}
		if err := exempt.checkRedirect(req, nil); err != nil {
			t.Errorf("checkRedirect = %v, want nil", err)
		}
	})

	t.Run("blocks redirect to a different private port", func(t *testing.T) {
		req := &http.Request{URL: mustURL(t, "http://localhost:6379/")}
		if err := exempt.checkRedirect(req, nil); err == nil {
			t.Error("checkRedirect = nil, want refusal for non-exempt loopback port")
		}
	})

	t.Run("blocks redirect to metadata endpoint", func(t *testing.T) {
		req := &http.Request{URL: mustURL(t, "http://169.254.169.254/latest/meta-data/")}
		if err := exempt.checkRedirect(req, nil); err == nil {
			t.Error("checkRedirect = nil, want refusal for metadata endpoint")
		}
	})
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}
