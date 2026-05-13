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

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}
