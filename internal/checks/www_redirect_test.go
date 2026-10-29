package checks

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// TestWWWRedirectSkipsSubdomains: for production https://app.example.com the
// check probed www.app.example.com and warned that it "does not resolve".
func TestWWWRedirectSkipsSubdomains(t *testing.T) {
	ctx := Context{Config: &config.PreflightConfig{URLs: config.URLConfig{Production: "https://app.preflight.sh"}}}
	res, _ := WWWRedirectCheck{}.Run(ctx)
	if res.Passed || !res.Skipped || !strings.Contains(res.Message, "Skipped for subdomain") {
		t.Fatalf("passed=%v skipped=%v msg=%q", res.Passed, res.Skipped, res.Message)
	}
}

// TestDescribeFetchError: every failure used to read "does not resolve",
// including the TLS error behind the subdomain case above.
func TestDescribeFetchError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("HEAD x: %w", &net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}), "does not resolve"},
		{fmt.Errorf("HEAD x: %w", x509.HostnameError{Certificate: &x509.Certificate{}, Host: "x"}), "has a TLS certificate error"},
		{fmt.Errorf("HEAD x: %w", context.DeadlineExceeded), "timed out"},
		{fmt.Errorf("HEAD x: connection refused"), "is unreachable"},
	}
	for _, tc := range cases {
		if got := describeFetchError(tc.err); got != tc.want {
			t.Errorf("describeFetchError(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
