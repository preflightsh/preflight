package checks

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

func securityContext(prodURL string, prefetch PageFetch) Context {
	return Context{
		Config:              &config.PreflightConfig{URLs: config.URLConfig{Production: prodURL}},
		Client:              http.DefaultClient,
		PageFetchProduction: prefetch,
	}
}

func TestSecurityHeadersUsesPrefetchedResponse(t *testing.T) {
	t.Run("a blocked response is reported, not measured", func(t *testing.T) {
		// Cloudflare's challenge page carries the edge's headers, not the
		// site's: reporting them invents missing headers for a site the
		// scan never reached.
		blocked := PageFetch{
			URL:    "https://prod/",
			Status: http.StatusForbidden,
			Headers: http.Header{
				"Cf-Mitigated":           []string{"challenge"},
				"X-Content-Type-Options": []string{"nosniff"},
			},
		}
		res, _ := SecurityHeadersCheck{}.Run(securityContext("https://prod", blocked))
		if res.Passed {
			t.Fatalf("blocked prod should not pass; got OK %q", res.Message)
		}
		if !strings.Contains(res.Message, "prod: blocked (HTTP 403)") {
			t.Fatalf("message = %q, want it to report the block", res.Message)
		}
		if strings.Contains(res.Message, "missing") {
			t.Fatalf("message = %q, want no header verdict from a block page", res.Message)
		}
	})

	t.Run("headers come from the prefetch without a second request", func(t *testing.T) {
		var hits int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
		}))
		defer srv.Close()

		prefetch := PageFetch{
			URL:    "https://prod/",
			Status: http.StatusOK,
			Headers: http.Header{
				"Strict-Transport-Security": []string{"max-age=31536000"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Referrer-Policy":           []string{"strict-origin-when-cross-origin"},
			},
		}
		res, _ := SecurityHeadersCheck{}.Run(securityContext(srv.URL, prefetch))
		if hits != 0 {
			t.Errorf("security check made %d request(s), want 0 when the scan already fetched the page", hits)
		}
		// CSP is the only one absent from the prefetched response.
		if !strings.Contains(res.Message, "prod missing: Content-Security-Policy") {
			t.Fatalf("message = %q, want CSP reported missing from the prefetched headers", res.Message)
		}
	})

	t.Run("a fetch the scan already failed is not retried", func(t *testing.T) {
		attempted := PageFetch{URL: "https://prod/"}
		res, _ := SecurityHeadersCheck{}.Run(securityContext("https://prod", attempted))
		if !strings.Contains(res.Message, "prod: unreachable") {
			t.Fatalf("message = %q, want 'prod: unreachable'", res.Message)
		}
	})

	t.Run("falls back to its own request outside a scan", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
		}))
		defer srv.Close()

		res, _ := SecurityHeadersCheck{}.Run(securityContext(srv.URL, PageFetch{}))
		// Plain HTTP test server, so HSTS isn't required and nothing is missing.
		if !res.Passed {
			t.Fatalf("expected all headers found via the check's own request; got %q", res.Message)
		}
	})
}
