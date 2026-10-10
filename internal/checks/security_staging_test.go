package checks

import (
	"net/http"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// TestSecurityHeadersStagingDownIsNotAFailure pins production as the
// authoritative environment: a configured staging host that is down during
// the scan (a local dev server) is noted but must not fail a compliant site.
// When production itself never answered, the check still fails.
func TestSecurityHeadersStagingDownIsNotAFailure(t *testing.T) {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=1")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'self'")
	ctx := Context{
		Config:              &config.PreflightConfig{URLs: config.URLConfig{Staging: "http://localhost:3000", Production: "https://example.com"}},
		PageFetchProduction: PageFetch{URL: "https://example.com/", Status: 200, Headers: h},
		PageFetchStaging:    PageFetch{URL: "http://localhost:3000/", Status: 0},
	}
	res, _ := SecurityHeadersCheck{}.Run(ctx)
	if !res.Passed || !strings.Contains(res.Message, "staging: unreachable") {
		t.Fatalf("staging down with compliant prod: passed=%v msg=%q", res.Passed, res.Message)
	}

	ctx.PageFetchProduction = PageFetch{URL: "https://example.com/", Status: 0}
	res, _ = SecurityHeadersCheck{}.Run(ctx)
	if res.Passed {
		t.Fatalf("both environments down must fail: msg=%q", res.Message)
	}
}
