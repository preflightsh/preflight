package checks

import (
	"net/http"
	"strings"
	"testing"
)

func cspPrefetch(csp string) PageFetch {
	h := http.Header{
		"Strict-Transport-Security": []string{"max-age=31536000"},
		"X-Content-Type-Options":    []string{"nosniff"},
		"Referrer-Policy":           []string{"strict-origin-when-cross-origin"},
	}
	if csp != "" {
		h.Set("Content-Security-Policy", csp)
	}
	return PageFetch{URL: "https://prod/", Status: http.StatusOK, Headers: h}
}

// A present-but-weak CSP is a suggestion, not a missing header: eight real
// sites with script-src 'unsafe-inline' were told CSP was missing.
func TestSecurityHeadersWeakCSP(t *testing.T) {
	cases := []struct {
		csp     string
		passed  bool
		message string
	}{
		{"default-src 'self'; script-src 'self' 'unsafe-inline'", true, "weak Content-Security-Policy: script-src allows 'unsafe-inline'"},
		{"script-src 'self' 'unsafe-eval'", true, "weak Content-Security-Policy: script-src allows 'unsafe-eval'"},
		{"default-src * 'unsafe-inline'", true, "weak Content-Security-Policy: default-src allows *"},
		{"frame-ancestors 'none'", true, "weak Content-Security-Policy: no script-src or default-src"},
		{"default-src 'self'", true, "prod: ✓"},
		{"", false, "prod missing: Content-Security-Policy"},
	}
	for _, tc := range cases {
		res, _ := SecurityHeadersCheck{}.Run(securityContext("https://prod", cspPrefetch(tc.csp)))
		if res.Passed != tc.passed || !strings.Contains(res.Message, tc.message) {
			t.Errorf("csp %q: passed=%v msg=%q, want passed=%v containing %q", tc.csp, res.Passed, res.Message, tc.passed, tc.message)
		}
		if strings.Contains(res.Message, "missing: Content-Security-Policy (invalid") {
			t.Errorf("csp %q: a present header reported as missing: %q", tc.csp, res.Message)
		}
		if tc.csp != "" && tc.message != "prod: ✓" && len(res.Suggestions) == 0 {
			t.Errorf("csp %q: expected a suggestion", tc.csp)
		}
	}
}
