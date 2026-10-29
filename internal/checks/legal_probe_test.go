package checks

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

func legalHTTPContext(t *testing.T, root, url string, client *http.Client) Context {
	t.Helper()
	return Context{RootDir: root, Client: client, Config: &config.PreflightConfig{URLs: config.URLConfig{Production: url}}}
}

var legalSourceFiles = map[string]string{
	"app/privacy/page.tsx": "export default function P() { return <h1>Privacy</h1> }",
	"app/terms/page.tsx":   "export default function T() { return <h1>Terms</h1> }",
}

// TestLegalPagesBlockedHostFallsBackToSource: a WAF that answers 403 to
// every probe says nothing about the pages, so the source decides.
func TestLegalPagesBlockedHostFallsBackToSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	t.Run("source has both pages", func(t *testing.T) {
		root := writeFiles(t, legalSourceFiles)
		res, _ := LegalPagesCheck{}.Run(legalHTTPContext(t, root, srv.URL, srv.Client()))
		if !res.Passed {
			t.Fatalf("expected pass from source, got %q", res.Message)
		}
		if !strings.Contains(res.Message, "app/privacy/page.tsx") || !strings.Contains(res.Message, "not verified on the deployed site") {
			t.Fatalf("message should name the source and note the unverified deploy: %q", res.Message)
		}
	})

	t.Run("source has neither", func(t *testing.T) {
		res, _ := LegalPagesCheck{}.Run(legalHTTPContext(t, t.TempDir(), srv.URL, srv.Client()))
		if res.Passed || !res.Inconclusive {
			t.Fatalf("expected inconclusive, got passed=%v inconclusive=%v %q", res.Passed, res.Inconclusive, res.Message)
		}
	})
}

// TestLegalPagesUnreachableHostFallsBackToSource: when the homepage
// prefetch found the host down, nothing is probed and the source decides.
func TestLegalPagesUnreachableHostFallsBackToSource(t *testing.T) {
	root := writeFiles(t, legalSourceFiles)
	url := "https://down.example.invalid"
	ctx := legalHTTPContext(t, root, url, http.DefaultClient)
	ctx.PageFetchProduction = PageFetch{URL: url}
	if !ctx.HostUnreachable(url) {
		t.Fatal("fixture: host should read as unreachable")
	}
	res, _ := LegalPagesCheck{}.Run(ctx)
	if !res.Passed {
		t.Fatalf("expected pass from source, got %q", res.Message)
	}
}

// TestLegalPagesNonceCatchAll: a catch-all host whose shell carries a
// per-request CSP nonce and CSRF token must still be recognised as a
// catch-all, not as a host that serves every legal page.
func TestLegalPagesNonceCatchAll(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := n.Add(1)
		fmt.Fprintf(w, `<!doctype html><html><head><title>Acme</title>
<meta name="csrf-token" content="tok%[1]d">
<script nonce="n%[1]d">window.__CSRF__ = {"csrfToken":"x%[1]d"}</script></head>
<body><form><input type="hidden" name="authenticity_token" value="a%[1]d"></form>
<div id="root"></div><p>Sorry, %[2]s was not found</p></body></html>`, i, r.URL.Path)
	}))
	defer srv.Close()

	res, _ := LegalPagesCheck{}.Run(legalHTTPContext(t, t.TempDir(), srv.URL, srv.Client()))
	if res.Passed {
		t.Fatalf("a nonce-bearing catch-all shell counted as legal pages: %q", res.Message)
	}
}

// TestLegalPagesRealPagesOnNonceHost: real pages on a host that also stamps
// nonces are still found.
func TestLegalPagesRealPagesOnNonceHost(t *testing.T) {
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := n.Add(1)
		body := "<div id=root></div>"
		switch r.URL.Path {
		case "/privacy":
			body = "<h1>Privacy Policy</h1><p>We collect very little.</p>"
		case "/terms":
			body = "<h1>Terms of Service</h1><p>Be nice.</p>"
		}
		fmt.Fprintf(w, `<html><head><script nonce="n%d"></script></head><body>%s</body></html>`, i, body)
	}))
	defer srv.Close()

	res, _ := LegalPagesCheck{}.Run(legalHTTPContext(t, t.TempDir(), srv.URL, srv.Client()))
	if !res.Passed {
		t.Fatalf("real pages should be found: %q", res.Message)
	}
}

// TestLegalPagesDisplayPathsUseSlashes: reported source paths are the same
// on every OS.
func TestLegalPagesDisplayPathsUseSlashes(t *testing.T) {
	root := writeFiles(t, map[string]string{
		"src/pages/privacy.tsx": "x",
		"app/terms/page.tsx":    "x",
	})
	res, _ := LegalPagesCheck{}.Run(Context{RootDir: root, Config: &config.PreflightConfig{}})
	if !res.Passed {
		t.Fatalf("expected pass: %q", res.Message)
	}
	if strings.Contains(res.Message, `\`) || !strings.Contains(res.Message, "src/pages/privacy.tsx") || !strings.Contains(res.Message, "app/terms/page.tsx") {
		t.Fatalf("paths should use forward slashes: %q", res.Message)
	}
}
