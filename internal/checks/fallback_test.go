package checks

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// Every HTTP probe used to take the first configured URL only, so with
// staging set to a local server that was not running, a project was told
// its sitemap, legal pages and health endpoint were missing while
// production served all of them. These tests pin the fall-through: staging
// answers 404 (or nothing at all) and production has the thing.

// notFoundServer answers 404 plain text to everything, like a dev server
// that is up but has no such route.
func notFoundServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// deadServer returns the URL of a server that has already been closed, so
// every connection is refused, like a local server that is not running.
func deadServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	return url
}

// prodServer serves the given paths with the given content types and
// answers an HTML 404 page for anything else.
func prodServer(t *testing.T, files map[string][2]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f, ok := files[r.URL.Path]; ok {
			w.Header().Set("Content-Type", f[0])
			_, _ = w.Write([]byte(f[1]))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<!doctype html><html><body>Custom 404</body></html>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fallbackContext(t *testing.T, staging, production string) Context {
	t.Helper()
	return Context{
		RootDir: t.TempDir(),
		Client:  http.DefaultClient,
		Config:  &config.PreflightConfig{Stack: "unknown", URLs: config.URLConfig{Staging: staging, Production: production}},
	}
}

func TestSitemapFallsBackToProduction(t *testing.T) {
	prod := prodServer(t, map[string][2]string{"/sitemap.xml": {"application/xml", "<urlset></urlset>"}})
	ctx := fallbackContext(t, notFoundServer(t).URL, prod.URL)
	res, _ := SitemapCheck{}.Run(ctx)
	if !res.Passed || !strings.Contains(res.Message, prod.URL+"/sitemap.xml") {
		t.Errorf("passed=%v message=%q, want the production sitemap to count", res.Passed, res.Message)
	}
}

func TestRobotsFallsBackToProduction(t *testing.T) {
	prod := prodServer(t, map[string][2]string{"/robots.txt": {"text/plain", "User-agent: *\n"}})
	ctx := fallbackContext(t, notFoundServer(t).URL, prod.URL)
	res, _ := RobotsTxtCheck{}.Run(ctx)
	if !res.Passed || !strings.Contains(res.Message, prod.URL+"/robots.txt") {
		t.Errorf("passed=%v message=%q, want the production robots.txt to count", res.Passed, res.Message)
	}
}

func TestLegalPagesFallBackToProduction(t *testing.T) {
	prod := prodServer(t, map[string][2]string{
		"/privacy": {"text/html", "<html>privacy</html>"},
		"/terms":   {"text/html", "<html>terms</html>"},
	})
	ctx := fallbackContext(t, notFoundServer(t).URL, prod.URL)
	res, _ := LegalPagesCheck{}.Run(ctx)
	if !res.Passed || !strings.Contains(res.Message, "/privacy (via HTTP)") || !strings.Contains(res.Message, "/terms (via HTTP)") {
		t.Errorf("passed=%v message=%q, want both pages found on production", res.Passed, res.Message)
	}
}

func TestErrorPages404FallsBackToProduction(t *testing.T) {
	// Staging answers a plain-text 404 (not a custom page); production
	// answers an HTML one.
	ctx := fallbackContext(t, notFoundServer(t).URL, prodServer(t, nil).URL)
	res, _ := ErrorPagesCheck{}.Run(ctx)
	if !res.Passed || !strings.Contains(res.Message, "served dynamically") {
		t.Errorf("passed=%v message=%q, want production's HTML 404 to count", res.Passed, res.Message)
	}
}

func TestHealthFallsBackToProduction(t *testing.T) {
	prod := prodServer(t, map[string][2]string{"/health": {"text/plain", "ok"}})
	ctx := fallbackContext(t, deadServer(t), prod.URL)
	res, _ := HealthCheck{}.Run(ctx)
	if !res.Passed || !strings.Contains(res.Message, prod.URL+"/health") {
		t.Errorf("passed=%v message=%q, want production's health endpoint to count", res.Passed, res.Message)
	}
}

// With both environments down the health check must still say so, naming
// the configured URL rather than claiming nothing was configured.
func TestHealthReportsUnreachableWhenEveryHostIsDown(t *testing.T) {
	staging, production := deadServer(t), deadServer(t)
	ctx := fallbackContext(t, staging, production)
	ctx.PageFetchStaging = PageFetch{URL: staging + "/", Status: 0}
	ctx.PageFetchProduction = PageFetch{URL: production + "/", Status: 0}
	res, _ := HealthCheck{}.Run(ctx)
	if res.Passed || !strings.Contains(res.Message, "Site unreachable: "+staging) {
		t.Errorf("passed=%v message=%q, want unreachable naming the staging URL", res.Passed, res.Message)
	}
}
