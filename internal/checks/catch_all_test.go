package checks

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

func spaServer(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := routes[r.URL.Path]; ok {
			fmt.Fprint(w, body)
			return
		}
		fmt.Fprint(w, "<!doctype html><div id=root></div>") // SPA rewrite: 200 for everything
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestCatchAllHostIsNotEvidence: an SPA rewrite (/* -> /index.html 200)
// made legal_pages report "Found privacy at /privacy (via HTTP)" and
// health_endpoint "/health returned 200" for a site with neither.
func TestCatchAllHostIsNotEvidence(t *testing.T) {
	srv := spaServer(t, nil)
	ctx := Context{RootDir: t.TempDir(), Client: srv.Client(), Config: &config.PreflightConfig{URLs: config.URLConfig{Production: srv.URL}}}

	if res, _ := (LegalPagesCheck{}).Run(ctx); res.Passed {
		t.Errorf("legal_pages passed on an SPA shell: %q", res.Message)
	}
	if res, _ := (HealthCheck{}).Run(ctx); strings.Contains(res.Message, "Health endpoint at") {
		t.Errorf("health_endpoint took the SPA shell for a health endpoint: %q", res.Message)
	}
}

// TestCatchAllHostRealPagesStillCount: on the same kind of host, pages that
// serve their own content are found.
func TestCatchAllHostRealPagesStillCount(t *testing.T) {
	srv := spaServer(t, map[string]string{
		"/privacy": "<h1>Privacy Policy</h1>",
		"/terms":   "<h1>Terms of Service</h1>",
		"/health":  `{"status":"ok"}`,
	})
	ctx := Context{RootDir: t.TempDir(), Client: srv.Client(), Config: &config.PreflightConfig{URLs: config.URLConfig{Production: srv.URL}}}

	if res, _ := (LegalPagesCheck{}).Run(ctx); !res.Passed {
		t.Errorf("legal_pages: %q", res.Message)
	}
	if res, _ := (HealthCheck{}).Run(ctx); !strings.Contains(res.Message, "Health endpoint at") {
		t.Errorf("health_endpoint: %q", res.Message)
	}
}

// TestHealthConfiguredPathMissingWarns: an explicitly configured health path
// that is missing is a finding, even though the homepage answers.
func TestHealthConfiguredPathMissingWarns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "home")
	}))
	defer srv.Close()
	ctx := Context{RootDir: t.TempDir(), Client: srv.Client(), Config: &config.PreflightConfig{
		URLs:   config.URLConfig{Production: srv.URL},
		Checks: config.ChecksConfig{HealthEndpoint: &config.HealthEndpointConfig{Enabled: true, Path: "/healthz"}},
	}}
	res, _ := HealthCheck{}.Run(ctx)
	if res.Passed || res.Severity != SeverityWarn {
		t.Fatalf("passed=%v sev=%s msg=%q", res.Passed, res.Severity, res.Message)
	}
}

// A path with no enabled key is probed first, and a missing one falls
// back to the defaults rather than warning.
func TestHealthUnsetEnabledTriesConfiguredPathFirst(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/up", "/":
			fmt.Fprint(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	run := func(path string) CheckResult {
		ctx := Context{RootDir: t.TempDir(), Client: srv.Client(), Config: &config.PreflightConfig{
			URLs:   config.URLConfig{Production: srv.URL},
			Checks: config.ChecksConfig{HealthEndpoint: &config.HealthEndpointConfig{Path: path}},
		}}
		res, _ := HealthCheck{}.Run(ctx)
		return res
	}
	if res := run("/internal/up"); !res.Passed || !strings.Contains(res.Message, "/internal/up") {
		t.Errorf("configured path: passed=%v msg=%q", res.Passed, res.Message)
	}
	if res := run("/missing"); !res.Passed {
		t.Errorf("missing unset path should fall back, got passed=%v msg=%q", res.Passed, res.Message)
	}
}
