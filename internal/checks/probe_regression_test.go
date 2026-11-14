package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// handlerServer starts a test server for one handler.
func handlerServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// scanContext builds the context a scan would: the homepage is fetched
// first, so each check sees the same prefetch state it does in a real run.
func scanContext(t *testing.T, root, production string, client *http.Client) Context {
	t.Helper()
	ctx := Context{
		RootDir: root,
		Client:  client,
		Probes:  NewProbeCache(),
		Config:  &config.PreflightConfig{Stack: "unknown", URLs: config.URLConfig{Production: production}},
	}
	ctx.PageHTMLProduction, ctx.PageFetchProduction = FetchPage(context.Background(), client, production)
	ctx.PageHTML = ctx.PageHTMLProduction
	return ctx
}

// An apex that redirects every path to www (here: another server on the
// same host) used to make every legal candidate a conclusive miss, because
// the redirect itself was judged instead of the page it led to.
func TestLegalPagesFollowASameSiteRedirect(t *testing.T) {
	www := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/privacy", "/terms":
			fmt.Fprint(w, "<h1>"+r.URL.Path+"</h1>")
		default:
			http.NotFound(w, r)
		}
	})
	apex := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, www.URL+r.URL.Path, http.StatusMovedPermanently)
	})
	res, _ := LegalPagesCheck{}.Run(legalHTTPContext(t, t.TempDir(), apex.URL, apex.Client()))
	if !res.Passed || !strings.Contains(res.Message, "/privacy (via HTTP)") || !strings.Contains(res.Message, "/terms (via HTTP)") {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}
}

// A site that adds a trailing slash to every path and then answers 404
// (Next.js with trailingSlash) used to read "Found privacy at /privacy".
func TestLegalPagesRedirectThatEndsIn404IsNotFound(t *testing.T) {
	srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusPermanentRedirect)
			return
		}
		http.NotFound(w, r)
	})
	res, _ := LegalPagesCheck{}.Run(legalHTTPContext(t, t.TempDir(), srv.URL, srv.Client()))
	if res.Passed || res.Inconclusive || !strings.Contains(res.Message, "Missing: privacy policy, terms of service") {
		t.Fatalf("passed=%v inconclusive=%v msg=%q", res.Passed, res.Inconclusive, res.Message)
	}
	if len(res.Suggestions) == 0 {
		t.Error("a definite miss should come with suggestions")
	}
}

// A redirect that leaves the site says nothing about the page.
func TestLegalPagesOffSiteRedirectIsNotAMiss(t *testing.T) {
	srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/landing", http.StatusFound)
	})
	res, _ := LegalPagesCheck{}.Run(legalHTTPContext(t, t.TempDir(), srv.URL, srv.Client()))
	if res.Passed || !res.Inconclusive {
		t.Fatalf("passed=%v inconclusive=%v msg=%q", res.Passed, res.Inconclusive, res.Message)
	}
}

// A static site serves the files as written.
func TestLegalPagesHTMLExtension(t *testing.T) {
	srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/privacy.html", "/terms.html":
			fmt.Fprint(w, "<h1>"+r.URL.Path+"</h1>")
		default:
			http.NotFound(w, r)
		}
	})
	res, _ := LegalPagesCheck{}.Run(legalHTTPContext(t, t.TempDir(), srv.URL, srv.Client()))
	if !res.Passed || !strings.Contains(res.Message, "/privacy.html") {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}
}

// One 404 on the deployed site used to end the check before the source
// was searched, so pages in the repo under a URL the list does not cover
// were reported as unverifiable.
func TestLegalPagesSourceStillCountsWhenTheSiteAnswers(t *testing.T) {
	srv := notFoundServer(t)
	root := writeFiles(t, legalSourceFiles)
	res, _ := LegalPagesCheck{}.Run(legalHTTPContext(t, root, srv.URL, srv.Client()))
	if !res.Passed || !strings.Contains(res.Message, "app/privacy/page.tsx") || !strings.Contains(res.Message, "from source") {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}
}

// The homepage the scan fetched links the pages, wherever they live.
func TestLegalPagesLinkedFromTheHomepage(t *testing.T) {
	srv := notFoundServer(t)
	ctx := legalHTTPContext(t, t.TempDir(), srv.URL, srv.Client())
	ctx.PageHTMLProduction = `<html><body><footer>
<!-- <a href="/old-terms">Terms of Service</a> -->
<a href="/datenschutz">Privacy Policy</a>
<a class="x" href='https://legal.example.net/acme/agb'><span>Terms of Service</span></a>
</footer></body></html>`
	res, _ := LegalPagesCheck{}.Run(ctx)
	if !res.Passed || !strings.Contains(res.Message, "/datenschutz (linked from the homepage)") || !strings.Contains(res.Message, "legal.example.net") {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}

	privacy, terms := legalLinksIn(`<a href="/a">About</a><!-- <a href="/privacy">Privacy</a> --><a href="#">Terms of use</a>`)
	if privacy != "" || terms != "" {
		t.Errorf("a commented-out link and a # link are not evidence: %q %q", privacy, terms)
	}
}

// A catch-all whose shell differs on every request cannot be recognised by
// its digest, so no 200 from it proves a page exists.
func TestCatchAllThatVariesPerRequestIsNotEvidence(t *testing.T) {
	var n atomic.Int64
	srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<!doctype html><html><body><div id=root></div><p>request %d</p></body></html>", n.Add(1))
	})
	ctx := legalHTTPContext(t, t.TempDir(), srv.URL, srv.Client())

	if shell := ctx.catchAllFor(srv.URL); !shell.answers || !shell.unstable {
		t.Fatalf("shell = %+v, want an unstable catch-all", shell)
	}
	if res, _ := (LegalPagesCheck{}).Run(ctx); res.Passed || !res.Inconclusive {
		t.Errorf("legal_pages: passed=%v inconclusive=%v msg=%q", res.Passed, res.Inconclusive, res.Message)
	}
	if res, _ := (HealthCheck{}).Run(ctx); strings.Contains(res.Message, "Health endpoint at") {
		t.Errorf("health_endpoint took a varying shell for an endpoint: %q", res.Message)
	}
}

// The health probe compared a digest that kept the request path, so a
// shell that echoes the path (a canonical link is enough) looked unique.
func TestHealthCatchAllThatEchoesThePath(t *testing.T) {
	srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!doctype html><html><head><link rel="canonical" href="https://example.com%s"></head><body><div id=root></div></body></html>`, r.URL.Path)
	})
	ctx := legalHTTPContext(t, t.TempDir(), srv.URL, srv.Client())
	res, _ := HealthCheck{}.Run(ctx)
	if strings.Contains(res.Message, "Health endpoint at") {
		t.Fatalf("msg=%q", res.Message)
	}
}

// On a catch-all host a JSON health endpoint still counts.
func TestHealthJSONEndpointOnAVaryingCatchAll(t *testing.T) {
	var n atomic.Int64
	srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"status":"ok","uptime":%d}`, n.Add(1))
			return
		}
		fmt.Fprintf(w, "<!doctype html><html><body>shell %d</body></html>", n.Add(1))
	})
	res, _ := HealthCheck{}.Run(legalHTTPContext(t, t.TempDir(), srv.URL, srv.Client()))
	if !res.Passed || !strings.Contains(res.Message, "/health returned 200") {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}
}

func healthStrictContext(srv *httptest.Server, path string) Context {
	return Context{RootDir: "", Client: srv.Client(), Config: &config.PreflightConfig{
		URLs:   config.URLConfig{Production: srv.URL},
		Checks: config.ChecksConfig{HealthEndpoint: &config.HealthEndpointConfig{Enabled: true, Path: path}},
	}}
}

// A configured path that answers 204, or that demands credentials, exists.
func TestHealthConfiguredPathAnswers204Or401(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusUnauthorized, http.StatusForbidden} {
		srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				w.WriteHeader(status)
				return
			}
			fmt.Fprint(w, "home")
		})
		res, _ := HealthCheck{}.Run(healthStrictContext(srv, "/healthz"))
		if !res.Passed || !strings.Contains(res.Message, "/healthz") {
			t.Errorf("status %d: passed=%v msg=%q", status, res.Passed, res.Message)
		}
		if status != http.StatusNoContent && !strings.Contains(res.Message, "requires authentication") {
			t.Errorf("status %d: msg=%q", status, res.Message)
		}
	}
}

// path: healthz (no leading slash) requested http://host:porthealthz.
func TestHealthPathWithoutLeadingSlash(t *testing.T) {
	var asked atomic.Value
	srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			asked.Store(r.URL.Path)
			fmt.Fprint(w, "ok")
			return
		}
		http.NotFound(w, r)
	})
	res, _ := HealthCheck{}.Run(healthStrictContext(srv, "healthz"))
	if !res.Passed || asked.Load() != "/healthz" {
		t.Fatalf("passed=%v asked=%v msg=%q", res.Passed, asked.Load(), res.Message)
	}
}

// A host that refuses the scan, fails with a 5xx, or is not there at all
// has not said that anything is missing. Every probe-based check reports
// that as inconclusive, naming what happened, instead of "not found".
func TestUnansweringHostIsInconclusiveEverywhere(t *testing.T) {
	indexNowKey := "0123456789abcdef0123456789abcdef"
	checksUnderTest := []Check{
		RobotsTxtCheck{}, SitemapCheck{}, LLMsTxtCheck{}, IndexNowCheck{},
		ErrorPagesCheck{}, FaviconCheck{}, HealthCheck{}, SecurityHeadersCheck{}, LegalPagesCheck{},
	}
	withIndexNow := func(ctx Context) Context {
		ctx.Config.Checks.IndexNow = &config.IndexNowConfig{Enabled: true, Key: indexNowKey}
		return ctx
	}

	cases := []struct {
		name string
		ctx  func(t *testing.T) Context
		want string
	}{
		{"blocked with 403", func(t *testing.T) Context {
			srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, "<html><body>Attention required</body></html>")
			})
			return scanContext(t, t.TempDir(), srv.URL, srv.Client())
		}, "blocked (HTTP 403)"},
		{"failing with 503", func(t *testing.T) Context {
			srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			})
			return scanContext(t, t.TempDir(), srv.URL, srv.Client())
		}, "HTTP 503"},
		{"not reachable", func(t *testing.T) Context {
			return scanContext(t, t.TempDir(), deadServer(t), http.DefaultClient)
		}, "unreachable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := withIndexNow(tc.ctx(t))
			for _, c := range checksUnderTest {
				res, err := c.Run(ctx)
				if err != nil {
					t.Fatalf("%s: %v", c.ID(), err)
				}
				if res.Passed || !res.Inconclusive || res.Skipped || res.Severity != SeverityWarn {
					t.Errorf("%s: passed=%v inconclusive=%v severity=%s msg=%q", c.ID(), res.Passed, res.Inconclusive, res.Severity, res.Message)
					continue
				}
				lower := strings.ToLower(res.Message)
				if !strings.Contains(lower, strings.ToLower(tc.want)) {
					t.Errorf("%s: message %q should say %q", c.ID(), res.Message, tc.want)
				}
				if strings.HasSuffix(lower, "not found") || strings.HasPrefix(lower, "missing:") || strings.Contains(lower, "no custom 404") {
					t.Errorf("%s: an unanswering host reported as a miss: %q", c.ID(), res.Message)
				}
				if strings.Contains(res.Message, "\n") {
					t.Errorf("%s: message must be one line: %q", c.ID(), res.Message)
				}
			}
		})
	}
}

// The same checks still say "not found" when the site answered.
func TestAnsweringHostStillReportsMisses(t *testing.T) {
	srv := notFoundServer(t)
	ctx := scanContext(t, t.TempDir(), srv.URL, srv.Client())
	for _, c := range []Check{RobotsTxtCheck{}, SitemapCheck{}, LLMsTxtCheck{}, ErrorPagesCheck{}} {
		res, _ := c.Run(ctx)
		if res.Passed || res.Inconclusive {
			t.Errorf("%s: passed=%v inconclusive=%v msg=%q", c.ID(), res.Passed, res.Inconclusive, res.Message)
		}
	}
}

// The scan shares the two "path that cannot exist" requests per host
// between the checks that need them.
func TestCatchAllProbeIsSharedPerScan(t *testing.T) {
	var probes atomic.Int64
	srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/preflight-404-probe") {
			probes.Add(1)
		}
		http.NotFound(w, r)
	})
	ctx := legalHTTPContext(t, t.TempDir(), srv.URL, srv.Client())
	ctx.Probes = NewProbeCache()
	for i := 0; i < 3; i++ {
		ctx.catchAllFor(srv.URL)
	}
	if got := probes.Load(); got != 2 {
		t.Errorf("catch-all probes = %d, want 2 for the whole scan", got)
	}
}
