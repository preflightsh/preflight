package checks

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// filesServer serves the given paths (content type, body) and answers a
// plain 404 for anything else.
func filesServer(t *testing.T, files map[string][2]string) (url string, client *http.Client) {
	t.Helper()
	srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		if f, ok := files[r.URL.Path]; ok {
			w.Header().Set("Content-Type", f[0])
			fmt.Fprint(w, f[1])
			return
		}
		http.NotFound(w, r)
	})
	return srv.URL, srv.Client()
}

const (
	goodRobots  = "User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml\n"
	goodSitemap = `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/</loc></url></urlset>`
	goodLLMs    = "# Example\n\n> A site.\n\n- [Docs](https://example.com/docs)\n"
)

// A 200 is not the file. These bodies all used to pass robots_txt,
// sitemap, and llms_txt.
func TestWellKnownFilesRejectSoft404s(t *testing.T) {
	bodies := map[string][2]string{
		"plain text error":            {"text/plain", "Not Found"},
		"JSON error":                  {"application/json", `{"error":"not found"}`},
		"HTML behind a comment":       {"application/octet-stream", "<!-- build 42 -->\n<!doctype html><html><body>App</body></html>"},
		"HTML behind a BOM":           {"text/plain", "\xef\xbb\xbf<!DOCTYPE html><html><body>App</body></html>"},
		"HTML with an html type":      {"text/html; charset=utf-8", "<html><body>App</body></html>"},
		"whitespace":                  {"text/plain", "  \n "},
		"unrelated plain text":        {"text/plain", "ok"},
		"error page with a 200":       {"text/plain", "Error: no such file"},
		"JSON served as octet-stream": {"application/octet-stream", `{"status":404}`},
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			url, client := filesServer(t, map[string][2]string{
				"/robots.txt": body, "/sitemap.xml": body, "/llms.txt": body, "/": {"text/html", "<html></html>"},
			})
			ctx := scanContext(t, t.TempDir(), url, client)
			for _, c := range []Check{RobotsTxtCheck{}, SitemapCheck{}, LLMsTxtCheck{}} {
				res, _ := c.Run(ctx)
				if res.Passed || res.Inconclusive {
					t.Errorf("%s: passed=%v inconclusive=%v msg=%q", c.ID(), res.Passed, res.Inconclusive, res.Message)
				}
			}
		})
	}
}

func TestWellKnownFilesServedLive(t *testing.T) {
	url, client := filesServer(t, map[string][2]string{
		"/robots.txt":        {"text/plain", "\xef\xbb\xbf" + goodRobots},
		"/sitemap-index.xml": {"application/xml", `<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></sitemapindex>`},
		"/llms.txt":          {"text/plain; charset=utf-8", goodLLMs},
		"/ads.txt":           {"text/plain", "google.com, pub-0000000000000000, DIRECT, f08c47fec0942fa0\n"},
		"/humans.txt":        {"text/plain", "/* TEAM */\nDeveloper: Someone\n"},
		"/":                  {"text/html", "<html></html>"},
	})
	ctx := scanContext(t, t.TempDir(), url, client)
	ctx.Config.Checks.AdsTxt = &config.AdsTxtConfig{Enabled: true}
	ctx.Config.Checks.HumansTxt = &config.HumansTxtConfig{Enabled: true}
	for _, c := range []Check{RobotsTxtCheck{}, SitemapCheck{}, LLMsTxtCheck{}, AdsTxtCheck{}, HumansTxtCheck{}} {
		res, _ := c.Run(ctx)
		if !res.Passed || !strings.Contains(res.Message, "served at "+url) {
			t.Errorf("%s: passed=%v msg=%q", c.ID(), res.Passed, res.Message)
		}
	}
}

// A CMS that serves ads.txt or humans.txt dynamically has no file on disk.
// Those two checks had no HTTP fallback at all, and no way to tell a
// blocked host from a missing file.
func TestAdsAndHumansBlockedHostIsInconclusive(t *testing.T) {
	srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	ctx := scanContext(t, t.TempDir(), srv.URL, srv.Client())
	ctx.Config.Checks.AdsTxt = &config.AdsTxtConfig{Enabled: true}
	ctx.Config.Checks.HumansTxt = &config.HumansTxtConfig{Enabled: true}
	for _, c := range []Check{AdsTxtCheck{}, HumansTxtCheck{}} {
		res, _ := c.Run(ctx)
		if res.Passed || !res.Inconclusive {
			t.Errorf("%s: passed=%v inconclusive=%v msg=%q", c.ID(), res.Passed, res.Inconclusive, res.Message)
		}
	}
}

// A file in a web root has a known URL. When the deployed site answers and
// does not serve it, the copy in the repo (a stale build output, or a file
// the server does not publish) is not a robots.txt anyone can fetch.
func TestWellKnownStaticFileNotServed(t *testing.T) {
	url, client := filesServer(t, map[string][2]string{"/": {"text/html", "<html></html>"}})
	root := writeFiles(t, map[string]string{"dist/robots.txt": goodRobots, "public/sitemap.xml": goodSitemap})
	ctx := scanContext(t, root, url, client)

	res, _ := RobotsTxtCheck{}.Run(ctx)
	if res.Passed || res.Inconclusive || !strings.Contains(res.Message, "robots.txt found at dist/robots.txt but not served at "+url+"/robots.txt (HTTP 404)") {
		t.Errorf("robots: passed=%v msg=%q", res.Passed, res.Message)
	}
	res, _ = SitemapCheck{}.Run(ctx)
	if res.Passed || !strings.Contains(res.Message, "found at public/sitemap.xml but not served at") {
		t.Errorf("sitemap: passed=%v msg=%q", res.Passed, res.Message)
	}
}

// The repo's copy still decides when there is no site to ask, when the
// site could not answer, and when the site serves it.
func TestWellKnownStaticFileStillPasses(t *testing.T) {
	root := writeFiles(t, map[string]string{"public/robots.txt": goodRobots})

	offline := Context{RootDir: root, Config: &config.PreflightConfig{}}
	if res, _ := (RobotsTxtCheck{}).Run(offline); !res.Passed || res.Message != "robots.txt found at public/robots.txt" {
		t.Errorf("offline: passed=%v msg=%q", res.Passed, res.Message)
	}

	blocked := handlerServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	if res, _ := (RobotsTxtCheck{}).Run(scanContext(t, root, blocked.URL, blocked.Client())); !res.Passed {
		t.Errorf("blocked host: passed=%v msg=%q", res.Passed, res.Message)
	}

	url, client := filesServer(t, map[string][2]string{"/robots.txt": {"text/plain", goodRobots}, "/": {"text/html", "<html></html>"}})
	if res, _ := (RobotsTxtCheck{}).Run(scanContext(t, root, url, client)); !res.Passed || res.Message != "robots.txt found at public/robots.txt" {
		t.Errorf("served: passed=%v msg=%q", res.Passed, res.Message)
	}
}

// A route or plugin that generates the file has no certain URL, so source
// evidence of one passes whatever the probe of the usual paths found.
func TestWellKnownGeneratedFilePassesWithoutAProbeHit(t *testing.T) {
	url, client := filesServer(t, map[string][2]string{"/": {"text/html", "<html></html>"}})
	root := writeFiles(t, map[string]string{"app/robots.ts": "export default function robots() { return { rules: [] } }"})
	res, _ := RobotsTxtCheck{}.Run(scanContext(t, root, url, client))
	if !res.Passed || !strings.Contains(res.Message, "generated via app/robots.ts") {
		t.Errorf("passed=%v msg=%q", res.Passed, res.Message)
	}
}

// Only "non-empty" used to be tested, so an HTML page saved as
// dist/sitemap.xml passed.
func TestWellKnownStaticFileMustBeThatKindOfFile(t *testing.T) {
	root := writeFiles(t, map[string]string{
		"dist/sitemap.xml": "<!doctype html><html><body>Not a sitemap</body></html>",
		"dist/robots.txt":  "<html><body>404</body></html>",
	})
	ctx := Context{RootDir: root, Config: &config.PreflightConfig{}}
	res, _ := SitemapCheck{}.Run(ctx)
	if res.Passed || !strings.Contains(res.Message, "dist/sitemap.xml exists but is not a sitemap.xml file") {
		t.Errorf("sitemap: passed=%v msg=%q", res.Passed, res.Message)
	}
	if res, _ := (RobotsTxtCheck{}).Run(ctx); res.Passed {
		t.Errorf("robots: passed=%v msg=%q", res.Passed, res.Message)
	}
}

func TestWellKnownValidators(t *testing.T) {
	valid := []struct {
		f    wellKnownFile
		body string
	}{
		{robotsTxtFile, "User-agent: *\nDisallow:\n"},
		{robotsTxtFile, "# nothing to block\n"},
		{robotsTxtFile, "sitemap: https://example.com/sitemap.xml"},
		{sitemapFile, goodSitemap},
		{sitemapFile, "\x1f\x8b\x08\x00binary"},
		{sitemapFile, `<rss version="2.0"><channel></channel></rss>`},
		{llmsTxtFile, goodLLMs},
		{adsTxtFile, "# ads.txt\ngoogle.com, pub-1, DIRECT\n"},
		{adsTxtFile, "contact=ads@example.com\n"},
		{adsTxtFile, "# no authorized sellers\n"},
		{humansTxtFile, "/* TEAM */\nSomeone\n"},
	}
	for _, tc := range valid {
		if !tc.f.valid([]byte(tc.body)) {
			t.Errorf("%s: %q should be valid", tc.f.name, tc.body)
		}
	}
	invalid := []struct {
		f    wellKnownFile
		body string
	}{
		{robotsTxtFile, "Not Found"},
		{robotsTxtFile, `{"error":"not found"}`},
		{sitemapFile, "Not Found"},
		{sitemapFile, "<html><body></body></html>"},
		{llmsTxtFile, "Not Found"},
		{llmsTxtFile, `{"error":"not found"}`},
		{llmsTxtFile, "<p>hi</p>"},
		{adsTxtFile, "Not Found"},
		{adsTxtFile, "just some words"},
		{humansTxtFile, "404 page not found"},
	}
	for _, tc := range invalid {
		if tc.f.valid([]byte(tc.body)) {
			t.Errorf("%s: %q should be rejected", tc.f.name, tc.body)
		}
	}
}

// Production serving "Disallow: /" to every crawler, or a noindex homepage,
// used to be "robots.txt served at ..." and a pass. It is the staging
// config shipped to production.
func TestRobotsProductionBlocksIndexing(t *testing.T) {
	run := func(robots, homepage string, header http.Header) CheckResult {
		srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/robots.txt":
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, robots)
			case "/":
				for k, v := range header {
					w.Header()[k] = v
				}
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, homepage)
			default:
				http.NotFound(w, r)
			}
		})
		res, _ := RobotsTxtCheck{}.Run(scanContext(t, t.TempDir(), srv.URL, srv.Client()))
		return res
	}
	// scanContext points production at a loopback test server, which the
	// indexing rules skip as a local URL, so those are tested directly.
	if res := run("User-agent: *\nDisallow: /\n", "<html></html>", nil); !res.Passed {
		t.Errorf("a local production URL is a dev server and is left alone: %q", res.Message)
	}

	prodCtx := func(html string, header http.Header) Context {
		return Context{
			Config:              &config.PreflightConfig{URLs: config.URLConfig{Production: "https://example.com", Staging: "https://staging.example.com"}},
			PageHTMLProduction:  html,
			PageFetchProduction: PageFetch{URL: "https://example.com/", Status: 200, Headers: header},
			PageHTMLStaging:     `<meta name="robots" content="noindex">`,
		}
	}
	pass := CheckResult{ID: "robots_txt", Severity: SeverityInfo, Passed: true, Message: "robots.txt served at https://example.com/robots.txt"}
	live := func(body string) liveFile {
		return liveFile{state: liveServed, production: []byte(body), productionURL: "https://example.com/robots.txt"}
	}

	res := productionIndexing(prodCtx("<html></html>", http.Header{}), pass, live("User-agent: *\nDisallow: /\n"))
	if res.Passed || res.Severity != SeverityWarn || !strings.Contains(res.Message, "tells all crawlers to stay out") {
		t.Errorf("disallow all: passed=%v msg=%q", res.Passed, res.Message)
	}

	res = productionIndexing(prodCtx(`<html><head><META NAME="Robots" CONTENT="NOINDEX, nofollow"></head></html>`, http.Header{}), pass, live(goodRobots))
	if res.Passed || !strings.Contains(res.Message, "marked noindex (meta robots)") {
		t.Errorf("meta noindex: passed=%v msg=%q", res.Passed, res.Message)
	}

	res = productionIndexing(prodCtx("<html></html>", http.Header{"X-Robots-Tag": []string{"googlebot: noindex"}}), pass, live(goodRobots))
	if res.Passed || !strings.Contains(res.Message, "X-Robots-Tag header") {
		t.Errorf("header noindex: passed=%v msg=%q", res.Passed, res.Message)
	}

	// Staging is supposed to keep crawlers out; only production counts.
	res = productionIndexing(prodCtx("<html></html>", http.Header{"X-Robots-Tag": []string{"max-image-preview:none, max-snippet:-1"}}), pass, live(goodRobots))
	if !res.Passed {
		t.Errorf("an indexable production must pass: %q", res.Message)
	}

	stagingOnly := Context{Config: &config.PreflightConfig{URLs: config.URLConfig{Staging: "https://staging.example.com"}}, PageHTMLStaging: `<meta name="robots" content="noindex">`}
	if res := productionIndexing(stagingOnly, pass, liveFile{}); !res.Passed {
		t.Errorf("staging only: %q", res.Message)
	}

	// A failing result keeps its own finding and gains the note.
	missing := CheckResult{ID: "robots_txt", Severity: SeverityWarn, Message: "robots.txt not found"}
	res = productionIndexing(prodCtx(`<meta name="robots" content="none">`, http.Header{}), missing, liveFile{})
	if !strings.Contains(res.Message, "robots.txt not found; the production homepage is marked noindex") {
		t.Errorf("msg=%q", res.Message)
	}
}

func TestRobotsBlocksEverything(t *testing.T) {
	blocks := []string{
		"User-agent: *\nDisallow: /\n",
		"user-agent: *\r\ndisallow: /  # staging\r\n",
		"User-agent: Googlebot\nUser-agent: *\nDisallow: /\n",
		"User-agent: Bingbot\nDisallow:\n\nUser-agent: *\nDisallow: /\n",
	}
	for _, body := range blocks {
		if !robotsBlocksEverything([]byte(body)) {
			t.Errorf("%q should read as blocking everything", body)
		}
	}
	open := []string{
		"User-agent: *\nDisallow:\n",
		"User-agent: *\nDisallow: /admin\n",
		"User-agent: *\nDisallow: /\nAllow: /public\n",
		"User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nAllow: /\n",
		"# Disallow: /\nUser-agent: *\nAllow: /\n",
	}
	for _, body := range open {
		if robotsBlocksEverything([]byte(body)) {
			t.Errorf("%q should not read as blocking everything", body)
		}
	}
}

// A host whose HTML catch-all changes on every request (a CSRF token, a
// render time) cannot be recognised by digest, but a plain text file it
// serves is still not that shell. dailytips.dev serves a real llms.txt
// next to such a catch-all and was reported as not serving it.
func TestWellKnownTextFileOnAVaryingHTMLCatchAll(t *testing.T) {
	var n atomic.Int64
	srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/llms.txt":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, goodLLMs)
		case "/humans.txt":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "/* TEAM */\nDeveloper: Someone\n")
		default:
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			fmt.Fprintf(w, "<!doctype html><html><body><p>request %d</p></body></html>", n.Add(1))
		}
	})
	ctx := scanContext(t, t.TempDir(), srv.URL, srv.Client())
	ctx.Config.Checks.HumansTxt = &config.HumansTxtConfig{Enabled: true}
	if shell := ctx.catchAllFor(srv.URL); !shell.unstable || !shell.html {
		t.Fatalf("shell = %+v, want an unstable HTML catch-all", shell)
	}
	for _, c := range []Check{LLMsTxtCheck{}, HumansTxtCheck{}} {
		res, _ := c.Run(ctx)
		if !res.Passed || !strings.Contains(res.Message, "served at "+srv.URL) {
			t.Errorf("%s: passed=%v msg=%q", c.ID(), res.Passed, res.Message)
		}
	}
}

// A catch-all that answers every path with varying plain text is still
// not evidence of the file.
func TestWellKnownTextFileOnAVaryingTextCatchAll(t *testing.T) {
	var n atomic.Int64
	srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "# Page %d\n\n> Generated for %s\n", n.Add(1), "everything")
	})
	ctx := scanContext(t, t.TempDir(), srv.URL, srv.Client())
	if res, _ := (LLMsTxtCheck{}).Run(ctx); res.Passed {
		t.Errorf("llms_txt passed on a varying text catch-all: %q", res.Message)
	}
}
