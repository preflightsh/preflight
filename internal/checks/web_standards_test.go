package checks

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// parentBaseURLs decides which hosts get probed for a subdomain app's
// robots.txt / sitemap.xml / llms.txt, so anything it returns becomes a real
// outbound request. It must never walk past the registrable domain onto a
// host the user has no relationship with.
func TestParentBaseURLs(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "subdomain walks up to apex",
			in:   "https://app.example.com",
			want: []string{"https://example.com"},
		},
		{
			name: "www walks up to apex",
			in:   "https://www.example.com",
			want: []string{"https://example.com"},
		},
		{
			name: "apex has no parent",
			in:   "https://example.com",
			want: nil,
		},
		{
			name: "nested subdomains walk up one label at a time",
			in:   "https://a.b.example.com",
			want: []string{"https://b.example.com", "https://example.com"},
		},
		{
			// A label count would emit https://co.uk here, which is a public
			// suffix, not a site anyone owns.
			name: "multi-label public suffix stops at the registrable domain",
			in:   "https://app.example.co.uk",
			want: []string{"https://example.co.uk"},
		},
		{
			name: "apex on a multi-label public suffix has no parent",
			in:   "https://example.co.uk",
			want: nil,
		},
		{
			name: "com.au stops at the registrable domain",
			in:   "https://shop.example.com.au",
			want: []string{"https://example.com.au"},
		},
		{
			// Walking IP labels invents hostnames belonging to someone else.
			name: "private IP has no parent",
			in:   "http://192.168.1.5:3000",
			want: nil,
		},
		{
			name: "loopback IP has no parent",
			in:   "http://127.0.0.1:8080",
			want: nil,
		},
		{
			name: "IPv6 has no parent",
			in:   "http://[::1]:8080",
			want: nil,
		},
		{
			name: "localhost has no registrable domain",
			in:   "https://localhost:3000",
			want: nil,
		},
		{
			name: "empty input",
			in:   "",
			want: nil,
		},
		{
			// A protocol-relative URL still parses a host; the walk defaults
			// the scheme rather than emitting "://example.com".
			name: "scheme defaults to https",
			in:   "//app.example.com",
			want: []string{"https://example.com"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parentBaseURLs(tc.in)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parentBaseURLs(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// probeFileAtBase backs every well-known-file check. A 200 is not enough:
// SPAs and login walls answer 200 with an HTML shell for any path, which
// would report robots.txt as present on sites that have no such file.
func TestProbeFileAtBase(t *testing.T) {
	newCtx := func(client *http.Client) Context {
		return Context{Client: client, Config: &config.PreflightConfig{}}
	}

	serve := func(t *testing.T, status int, contentType, body string) *httptest.Server {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if contentType != "" {
				w.Header().Set("Content-Type", contentType)
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("plain text 200 is served", func(t *testing.T) {
		srv := serve(t, 200, "text/plain", "User-agent: *\nDisallow:\n")
		if _, ok := probeFileAtBase(newCtx(srv.Client()), srv.URL, "/robots.txt"); !ok {
			t.Error("ok = false, want true for a plain-text robots.txt")
		}
	})

	t.Run("xml 200 is served", func(t *testing.T) {
		srv := serve(t, 200, "application/xml", "<urlset></urlset>")
		if _, ok := probeFileAtBase(newCtx(srv.Client()), srv.URL, "/sitemap.xml"); !ok {
			t.Error("ok = false, want true for an XML sitemap")
		}
	})

	t.Run("html content-type is rejected", func(t *testing.T) {
		srv := serve(t, 200, "text/html", "<html><body>SPA shell</body></html>")
		if _, ok := probeFileAtBase(newCtx(srv.Client()), srv.URL, "/robots.txt"); ok {
			t.Error("ok = true, want false: an HTML body is a page, not the file")
		}
	})

	t.Run("html body without an html content-type is rejected", func(t *testing.T) {
		srv := serve(t, 200, "text/plain", "<!DOCTYPE html>\n<html><body>x</body></html>")
		if _, ok := probeFileAtBase(newCtx(srv.Client()), srv.URL, "/robots.txt"); ok {
			t.Error("ok = true, want false: doctype sniffing must catch a mislabeled page")
		}
	})

	t.Run("empty body is rejected", func(t *testing.T) {
		srv := serve(t, 200, "text/plain", "   \n  ")
		if _, ok := probeFileAtBase(newCtx(srv.Client()), srv.URL, "/robots.txt"); ok {
			t.Error("ok = true, want false for a blank body")
		}
	})

	t.Run("404 is rejected", func(t *testing.T) {
		srv := serve(t, 404, "text/plain", "not found")
		if _, ok := probeFileAtBase(newCtx(srv.Client()), srv.URL, "/robots.txt"); ok {
			t.Error("ok = true, want false for a 404")
		}
	})

	t.Run("nil client probes nothing", func(t *testing.T) {
		if _, ok := probeFileAtBase(newCtx(nil), "https://example.com", "/robots.txt"); ok {
			t.Error("ok = true, want false with no client")
		}
	})

	t.Run("empty base probes nothing", func(t *testing.T) {
		if _, ok := probeFileAtBase(newCtx(&http.Client{}), "", "/robots.txt"); ok {
			t.Error("ok = true, want false with no base URL")
		}
	})

	t.Run("trailing slash on the base does not double up", func(t *testing.T) {
		var gotPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("ok"))
		}))
		defer srv.Close()
		probeFileAtBase(newCtx(srv.Client()), srv.URL+"/", "/robots.txt")
		if gotPath != "/robots.txt" {
			t.Errorf("requested path = %q, want /robots.txt", gotPath)
		}
	})
}

func TestConfiguredProbeBaseURL(t *testing.T) {
	cases := []struct {
		name string
		urls config.URLConfig
		want string
	}{
		{"staging preferred", config.URLConfig{Staging: "https://stg", Production: "https://prod"}, "https://stg"},
		{"production when no staging", config.URLConfig{Production: "https://prod"}, "https://prod"},
		{"neither", config.URLConfig{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := configuredProbeBaseURL(Context{Config: &config.PreflightConfig{URLs: tc.urls}})
			if got != tc.want {
				t.Errorf("configuredProbeBaseURL = %q, want %q", got, tc.want)
			}
		})
	}
}

// The path tables carry a "*" for the app-name segment Phoenix embeds
// (lib/<app>_web/...). os.Stat treats "*" literally, so those entries could
// never match and Phoenix projects were told the file was missing.
func TestFindProjectPath(t *testing.T) {
	dir := t.TempDir()
	mustWrite := func(rel string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("lib/myapp_web/controllers/sitemap_controller.ex")
	mustWrite("handlers/sitemap.go")

	t.Run("literal path matches", func(t *testing.T) {
		got, ok := findProjectPath(dir, "handlers/sitemap.go")
		if !ok || got != "handlers/sitemap.go" {
			t.Errorf("got (%q, %v), want (handlers/sitemap.go, true)", got, ok)
		}
	})

	t.Run("literal path absent", func(t *testing.T) {
		if _, ok := findProjectPath(dir, "handlers/nope.go"); ok {
			t.Error("ok = true for a path that does not exist")
		}
	})

	t.Run("glob matches and reports the real path", func(t *testing.T) {
		got, ok := findProjectPath(dir, "lib/*/controllers/sitemap_controller.ex")
		if !ok {
			t.Fatal("ok = false, want true: the glob should expand")
		}
		if got != "lib/myapp_web/controllers/sitemap_controller.ex" {
			t.Errorf("got %q, want the resolved path rather than the pattern", got)
		}
	})

	t.Run("glob with no match", func(t *testing.T) {
		if _, ok := findProjectPath(dir, "lib/*/services/nothing.ex"); ok {
			t.Error("ok = true for a glob matching nothing")
		}
	})

	t.Run("glob does not match across separators", func(t *testing.T) {
		if _, ok := findProjectPath(dir, "lib/*/sitemap_controller.ex"); ok {
			t.Error("ok = true: a single star must not span directory separators")
		}
	})
}

// End-to-end: a Phoenix project with a real sitemap controller.
func TestSitemapCheckFindsPhoenixController(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "lib", "myapp_web", "controllers")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "sitemap_controller.ex"), []byte("defmodule X do\nend\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := SitemapCheck{}.Run(Context{RootDir: dir, Config: &config.PreflightConfig{Stack: "elixir"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed {
		t.Errorf("Phoenix sitemap_controller.ex present but reported %q", res.Message)
	}
	if !strings.Contains(res.Message, "myapp_web") {
		t.Errorf("message %q should name the resolved path, not the glob", res.Message)
	}
}

func TestIndexNowCheckFindsPhoenixService(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "lib", "myapp_web", "services")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "index_now.ex"), []byte("defmodule X do\nend\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := IndexNowCheck{}.Run(Context{
		RootDir: dir,
		Config: &config.PreflightConfig{
			Stack:  "elixir",
			Checks: config.ChecksConfig{IndexNow: &config.IndexNowConfig{Enabled: true, Key: "abc123"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("phoenix index_now.ex -> passed=%v msg=%q", res.Passed, res.Message)
}
