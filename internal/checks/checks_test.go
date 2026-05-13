package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

func TestIsLocalURL(t *testing.T) {
	cases := []struct {
		in   string
		want bool
		why  string
	}{
		// Real local URLs — must still be detected.
		{"http://localhost", true, "bare localhost"},
		{"http://localhost:3000", true, "localhost with port"},
		{"localhost:3000", true, "no scheme + port"},
		{"http://127.0.0.1", true, "loopback IPv4"},
		{"http://127.0.0.5:8080", true, "loopback IPv4 (not .1)"},
		{"http://0.0.0.0", true, "unspecified IPv4"},
		{"http://[::1]", true, "loopback IPv6"},
		{"https://myapp.local", true, "mDNS suffix"},
		{"https://x.y.test", true, ".test suffix"},
		{"https://example.ddev.site", true, "ddev"},
		{"https://yow.lndo.site", true, "lando"},
		{"https://app.localhost", true, ".localhost TLD"},

		// SSRF-bypass attempts via the new local TLDs — must NOT match.
		{"https://attacker.com/?h=yow.lndo.site", false, ".lndo.site in query"},
		{"https://example.lndo.site.evil.com", false, "'.lndo.site' is not the suffix"},

		// SSRF-bypass attempts via substring — must NOT match.
		{"https://localhost.attacker.com/", false, "substring 'localhost' in hostname"},
		{"https://attacker.com/?h=localhost", false, "substring in query"},
		{"https://attacker.com#127.0.0.1", false, "substring in fragment"},
		{"https://attacker-127.0.0.1.example.com/", false, "substring in hostname"},
		{"https://localproject.com", false, "starts with 'local' but not local"},
		{"https://my.local.com", false, "'.local' is not the suffix"},
		{"https://example.test.evil.com", false, "'.test' is not the suffix"},

		// Non-local public.
		{"https://example.com", false, "public domain"},
		{"https://8.8.8.8", false, "public IP"},
	}
	for _, tc := range cases {
		got := IsLocalURL(tc.in)
		if got != tc.want {
			t.Errorf("IsLocalURL(%q) = %v, want %v (%s)", tc.in, got, tc.want, tc.why)
		}
	}
}

func TestRelPath(t *testing.T) {
	tmp := t.TempDir()
	cases := []struct {
		name   string
		base   string
		target string
		want   string
	}{
		{
			name:   "target inside base",
			base:   tmp,
			target: filepath.Join(tmp, "sub", "file.go"),
			want:   filepath.Join("sub", "file.go"),
		},
		{
			name:   "target equals base",
			base:   tmp,
			target: tmp,
			want:   ".",
		},
		{
			name:   "absolute base with relative target falls back to basename",
			base:   "/var/log",
			target: "hosts",
			want:   "hosts",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := relPath(tc.base, tc.target)
			if got != tc.want {
				t.Errorf("relPath(%q, %q) = %q, want %q", tc.base, tc.target, got, tc.want)
			}
		})
	}
}

func TestStripComments(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "single-line JS comment removed",
			in:   "var x = 1; // a comment\nvar y = 2;",
			want: "var x = 1; \nvar y = 2;",
		},
		{
			name: "multi-line C-style comment removed",
			in:   "/* secret */\nfn();",
			want: "\nfn();",
		},
		{
			name: "HTML comment removed",
			in:   "<p>hello</p><!-- secret -->",
			want: "<p>hello</p>",
		},
		{
			name: "Twig comment removed",
			in:   "{{ x }}{# inner #}",
			want: "{{ x }}",
		},
		{
			name: "hash line comment removed but preserves Twig blocks",
			in:   "# a shell comment\nkey: value",
			want: "\nkey: value",
		},
		{
			name: "hash comment without leading whitespace kept when adjacent to brace",
			in:   "#{not_a_comment}",
			want: "#{not_a_comment}",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripComments(tc.in)
			if got != tc.want {
				t.Errorf("stripComments(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFetchPageHTML(t *testing.T) {
	t.Run("returns body on 200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<html>ok</html>"))
		}))
		defer srv.Close()
		got := FetchPageHTML(context.Background(), srv.Client(), srv.URL)
		if !strings.Contains(got, "<html>ok</html>") {
			t.Errorf("FetchPageHTML = %q, want body containing <html>ok</html>", got)
		}
	})

	t.Run("returns empty on 4xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "no", http.StatusNotFound)
		}))
		defer srv.Close()
		if got := FetchPageHTML(context.Background(), srv.Client(), srv.URL); got != "" {
			t.Errorf("FetchPageHTML on 404 = %q, want empty string", got)
		}
	})

	t.Run("returns empty on empty URL", func(t *testing.T) {
		if got := FetchPageHTML(context.Background(), http.DefaultClient, ""); got != "" {
			t.Errorf("FetchPageHTML(empty) = %q, want empty string", got)
		}
	})

	t.Run("nil context is treated as Background", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}))
		defer srv.Close()
		// Intentionally pass a nil context to exercise FetchPageHTML's
		// guard clause. The linter complains about nil contexts in
		// general, but here it's the behavior under test.
		var nilCtx context.Context
		if got := FetchPageHTML(nilCtx, srv.Client(), srv.URL); got != "ok" {
			t.Errorf("FetchPageHTML with nil ctx = %q, want %q", got, "ok")
		}
	})

	t.Run("cancelled context aborts the fetch", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}))
		defer srv.Close()
		if got := FetchPageHTML(ctx, srv.Client(), srv.URL); got != "" {
			t.Errorf("FetchPageHTML with cancelled ctx = %q, want empty string", got)
		}
	})
}

func TestRunPerEnv(t *testing.T) {
	const sentinel = "<meta name=\"og:title\" content=\"x\">"
	scanRendered := func(html string) []string {
		if strings.Contains(html, sentinel) {
			return nil
		}
		return []string{"og:title"}
	}

	t.Run("no envs configured returns empty", func(t *testing.T) {
		ctx := Context{Config: &config.PreflightConfig{}}
		summary, ok := RunPerEnv(ctx, scanRendered)
		if summary != "" || ok {
			t.Errorf("RunPerEnv with no envs = (%q, %v), want (\"\", false)", summary, ok)
		}
	})

	t.Run("production passes is authoritative", func(t *testing.T) {
		ctx := Context{
			Config: &config.PreflightConfig{
				URLs: config.URLConfig{Production: "https://prod", Staging: "https://staging"},
			},
			PageHTMLProduction: sentinel,
			PageHTMLStaging:    "<html></html>",
		}
		summary, ok := RunPerEnv(ctx, scanRendered)
		if !ok {
			t.Errorf("RunPerEnv prod-passes authoritativePassed = false, want true (summary=%q)", summary)
		}
		if !strings.Contains(summary, "prod: ✓") {
			t.Errorf("RunPerEnv summary = %q, want it to contain 'prod: ✓'", summary)
		}
	})

	t.Run("production unreachable does not pass even if staging is fine", func(t *testing.T) {
		ctx := Context{
			Config: &config.PreflightConfig{
				URLs: config.URLConfig{Production: "https://prod", Staging: "https://staging"},
			},
			PageHTMLProduction: "",
			PageHTMLStaging:    sentinel,
		}
		_, ok := RunPerEnv(ctx, scanRendered)
		if ok {
			t.Errorf("RunPerEnv with unreachable prod authoritativePassed = true, want false")
		}
	})

	t.Run("staging-only env is authoritative when production absent", func(t *testing.T) {
		ctx := Context{
			Config: &config.PreflightConfig{
				URLs: config.URLConfig{Staging: "https://staging"},
			},
			PageHTMLStaging: sentinel,
		}
		_, ok := RunPerEnv(ctx, scanRendered)
		if !ok {
			t.Errorf("RunPerEnv staging-only authoritativePassed = false, want true")
		}
	})
}
