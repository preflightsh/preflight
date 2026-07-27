package checks

import (
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// kobonewsFooter mirrors the Craft site that surfaced this bug: the legal
// pages are hosted on other domains and only ever appear as links in a
// footer the layout includes.
const kobonewsFooter = `<ul>
  <li><a href="https://www.kobo.com/termsofuse?style=onestore&amp;store=CA">Terms of Use</a></li>
  <li><a href="https://authorize.kobo.com/terms/privacypolicy">Privacy Policy</a></li>
</ul>`

func legalContext(root string, mainLayout string) Context {
	cfg := &config.PreflightConfig{Stack: "craft"}
	if mainLayout != "" {
		cfg.Checks.SEOMeta = &config.SEOMetaConfig{Enabled: true, MainLayout: mainLayout}
	}
	return Context{RootDir: root, Config: cfg}
}

func TestLegalPagesFollowsLayoutIncludes(t *testing.T) {
	t.Run("craft footer included by the configured main layout", func(t *testing.T) {
		root := writeFiles(t, map[string]string{
			"templates/_layout.twig":         `<body>{% block content %}{% endblock %}{% include 'globals/_footer' %}</body>`,
			"templates/globals/_footer.twig": kobonewsFooter,
		})
		res, err := LegalPagesCheck{}.Run(legalContext(root, "templates/_layout.twig"))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if !res.Passed {
			t.Fatalf("legal pages should pass via the included footer; got WARN %q", res.Message)
		}
	})

	t.Run("layout found by convention when preflight.yml names none", func(t *testing.T) {
		root := writeFiles(t, map[string]string{
			"templates/_layout.twig":         `{% include "globals/_footer.twig" with { site: 1 } %}`,
			"templates/globals/_footer.twig": kobonewsFooter,
		})
		res, _ := LegalPagesCheck{}.Run(legalContext(root, ""))
		if !res.Passed {
			t.Fatalf("legal pages should pass via the conventional layout; got WARN %q", res.Message)
		}
	})

	t.Run("blade dotted include", func(t *testing.T) {
		root := writeFiles(t, map[string]string{
			"resources/views/layouts/app.blade.php":     `<body>@include('partials.footer')</body>`,
			"resources/views/partials/footer.blade.php": `<a href="/privacy-policy">Privacy</a><a href="/terms">Terms</a>`,
		})
		res, _ := LegalPagesCheck{}.Run(legalContext(root, "resources/views/layouts/app.blade.php"))
		if !res.Passed {
			t.Fatalf("legal pages should pass via the Blade partial; got WARN %q", res.Message)
		}
	})

	t.Run("include chain deeper than one hop", func(t *testing.T) {
		root := writeFiles(t, map[string]string{
			"templates/_layout.twig":         `{% include 'globals/_chrome' %}`,
			"templates/globals/_chrome.twig": `{% include 'globals/_footer' %}`,
			"templates/globals/_footer.twig": kobonewsFooter,
		})
		res, _ := LegalPagesCheck{}.Run(legalContext(root, "templates/_layout.twig"))
		if !res.Passed {
			t.Fatalf("legal pages should pass through a two-hop include; got WARN %q", res.Message)
		}
	})

	t.Run("included footer without legal links still warns", func(t *testing.T) {
		root := writeFiles(t, map[string]string{
			"templates/_layout.twig":         `{% include 'globals/_footer' %}`,
			"templates/globals/_footer.twig": `<p>&copy; 2026</p><a href="/contact">Contact</a>`,
		})
		res, _ := LegalPagesCheck{}.Run(legalContext(root, "templates/_layout.twig"))
		if res.Passed {
			t.Fatalf("legal pages should warn when nothing links to them; got OK %q", res.Message)
		}
		if !strings.Contains(res.Message, "privacy policy") || !strings.Contains(res.Message, "terms of service") {
			t.Fatalf("expected both items reported missing, got %q", res.Message)
		}
	})

	t.Run("dynamic include target is skipped, not resolved", func(t *testing.T) {
		root := writeFiles(t, map[string]string{
			"templates/_layout.twig": `{% include "globals/" ~ handle ~ "_footer" %}{% include partialName %}`,
		})
		if got := layoutChrome(root, "templates/_layout.twig"); len(got) != 0 {
			t.Fatalf("layoutChrome resolved a dynamic include: %v", got)
		}
	})
}

func TestResolveTemplate(t *testing.T) {
	root := writeFiles(t, map[string]string{
		"templates/globals/_footer.twig":            "footer",
		"templates/partials/nav.html.twig":          "nav",
		"resources/views/partials/footer.blade.php": "blade footer",
		"app/views/shared/_footer.html.erb":         "erb footer",
	})

	cases := []struct {
		name    string
		fromDir string
		target  string
		want    string
	}{
		{"craft underscore partial without extension", "templates", "globals/_footer", "templates/globals/_footer.twig"},
		{"underscore added to bare name", "templates", "globals/footer", "templates/globals/_footer.twig"},
		{"explicit extension", "templates", "globals/_footer.twig", "templates/globals/_footer.twig"},
		{"compound extension", "templates", "partials/nav", "templates/partials/nav.html.twig"},
		{"blade dotted name", "resources/views/layouts", "partials.footer", "resources/views/partials/footer.blade.php"},
		{"rails partial", "app/views/layouts", "shared/footer", "app/views/shared/_footer.html.erb"},
		{"unknown template", "templates", "globals/_header", ""},
		{"traversal is refused", "templates", "../../../etc/passwd", ""},
		{"empty target", "templates", "  ", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveTemplate(root, tc.fromDir, tc.target)
			if tc.want == "" {
				if got != "" {
					t.Fatalf("resolveTemplate(%q) = %q, want no match", tc.target, got)
				}
				return
			}
			if rel := relPath(root, got); rel != tc.want {
				t.Fatalf("resolveTemplate(%q) = %q, want %q", tc.target, rel, tc.want)
			}
		})
	}
}
