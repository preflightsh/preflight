package checks

import (
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

func runFavicon(t *testing.T, stack string, files map[string]string, pageHTML string) CheckResult {
	t.Helper()
	root := writeFiles(t, files)
	res, err := FaviconCheck{}.Run(Context{
		RootDir:  root,
		Config:   &config.PreflightConfig{Stack: stack},
		PageHTML: pageHTML,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestFaviconDeclaredInSource(t *testing.T) {
	cases := []struct {
		name  string
		stack string
		files map[string]string
	}{
		{
			name:  "next metadata icons.icon",
			stack: "next",
			files: map[string]string{
				"app/layout.tsx":        "export const metadata = { title: 'x', icons: { icon: '/brand/logo.svg' } }\n",
				"public/brand/logo.svg": "<svg/>",
			},
		},
		{
			name:  "next metadata icons string",
			stack: "next",
			files: map[string]string{
				"src/app/layout.tsx": "export const metadata = { icons: '/brand/logo.png' }\n",
			},
		},
		{
			name:  "angular src favicon",
			stack: "angular",
			files: map[string]string{
				"src/favicon.ico": "ico",
				"src/index.html":  `<html><head><link rel="icon" type="image/x-icon" href="favicon.ico"></head></html>`,
			},
		},
		{
			name:  "link rel icon in layout only",
			stack: "rails",
			files: map[string]string{
				"app/views/layouts/application.html.erb": `<head><%= favicon_link_tag %><link href="/brand/mark.png" rel="shortcut icon"></head>`,
			},
		},
		{
			name:  "sveltekit app.html",
			stack: "svelte",
			files: map[string]string{
				"src/app.html": `<head><link rel="icon" href="%sveltekit.assets%/brand.png" /></head>`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runFavicon(t, tc.stack, tc.files, "")
			if strings.Contains(res.Message, "Missing favicon") || strings.Contains(res.Message, "Missing: favicon") {
				t.Fatalf("favicon declared in source should be found; got %q", res.Message)
			}
		})
	}
}

func TestFaviconFromDeployedHTML(t *testing.T) {
	res := runFavicon(t, "node", map[string]string{"package.json": "{}"},
		`<html><head><link rel="icon" href="/cdn/icon.png"></head></html>`)
	if strings.Contains(res.Message, "favicon,") || res.Message == "Missing favicon" {
		t.Fatalf("favicon in deployed HTML should count; got %q", res.Message)
	}
}

func TestFaviconMissingIsWarn(t *testing.T) {
	res := runFavicon(t, "node", map[string]string{"package.json": "{}"}, "")
	if res.Passed {
		t.Fatalf("expected a miss, got pass %q", res.Message)
	}
	if res.Severity != SeverityWarn {
		t.Fatalf("missing favicon should warn, got %s (%q)", res.Severity, res.Message)
	}
	if !strings.Contains(res.Message, "favicon") {
		t.Fatalf("message should name the favicon: %q", res.Message)
	}
}

func TestFaviconCommentedOutLinkIgnored(t *testing.T) {
	res := runFavicon(t, "angular", map[string]string{
		"src/index.html": `<html><head><!-- <link rel="icon" href="favicon.ico"> --></head></html>`,
	}, "")
	if !strings.Contains(res.Message, "favicon") {
		t.Fatalf("a commented-out link should not count; got %q", res.Message)
	}
}
