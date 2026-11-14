package checks

import (
	"fmt"
	"image"
	"image/png"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

func allSecurityHeaders() http.Header {
	return http.Header{
		"Strict-Transport-Security": []string{"max-age=31536000"},
		"X-Content-Type-Options":    []string{"nosniff"},
		"Referrer-Policy":           []string{"strict-origin-when-cross-origin"},
		"Content-Security-Policy":   []string{"default-src 'self'"},
	}
}

// An API whose root is a 404 sends its headers on that 404. It used to be
// reported as "prod: unreachable" with advice to add the headers.
func TestSecurityHeadersMeasuredOnA404Homepage(t *testing.T) {
	ctx := securityContext("https://api.example.com", PageFetch{URL: "https://api.example.com/", Status: http.StatusNotFound, Headers: allSecurityHeaders()})
	res, _ := SecurityHeadersCheck{}.Run(ctx)
	if !res.Passed || !strings.Contains(res.Message, "prod: ✓") {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}

	h := allSecurityHeaders()
	h.Del("Referrer-Policy")
	ctx = securityContext("https://api.example.com", PageFetch{URL: "https://api.example.com/", Status: http.StatusNotFound, Headers: h})
	res, _ = SecurityHeadersCheck{}.Run(ctx)
	if res.Passed || res.Inconclusive || !strings.Contains(res.Message, "prod missing: Referrer-Policy") {
		t.Fatalf("passed=%v inconclusive=%v msg=%q", res.Passed, res.Inconclusive, res.Message)
	}
}

// A host that never showed its headers is not missing them.
func TestSecurityHeadersUnmeasuredIsInconclusive(t *testing.T) {
	for _, status := range []int{0, http.StatusForbidden, http.StatusBadGateway} {
		fetch := PageFetch{URL: "https://example.com/", Status: status}
		if status != 0 {
			fetch.Headers = http.Header{"Server": []string{"edge"}}
		}
		res, _ := SecurityHeadersCheck{}.Run(securityContext("https://example.com", fetch))
		if res.Passed || !res.Inconclusive || strings.Contains(res.Message, "missing") {
			t.Errorf("status %d: passed=%v inconclusive=%v msg=%q", status, res.Passed, res.Inconclusive, res.Message)
		}
		for _, s := range res.Suggestions {
			if strings.Contains(s, "Add missing security headers") {
				t.Errorf("status %d: advice to add headers for a host that was never measured", status)
			}
		}
	}
}

// Production is authoritative. A local dev server as staging almost never
// sends headers the production edge adds, and that used to fail the check.
func TestSecurityHeadersStagingMissingDoesNotFailACompliantProduction(t *testing.T) {
	ctx := Context{
		Config:              &config.PreflightConfig{URLs: config.URLConfig{Staging: "http://localhost:3000", Production: "https://example.com"}},
		PageFetchProduction: PageFetch{URL: "https://example.com/", Status: 200, Headers: allSecurityHeaders()},
		PageFetchStaging:    PageFetch{URL: "http://localhost:3000/", Status: 200, Headers: http.Header{"X-Powered-By": []string{"dev"}}},
	}
	res, _ := SecurityHeadersCheck{}.Run(ctx)
	if !res.Passed || !strings.Contains(res.Message, "staging missing:") || !strings.Contains(res.Message, "not a failure") {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}

	// With production itself missing headers, staging's still count.
	prod := allSecurityHeaders()
	prod.Del("Content-Security-Policy")
	ctx.PageFetchProduction.Headers = prod
	res, _ = SecurityHeadersCheck{}.Run(ctx)
	if res.Passed {
		t.Fatalf("production missing a header must fail: %q", res.Message)
	}

	// Staging alone is the only environment there is.
	ctx.Config.URLs.Production = ""
	ctx.PageFetchProduction = PageFetch{}
	res, _ = SecurityHeadersCheck{}.Run(ctx)
	if res.Passed || res.Inconclusive {
		t.Fatalf("staging-only with missing headers must fail: %q", res.Message)
	}
}

func TestCSPStrictDynamicIsNotWeak(t *testing.T) {
	strict := "script-src 'nonce-r4nd0m' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'"
	if w := cspWeakness(strict); w != "" {
		t.Errorf("the recommended strict policy read as weak: %q", w)
	}
	if w := cspWeakness("script-src 'strict-dynamic' https:"); w == "" {
		t.Error("'strict-dynamic' without a nonce or hash does not make https: safe")
	}
	if w := cspWeakness("script-src 'nonce-x' 'strict-dynamic' 'unsafe-eval'"); !strings.Contains(w, "'unsafe-eval'") {
		t.Errorf("'unsafe-eval' is weak under any policy: %q", w)
	}
}

// A static host that cannot set headers delivers its policy in a meta tag.
func TestSecurityHeadersAcceptMetaCSP(t *testing.T) {
	h := allSecurityHeaders()
	h.Del("Content-Security-Policy")
	ctx := securityContext("https://example.com", PageFetch{URL: "https://example.com/", Status: 200, Headers: h})
	ctx.PageHTMLProduction = `<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head></html>`
	res, _ := SecurityHeadersCheck{}.Run(ctx)
	if !res.Passed {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}
}

func TestRenderedDocReadsTheHeadOnly(t *testing.T) {
	doc := parseRenderedHTML(`<html lang="en"><head><title> </title>
<meta name="description" content="">
<meta name="description" content="The real one">
<script type="application/ld+json"></script>
</head><body><svg><title>Logo</title></svg>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization"}</script>
</body></html>`)
	if doc.title != "" {
		t.Errorf("title = %q; an SVG title in the body is not the page title", doc.title)
	}
	if doc.meta("description") != "The real one" {
		t.Errorf("description = %q; an empty duplicate must not win", doc.meta("description"))
	}
	if !doc.hasJSONLD {
		t.Error("a valid JSON-LD block after an empty one should count")
	}

	for _, block := range []string{``, `   `, `{not json`, `{"name":"no schema here"}`} {
		d := parseRenderedHTML(`<head><script type="application/ld+json">` + block + `</script></head>`)
		if d.hasJSONLD {
			t.Errorf("ld+json %q counted as structured data", block)
		}
	}
	graph := parseRenderedHTML(`<script type="application/ld+json">[{"@graph":[{"@type":"WebSite"}]}]</script>`)
	if !graph.hasJSONLD {
		t.Error("an array with @graph is structured data")
	}
}

func canonicalContext(html string) Context {
	return Context{
		Config:              &config.PreflightConfig{URLs: config.URLConfig{Production: "https://example.com"}},
		PageFetchProduction: PageFetch{URL: "https://example.com/", Status: 200},
		PageHTMLProduction:  html,
	}
}

// A canonical pointing at a dev server, or a relative one, passed.
func TestCanonicalMustPointAtTheLiveSite(t *testing.T) {
	cases := []struct {
		href   string
		passed bool
	}{
		{"https://example.com/", true},
		{"https://www.example.com/page", true},
		{"http://localhost:3000/", false},
		{"http://127.0.0.1:8080/", false},
		{"/page", false},
		{"", false},
	}
	for _, tc := range cases {
		res, _ := CanonicalURLCheck{}.Run(canonicalContext(`<head><link rel="canonical" href="` + tc.href + `"></head>`))
		if res.Passed != tc.passed {
			t.Errorf("canonical %q: passed=%v msg=%q", tc.href, res.Passed, res.Message)
		}
	}

	// Staging may point wherever it likes.
	ctx := Context{
		Config:           &config.PreflightConfig{URLs: config.URLConfig{Staging: "http://localhost:3000"}},
		PageFetchStaging: PageFetch{URL: "http://localhost:3000/", Status: 200},
		PageHTMLStaging:  `<link rel="canonical" href="http://localhost:3000/">`,
	}
	if res, _ := (CanonicalURLCheck{}).Run(ctx); !res.Passed {
		t.Errorf("staging: %q", res.Message)
	}
}

// The source heuristics only run with no URL configured. Loose is fine;
// passing on a comment, an unrelated tag, or a sentence is not.
func TestLocalHeuristicsDoNotPassOnUnrelatedText(t *testing.T) {
	langNo := []string{
		`<html><head><style lang="scss">a{}</style></head></html>`,
		`<template><div/></template><script lang="ts">export default {}</script>`,
		`<html><link rel="alternate" hreflang="en" href="/en"></html>`,
		`<html data-lang="en"></html>`,
		`<!-- <html lang="en"> --><html>`,
	}
	for _, src := range langNo {
		if hasLangAttribute(src, "") {
			t.Errorf("lang passed on %q", src)
		}
	}
	langYes := []string{
		`<html lang="en">`, `<html class="x" lang='en-GB'>`, `<html lang={locale}>`, `<html lang="{{ app()->getLocale() }}">`,
		`<html lang="<%= I18n.locale %>">`, `<Html lang="en">`, "htmlAttrs: { lang: 'en' }", `<html dir="ltr" lang="{{ .Site.Language.Lang }}">`,
	}
	for _, src := range langYes {
		if !hasLangAttribute(src, "") {
			t.Errorf("lang missed %q", src)
		}
	}

	canonicalNo := []string{
		`<base href="{{ .Site.BaseURL }}">`,
		`@section('title', 'Our canonical guide')`,
		`{{ "Read our canonical guide to widgets" }}`,
		`<%= t("The canonical way to do it") %>`,
		`<!-- <link rel="canonical" href="x"> -->`,
	}
	for _, src := range canonicalNo {
		if hasCanonicalURL(src, "") {
			t.Errorf("canonical passed on %q", src)
		}
	}
	canonicalYes := []string{
		`<link rel="canonical" href="{{ .Permalink }}">`,
		`<link href="https://example.com/" rel="canonical">`,
		`{{ seomatic.link.get('canonical') }}`,
		`{% include "partials/_canonical.twig" %}`,
		`<%= canonical_tag %>`,
		`<?php echo get_canonical_url(); ?>`,
		`@yield('canonical')`,
		`@include('partials.canonical')`,
		`{{ $canonical }}`,
		`{% block canonical %}{% endblock %}`,
		`alternates: { canonical: "/" }`,
	}
	for _, src := range canonicalYes {
		if !hasCanonicalURL(src, "") {
			t.Errorf("canonical missed %q", src)
		}
	}

	schemaNo := []string{`<%= render "admin/schema_browser" %>`, `{% include "docs/schema-migrations.html" %}`}
	for _, src := range schemaNo {
		if hasStructuredData(src, "") {
			t.Errorf("structured data passed on %q", src)
		}
	}
	schemaYes := []string{
		`<%= render "shared/schema" %>`, `<%= render partial: "layouts/structured_data" %>`, `{{ partial "schema.html" . }}`,
		`{% include "seo/_json-ld.twig" %}`, `{% include "schema-organization.html" %}`,
		`<script type="application/ld+json">{}</script>`,
	}
	for _, src := range schemaYes {
		if !hasStructuredData(src, "") {
			t.Errorf("structured data missed %q", src)
		}
	}

	if checkAlternatePatterns(`const blurb = "The title: a story about widgets"`, "title") {
		t.Error("title passed on a string that contains \"title:\"")
	}
	for _, src := range []string{`export const meta = { title: "Home" }`, `{"title": "Home"}`, `<Seo title="Home" />`} {
		if !checkAlternatePatterns(src, "title") {
			t.Errorf("title missed %q", src)
		}
	}
}

// A TODO comment mentioning apple-touch-icon satisfied the favicon check.
func TestFaviconAppleTouchIconInACommentDoesNotCount(t *testing.T) {
	root := writeFiles(t, map[string]string{
		"public/favicon.ico":     "icon",
		"public/manifest.json":   "{}",
		"index.html":             "<html><head><!-- TODO add apple-touch-icon --></head></html>",
		"templates/_layout.twig": "{# apple-touch-icon goes here #}",
	})
	ctx := Context{RootDir: root, Config: &config.PreflightConfig{Stack: "static"}}
	res, _ := FaviconCheck{}.Run(ctx)
	if res.Passed || !strings.Contains(res.Message, "apple-touch-icon") {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}
	for _, s := range res.Suggestions {
		if strings.Contains(s, "manifest") || strings.Contains(s, "favicon.ico") {
			t.Errorf("suggestion for something that is present: %q", s)
		}
	}
}

func TestResolveImageURL(t *testing.T) {
	cases := []struct{ raw, base, want string }{
		{"//cdn.example.com/a.png", "https://example.com", "https://cdn.example.com/a.png"},
		{"  https://cdn.example.com/a.png \n", "https://example.com", "https://cdn.example.com/a.png"},
		{" /img/a.png ", "https://example.com/", "https://example.com/img/a.png"},
		{"img/a.png", "https://example.com", "https://example.com/img/a.png"},
		{"/a.png", "example.com", "https://example.com/a.png"},
		{"HTTPS://CDN.example.com/a.png", "https://example.com", "HTTPS://CDN.example.com/a.png"},
		{"data:image/png;base64,AAAA", "https://example.com", ""},
		{"", "https://example.com", ""},
		{"/a.png", "", ""},
	}
	for _, tc := range cases {
		if got := resolveImageURL(tc.raw, tc.base); got != tc.want {
			t.Errorf("resolveImageURL(%q, %q) = %q, want %q", tc.raw, tc.base, got, tc.want)
		}
	}
}

func ogContext(t *testing.T, width, height int, head string) (Context, *atomic.Int64) {
	t.Helper()
	var imageRequests atomic.Int64
	srv := handlerServer(t, func(w http.ResponseWriter, r *http.Request) {
		imageRequests.Add(1)
		w.Header().Set("Content-Type", "image/png")
		_ = png.Encode(w, image.NewRGBA(image.Rect(0, 0, width, height)))
	})
	rendered := "<html><head>" + fmt.Sprintf(head, srv.URL) + "</head></html>"
	return Context{
		RootDir:             t.TempDir(),
		Client:              srv.Client(),
		Config:              &config.PreflightConfig{URLs: config.URLConfig{Production: "https://example.com"}},
		PageFetchProduction: PageFetch{URL: "https://example.com/", Status: 200},
		PageHTMLProduction:  rendered,
	}, &imageRequests
}

const ogHeadBoth = `<meta property="og:image" content=" %[1]s/og.png ">
<meta property="og:url" content="https://example.com/"><meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image"><meta name="twitter:image" content="%[1]s/og.png">`

const ogHeadNoTwitterImage = `<meta property="og:image" content="%[1]s/og.png">
<meta property="og:url" content="https://example.com/"><meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">`

// 1200x628 is what Facebook's own tools exported for years.
func TestOGImageJustUnderRecommendedPasses(t *testing.T) {
	ctx, requests := ogContext(t, 1200, 628, ogHeadBoth)
	res := OGTwitterCheck{}.runRendered(ctx)
	if !res.Passed {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("the same image was fetched %d times, want 1", got)
	}

	ctx, _ = ogContext(t, 800, 418, ogHeadBoth)
	if res := (OGTwitterCheck{}).runRendered(ctx); res.Passed || !strings.Contains(res.Message, "below recommended") {
		t.Errorf("a clearly undersized image should still be called out: %q", res.Message)
	}
}

// X falls back to og:image, so a missing twitter:image is not a finding.
func TestOGWithoutTwitterImagePasses(t *testing.T) {
	ctx, _ := ogContext(t, 1200, 630, ogHeadNoTwitterImage)
	res := OGTwitterCheck{}.runRendered(ctx)
	if !res.Passed {
		t.Fatalf("passed=%v msg=%q", res.Passed, res.Message)
	}
}

// The Next.js built-in 404 is HTML, but it is nobody's custom page.
func TestNextDefault404IsAStockPage(t *testing.T) {
	body := strings.ToLower(`<!DOCTYPE html><html><body><div><h1 class="next-error-h1" style="x">404</h1><div><h2>This page could not be found.</h2></div></div></body></html>`)
	if !isStockErrorPage(body) {
		t.Error("the Next.js default 404 should read as a stock page")
	}
	if isStockErrorPage(strings.ToLower(`<html><body><h1>Lost?</h1><p>That page is gone. Try the <a href="/">homepage</a>.</p></body></html>`)) {
		t.Error("a custom 404 should not read as a stock page")
	}
}
