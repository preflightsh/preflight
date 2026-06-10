package checks

import "testing"

func TestParseRenderedHTML(t *testing.T) {
	doc := parseRenderedHTML(`<!doctype html>
<html LANG="en-US">
<head>
	<title>  My Site  </title>
	<meta content="https://x.test/og.png" property="OG:IMAGE">
	<meta name='twitter:card' content='summary_large_image' />
	<meta
		name="viewport"
		content="width=device-width, initial-scale=1">
	<meta name=description content="hi">
	<link href="/feed.xml" rel="alternate">
	<link rel="SHORTCUT ICON" href=/favicon.ico>
	<link rel="canonical" href="https://x.test/">
	<script type="application/ld+json">{"@context":"https://schema.org"}</script>
</head>
<body><p>unclosed`)

	if doc.title != "My Site" {
		t.Errorf("title = %q, want %q", doc.title, "My Site")
	}
	if doc.htmlLang != "en-US" {
		t.Errorf("htmlLang = %q, want en-US", doc.htmlLang)
	}
	// content-before-property order and uppercase property name
	if !doc.hasMeta("og:image") {
		t.Error("og:image should be detected despite attribute order and case")
	}
	// single quotes + self-closing
	if !doc.hasMeta("twitter:card") {
		t.Error("twitter:card should be detected")
	}
	// multi-line tag
	if _, ok := doc.metaName["viewport"]; !ok {
		t.Error("viewport should be detected across line breaks")
	}
	// unquoted attribute value
	if _, ok := doc.metaName["description"]; !ok {
		t.Error("description should be detected with unquoted name attr")
	}
	// multi-token rel, case-insensitive
	if !doc.hasLinkRel("icon") {
		t.Error(`rel="SHORTCUT ICON" should count as icon`)
	}
	if !doc.hasLinkRel("canonical") {
		t.Error("canonical link should be detected")
	}
	if doc.hasLinkRel("manifest") {
		t.Error("manifest should not be detected")
	}
	if !doc.hasJSONLD {
		t.Error("JSON-LD script should be detected")
	}
	if doc.hasMeta("og:url") {
		t.Error("og:url should not be detected")
	}
}

func TestParseRenderedHTMLGarbage(t *testing.T) {
	for _, in := range []string{"", "not html at all", "<><<<meta", "<meta name=>"} {
		d := parseRenderedHTML(in)
		if d.hasMeta("og:image") || d.title != "" || d.hasJSONLD {
			t.Errorf("garbage input %q produced detections", in)
		}
	}
}
