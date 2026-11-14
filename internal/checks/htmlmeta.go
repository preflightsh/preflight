package checks

import (
	"encoding/json"
	"strings"

	"golang.org/x/net/html"
)

// renderedDoc is a lightweight view over a *rendered* HTML page, built with a
// real HTML tokenizer so attribute order, quoting style, whitespace, and case
// don't matter. Use it instead of regexes whenever the input is actual served
// HTML; template/source files (Twig, JSX, ERB, …) are not valid HTML and stay
// on the regex helpers.
type renderedDoc struct {
	metaName     map[string]string   // <meta name=K content=V>, keys lowercased
	metaProperty map[string]string   // <meta property=K content=V>, keys lowercased
	httpEquiv    map[string]string   // <meta http-equiv=K content=V>, keys lowercased
	linkRels     map[string][]string // rel -> hrefs, rel tokens lowercased
	title        string              // trimmed text of the first non-empty <title> in the head
	htmlLang     string              // lang attribute on <html>
	hasJSONLD    bool                // a <script type="application/ld+json"> holding schema data
}

// parseRenderedHTML tokenizes doc and collects the head-level signals the
// checks care about. The tokenizer is tolerant of broken markup and never
// fails; on garbage input the result is simply empty.
func parseRenderedHTML(doc string) renderedDoc {
	d := renderedDoc{
		metaName:     map[string]string{},
		metaProperty: map[string]string{},
		httpEquiv:    map[string]string{},
		linkRels:     map[string][]string{},
	}

	// keepFirst stores a value under key unless a non-empty one is already
	// there. Sites emit duplicates (an empty tag from the theme, then the
	// real one from an SEO plugin), and the empty one must not win.
	keepFirst := func(m map[string]string, key, value string) {
		if cur, seen := m[key]; !seen || strings.TrimSpace(cur) == "" {
			m[key] = value
		}
	}

	z := html.NewTokenizer(strings.NewReader(doc))
	inTitle := false
	inJSONLD := false
	// The page title lives in the head. A <title> after <body> opens is an
	// SVG's accessible name ("Logo"), not the page's.
	inBody := false
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return d // io.EOF or unrecoverable garbage; keep what we have
		case html.TextToken:
			if inTitle && d.title == "" {
				d.title = strings.TrimSpace(string(z.Text()))
			}
			if inJSONLD && !d.hasJSONLD {
				d.hasJSONLD = validJSONLD(z.Text())
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			attrs := map[string]string{}
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				attrs[strings.ToLower(string(k))] = string(v)
			}
			switch string(name) {
			case "meta":
				if n := strings.ToLower(strings.TrimSpace(attrs["name"])); n != "" {
					keepFirst(d.metaName, n, attrs["content"])
				}
				if p := strings.ToLower(strings.TrimSpace(attrs["property"])); p != "" {
					keepFirst(d.metaProperty, p, attrs["content"])
				}
				if e := strings.ToLower(strings.TrimSpace(attrs["http-equiv"])); e != "" {
					keepFirst(d.httpEquiv, e, attrs["content"])
				}
			case "link":
				// rel can hold multiple space-separated tokens
				// (e.g. rel="shortcut icon").
				for _, rel := range strings.Fields(strings.ToLower(attrs["rel"])) {
					d.linkRels[rel] = append(d.linkRels[rel], attrs["href"])
				}
			case "html":
				if d.htmlLang == "" {
					d.htmlLang = strings.TrimSpace(attrs["lang"])
				}
			case "body":
				inBody = true
			case "title":
				if tt == html.StartTagToken && !inBody {
					inTitle = true
				}
			case "script":
				if tt == html.StartTagToken && strings.Contains(strings.ToLower(attrs["type"]), "application/ld+json") {
					inJSONLD = true
				}
			}
		case html.EndTagToken:
			switch name, _ := z.TagName(); string(name) {
			case "title":
				inTitle = false
			case "script":
				inJSONLD = false
			}
		}
	}
}

// validJSONLD reports whether the contents of an ld+json script are schema
// data: JSON that parses and names a context or a type. An empty script tag
// left behind by a template is not structured data.
func validJSONLD(raw []byte) bool {
	text := strings.TrimSpace(string(raw))
	if text == "" || !json.Valid([]byte(text)) {
		return false
	}
	return strings.Contains(text, `"@context"`) || strings.Contains(text, `"@type"`)
}

// hasMeta reports whether the page has a meta tag for the canonical OG or
// Twitter name. OG tags conventionally use property= and Twitter tags name=,
// but plugins emit either, so both maps are consulted.
func (d renderedDoc) hasMeta(name string) bool {
	return d.meta(name) != ""
}

// meta returns the trimmed content of the meta tag for name, whichever of
// property= or name= carries it.
func (d renderedDoc) meta(name string) string {
	key := strings.ToLower(name)
	if v := strings.TrimSpace(d.metaProperty[key]); v != "" {
		return v
	}
	return strings.TrimSpace(d.metaName[key])
}

// hasLinkRel reports whether any <link> carries the given rel token.
func (d renderedDoc) hasLinkRel(rel string) bool {
	return d.linkHref(rel) != ""
}

// linkHref returns the first non-empty href of a <link> with the given rel
// token.
func (d renderedDoc) linkHref(rel string) string {
	for _, href := range d.linkRels[strings.ToLower(rel)] {
		if h := strings.TrimSpace(href); h != "" {
			return h
		}
	}
	return ""
}
