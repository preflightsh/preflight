package checks

import (
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
	linkRels     map[string][]string // rel -> hrefs, rel tokens lowercased
	title        string              // trimmed text of the first non-empty <title>
	htmlLang     string              // lang attribute on <html>
	hasJSONLD    bool                // <script type="application/ld+json"> present
}

// parseRenderedHTML tokenizes doc and collects the head-level signals the
// checks care about. The tokenizer is tolerant of broken markup and never
// fails; on garbage input the result is simply empty.
func parseRenderedHTML(doc string) renderedDoc {
	d := renderedDoc{
		metaName:     map[string]string{},
		metaProperty: map[string]string{},
		linkRels:     map[string][]string{},
	}

	z := html.NewTokenizer(strings.NewReader(doc))
	inTitle := false
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return d // io.EOF or unrecoverable garbage; keep what we have
		case html.TextToken:
			if inTitle && d.title == "" {
				d.title = strings.TrimSpace(string(z.Text()))
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
					if _, seen := d.metaName[n]; !seen {
						d.metaName[n] = attrs["content"]
					}
				}
				if p := strings.ToLower(strings.TrimSpace(attrs["property"])); p != "" {
					if _, seen := d.metaProperty[p]; !seen {
						d.metaProperty[p] = attrs["content"]
					}
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
			case "title":
				if tt == html.StartTagToken {
					inTitle = true
				}
			case "script":
				if strings.Contains(strings.ToLower(attrs["type"]), "application/ld+json") {
					d.hasJSONLD = true
				}
			}
		case html.EndTagToken:
			if name, _ := z.TagName(); string(name) == "title" {
				inTitle = false
			}
		}
	}
}

// hasMeta reports whether the page has a meta tag for the canonical OG or
// Twitter name. OG tags conventionally use property= and Twitter tags name=,
// but plugins emit either, so both maps are consulted.
func (d renderedDoc) hasMeta(name string) bool {
	key := strings.ToLower(name)
	if _, ok := d.metaProperty[key]; ok {
		return true
	}
	_, ok := d.metaName[key]
	return ok
}

// hasLinkRel reports whether any <link> carries the given rel token.
func (d renderedDoc) hasLinkRel(rel string) bool {
	return len(d.linkRels[strings.ToLower(rel)]) > 0
}
