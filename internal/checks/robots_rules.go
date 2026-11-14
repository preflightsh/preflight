package checks

import (
	"strings"
)

// productionIndexing adds what the robots.txt check has to say about
// whether production can be indexed at all. A robots.txt that exists and
// tells every crawler to stay out, or a homepage marked noindex, is the
// classic launch mistake: the staging settings shipped. Only production is
// looked at. Staging is supposed to keep crawlers out.
func productionIndexing(ctx Context, res CheckResult, live liveFile) CheckResult {
	if ctx.Config == nil || ctx.Config.URLs.Production == "" || IsLocalURL(ctx.Config.URLs.Production) {
		return res
	}
	var problems, fixes []string
	if len(live.production) > 0 && robotsBlocksEverything(live.production) {
		problems = append(problems, "robots.txt at "+live.productionURL+" tells all crawlers to stay out (Disallow: / for User-agent: *)")
		fixes = append(fixes, "Remove the Disallow: / rule from production's robots.txt")
	}
	if how := productionNoindex(ctx); how != "" {
		problems = append(problems, "the production homepage is marked noindex ("+how+")")
		fixes = append(fixes, "Remove noindex from production so search engines can index the site")
	}
	if len(problems) == 0 {
		return res
	}
	if res.Passed {
		res.Passed = false
		res.Severity = SeverityWarn
		res.Message = upperFirst(strings.Join(problems, "; "))
		res.Suggestions = fixes
		return res
	}
	res.Message += "; " + strings.Join(problems, "; ")
	res.Suggestions = append(res.Suggestions, fixes...)
	return res
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// robotsBlocksEverything reports whether a robots.txt has a group for every
// crawler (User-agent: *) that disallows the whole site and allows nothing
// back.
func robotsBlocksEverything(body []byte) bool {
	type group struct {
		agents             []string
		disallowAll, allow bool
	}
	var groups []*group
	var current *group
	inRules := false
	for _, line := range strings.Split(trimBOM(body), "\n") {
		line, _, _ = strings.Cut(line, "#")
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "user-agent":
			// Consecutive User-agent lines share one group; a User-agent
			// line after rules starts the next.
			if current == nil || inRules {
				current = &group{}
				groups = append(groups, current)
				inRules = false
			}
			current.agents = append(current.agents, strings.ToLower(value))
		case "disallow":
			inRules = true
			if current != nil && value == "/" {
				current.disallowAll = true
			}
		case "allow":
			inRules = true
			if current != nil && value != "" {
				current.allow = true
			}
		}
	}
	for _, g := range groups {
		for _, agent := range g.agents {
			if agent == "*" && g.disallowAll && !g.allow {
				return true
			}
		}
	}
	return false
}

// productionNoindex reports how the production homepage tells search
// engines not to index it ("meta robots" or "X-Robots-Tag header"), or ""
// when it does not.
func productionNoindex(ctx Context) string {
	for _, value := range ctx.PageFetchProduction.Headers.Values("X-Robots-Tag") {
		if robotsValueNoindex(value) {
			return "X-Robots-Tag header"
		}
	}
	if strings.TrimSpace(ctx.PageHTMLProduction) == "" {
		return ""
	}
	doc := parseRenderedHTML(ctx.PageHTMLProduction)
	for _, name := range []string{"robots", "googlebot"} {
		if robotsValueNoindex(doc.metaName[name]) {
			return "meta " + name
		}
	}
	return ""
}

// robotsValueNoindex reports whether a robots meta or header value carries
// noindex, or "none", which means noindex and nofollow together.
func robotsValueNoindex(value string) bool {
	for _, part := range strings.Split(strings.ToLower(value), ",") {
		part = strings.TrimSpace(part)
		// "googlebot: noindex" scopes a directive to one crawler, while
		// "max-image-preview:none" is a setting whose value happens to be
		// "none". Only the first form is unwrapped.
		if name, rest, ok := strings.Cut(part, ":"); ok {
			name = strings.TrimSpace(name)
			if strings.HasPrefix(name, "max-") || name == "unavailable_after" {
				continue
			}
			part = strings.TrimSpace(rest)
		}
		if part == "noindex" || part == "none" {
			return true
		}
	}
	return false
}
