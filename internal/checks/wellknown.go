package checks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/preflightsh/preflight/internal/netutil"
)

// This file holds what robots.txt, sitemap.xml, llms.txt, ads.txt, and
// humans.txt share: finding the file in the project's web roots, asking the
// deployed site for it, checking that what came back is that kind of file,
// and combining the two answers into one result.

// wellKnownFile describes one of those files.
type wellKnownFile struct {
	// name is what the result calls the file: "robots.txt".
	name string
	// staticNames are the paths under a web root where the file can sit.
	staticNames []string
	// urlPaths are the paths to ask the deployed site for, in order.
	urlPaths []string
	// parents also asks production's parent domain(s), for a file that
	// legitimately lives on the organization's main site.
	parents bool
	// valid reports whether a body is this kind of file. A 200 is not
	// enough: soft 404s, JSON error bodies, and SPA shells all answer 200.
	valid func(body []byte) bool
	// weakShape marks a format too free-form for valid to rule out a
	// catch-all answer, so a hit is also compared with what the host
	// serves for a path that cannot exist.
	weakShape bool
}

var (
	robotsTxtFile = wellKnownFile{
		name:        "robots.txt",
		staticNames: []string{"robots.txt"},
		urlPaths:    []string{"/robots.txt"},
		valid:       validRobotsTxt,
	}
	sitemapFile = wellKnownFile{
		name:        "sitemap.xml",
		staticNames: []string{"sitemap.xml"},
		// sitemap-index.xml is what Astro's integration writes and
		// sitemap_index.xml is what Yoast serves.
		urlPaths: []string{"/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml", "/sitemap.xml.gz"},
		parents:  true,
		valid:    validSitemap,
	}
	llmsTxtFile = wellKnownFile{
		name:        "llms.txt",
		staticNames: []string{"llms.txt", ".well-known/llms.txt"},
		urlPaths:    []string{"/llms.txt", "/.well-known/llms.txt"},
		parents:     true,
		valid:       validLLMsTxt,
		weakShape:   true,
	}
	adsTxtFile = wellKnownFile{
		name:        "ads.txt",
		staticNames: []string{"ads.txt"},
		urlPaths:    []string{"/ads.txt"},
		valid:       validAdsTxt,
	}
	humansTxtFile = wellKnownFile{
		name:        "humans.txt",
		staticNames: []string{"humans.txt"},
		urlPaths:    []string{"/humans.txt"},
		valid:       validPlainText,
		weakShape:   true,
	}
)

// wellKnownWebRoots are the directories a static file is served from across
// frameworks, ending with the project root.
var wellKnownWebRoots = []string{
	"public", // Laravel, Rails, many Node.js
	"static", // Hugo, some SSGs
	"web",    // Craft CMS, Symfony
	"www",    // Some PHP apps
	"dist",   // Built static sites
	"build",  // Build outputs
	"_site",  // Jekyll
	"out",    // Next.js static export
	"",       // Root directory
}

// findStatic looks for the file in the web roots and in a monorepo's app
// public directories. found is the project-relative path of the first one
// whose contents are that kind of file. rejected is the first one that
// exists with something else in it (an HTML page saved as sitemap.xml).
func (f wellKnownFile) findStatic(rootDir string) (found, rejected string) {
	consider := func(full string) bool {
		content, err := readSourceFile(full)
		if err != nil || len(bytes.TrimSpace(content)) == 0 {
			return false
		}
		rel := relPath(rootDir, full)
		if f.valid(content) {
			found = rel
			return true
		}
		if rejected == "" {
			rejected = rel
		}
		return false
	}
	for _, root := range wellKnownWebRoots {
		for _, name := range f.staticNames {
			if consider(filepath.Join(rootDir, root, filepath.FromSlash(name))) {
				return found, rejected
			}
		}
	}
	// findMonorepoPublicFiles already lists the .well-known variant.
	for _, full := range findMonorepoPublicFiles(rootDir, filepath.Base(f.staticNames[0])) {
		if consider(full) {
			return found, rejected
		}
	}
	return "", rejected
}

// liveState is what the deployed site said about a file.
type liveState int

const (
	// liveUnknown: no URL is configured, or no configured host gave an
	// answer that says anything (down, blocked by a WAF, a 5xx).
	liveUnknown liveState = iota
	// liveServed: a host served the file.
	liveServed
	// liveNotServed: a configured host answered, and not with the file.
	liveNotServed
)

// liveFile is the outcome of asking the deployed site for a file.
type liveFile struct {
	state liveState
	// servedAt is the URL that served it (liveServed).
	servedAt string
	// missAt names the first configured URL that answered without it
	// (liveNotServed): "https://example.com/robots.txt (HTTP 404)".
	missAt string
	// reason says why nothing could be verified (liveUnknown with a URL
	// configured): "prod: blocked (HTTP 403)".
	reason string
	// production is the body production served, and productionURL where,
	// when production is configured and served the file.
	production    []byte
	productionURL string
}

// fileAnswer is one request's verdict.
type fileAnswer struct {
	state liveState
	url   string
	body  []byte
	// note describes a miss or the reason the answer was unusable.
	note string
}

// fetchFile asks one base URL for one path. Redirects are followed, off
// the site included: a sitemap that redirects to a CDN is still the
// sitemap.
func (f wellKnownFile) fetchFile(ctx Context, baseURL, urlPath string) fileAnswer {
	base := strings.TrimSuffix(baseURL, "/")
	if ctx.Client == nil || base == "" || ctx.HostUnreachable(base) {
		return fileAnswer{note: "unreachable"}
	}
	resp, actualURL, err := tryURL(ctx.reqContext(), ctx.Client, base+urlPath)
	if err != nil {
		return fileAnswer{note: "unreachable"}
	}
	defer resp.Body.Close()
	if blockedStatus(resp.StatusCode) || resp.StatusCode >= 500 {
		return fileAnswer{url: actualURL, note: fetchFailure(resp.StatusCode)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fileAnswer{state: liveNotServed, url: actualURL, note: fmt.Sprintf("%s (HTTP %d)", actualURL, resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, netutil.MaxResponseBody))
	if err != nil {
		return fileAnswer{url: actualURL, note: "unreachable"}
	}
	wrongShape := fileAnswer{state: liveNotServed, url: actualURL, note: actualURL + " (answered, but not with a " + f.name + " file)"}
	if len(bytes.TrimSpace(body)) == 0 || looksLikeHTML(resp.Header.Get("Content-Type"), body) || !f.valid(body) {
		return wrongShape
	}
	if f.weakShape && ctx.catchAllFor(base).servesFile(pageDigest(bytes.NewReader(body), urlPath)) {
		return wrongShape
	}
	return fileAnswer{state: liveServed, url: actualURL, body: body}
}

// probe asks every configured environment for the file, then production's
// parent domains when the file may live there.
func (f wellKnownFile) probe(ctx Context) liveFile {
	var live liveFile
	if ctx.Client == nil || !ctx.urlConfigured() {
		return live
	}
	configured := ctx.probeBaseURLs()
	prod := strings.TrimSuffix(ctx.Config.URLs.Production, "/")

	var reasons []string
	for _, base := range configured {
		answer := f.firstAnswer(ctx, base)
		switch answer.state {
		case liveServed:
			if live.servedAt == "" {
				live.servedAt = answer.url
			}
			if base == prod {
				live.production, live.productionURL = answer.body, answer.url
			}
		case liveNotServed:
			if live.missAt == "" {
				live.missAt = answer.note
			}
		default:
			reasons = append(reasons, ctx.envName(base)+": "+answer.note)
		}
	}
	if live.servedAt == "" && f.parents {
		for _, base := range parentBaseURLs(ctx.Config.URLs.Production) {
			// A miss on a parent domain is not a verdict: the file only
			// has to be on the configured host.
			if answer := f.firstAnswer(ctx, base); answer.state == liveServed {
				live.servedAt = answer.url
				break
			}
		}
	}

	switch {
	case live.servedAt != "":
		live.state = liveServed
	case live.missAt != "":
		live.state = liveNotServed
	default:
		// Hosts the homepage request already found down are not in
		// configured at all, so name them from that request.
		if unverified := ctx.siteUnverified(); len(reasons) == 0 && unverified != "" {
			reasons = append(reasons, unverified)
		}
		if len(reasons) == 0 {
			reasons = append(reasons, "site unreachable")
		}
		live.reason = strings.Join(reasons, "; ")
	}
	return live
}

// firstAnswer tries the file's URL paths on one base and returns the first
// that served it, or else the most telling of the others: a conclusive miss
// over an answer that could not be used.
func (f wellKnownFile) firstAnswer(ctx Context, baseURL string) fileAnswer {
	var miss, unusable fileAnswer
	for _, urlPath := range f.urlPaths {
		answer := f.fetchFile(ctx, baseURL, urlPath)
		switch {
		case answer.state == liveServed:
			return answer
		case answer.state == liveNotServed && miss.note == "":
			miss = answer
		case answer.state == liveUnknown && unusable.note == "":
			unusable = answer
		}
		if ctx.reqContext().Err() != nil {
			break
		}
	}
	if miss.note != "" {
		return miss
	}
	return unusable
}

// probeFileAtBase reports whether baseURL serves the well-known file at
// path, and from which URL.
func probeFileAtBase(ctx Context, baseURL, path string) (string, bool) {
	answer := wellKnownForPath(path).fetchFile(ctx, baseURL, path)
	return answer.url, answer.state == liveServed
}

// wellKnownForPath picks the file description a URL path belongs to.
func wellKnownForPath(path string) wellKnownFile {
	for _, f := range []wellKnownFile{robotsTxtFile, sitemapFile, llmsTxtFile, adsTxtFile, humansTxtFile} {
		for _, p := range f.urlPaths {
			if p == path {
				return f
			}
		}
	}
	return wellKnownFile{name: strings.TrimPrefix(path, "/"), urlPaths: []string{path}, valid: validPlainText, weakShape: true}
}

// wellKnownResult combines the project's files, the deployed site, and the
// framework-specific source detection into one result.
//
// A static file in a web root has a known URL, so when a configured host
// answered and did not serve it, the file is not live and that is the
// finding. Source that generates the file (a route, a plugin, a CMS) has no
// such certainty about the URL, so it passes on its own, as it always has.
// And when a URL is configured but nothing could be verified, the result is
// inconclusive rather than "not found".
func wellKnownResult(ctx Context, c Check, f wellKnownFile, fromSource func(Context) CheckResult) CheckResult {
	res, _ := wellKnownResultLive(ctx, c, f, fromSource)
	return res
}

// wellKnownResultLive is wellKnownResult for a caller that also wants what
// the deployed site served.
func wellKnownResultLive(ctx Context, c Check, f wellKnownFile, fromSource func(Context) CheckResult) (CheckResult, liveFile) {
	static, rejected := f.findStatic(ctx.RootDir)
	live := f.probe(ctx)
	return f.combine(ctx, c, static, rejected, live, fromSource), live
}

func (f wellKnownFile) combine(ctx Context, c Check, static, rejected string, live liveFile, fromSource func(Context) CheckResult) CheckResult {

	pass := func(message string) CheckResult {
		return CheckResult{ID: c.ID(), Title: c.Title(), Severity: SeverityInfo, Passed: true, Message: message}
	}

	if static != "" {
		if live.state == liveNotServed {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityWarn,
				Passed:   false,
				Message:  f.name + " found at " + static + " but not served at " + live.missAt,
				Suggestions: []string{
					"Deploy the file, or check that the web server serves that directory at the site root",
				},
			}
		}
		return pass(f.name + " found at " + static)
	}

	source := fromSource(ctx)
	switch {
	case source.Passed:
		return source
	case live.state == liveServed:
		return pass(f.name + " served at " + live.servedAt)
	case live.state == liveUnknown && live.reason != "":
		return inconclusiveResult(c, f.name, live.reason+", and not found in source")
	}
	if rejected != "" {
		source.Message = f.name + " not found (" + rejected + " exists but is not a " + f.name + " file)"
	}
	return source
}

func (c RobotsTxtCheck) Run(ctx Context) (CheckResult, error) {
	res, live := wellKnownResultLive(ctx, c, robotsTxtFile, c.fromSource)
	return productionIndexing(ctx, res, live), nil
}

func (c SitemapCheck) Run(ctx Context) (CheckResult, error) {
	return wellKnownResult(ctx, c, sitemapFile, c.fromSource), nil
}

func (c LLMsTxtCheck) Run(ctx Context) (CheckResult, error) {
	return wellKnownResult(ctx, c, llmsTxtFile, c.fromSource), nil
}

// trimBOM drops a leading UTF-8 byte order mark.
func trimBOM(body []byte) string {
	return strings.TrimPrefix(string(body), utf8BOM)
}

// looksLikeErrorBody reports whether a short body is an error message
// served with a 200: "Not Found", "404", "Error: no such file".
func looksLikeErrorBody(text string) bool {
	t := strings.ToLower(strings.TrimSpace(text))
	if len(t) > 200 {
		return false
	}
	return strings.Contains(t, "not found") || strings.HasPrefix(t, "404") || strings.HasPrefix(t, "error") ||
		strings.Contains(t, "forbidden") || strings.Contains(t, "access denied")
}

var robotsDirectiveRE = regexp.MustCompile(`(?im)^[ \t]*(user-agent|disallow|allow|sitemap|crawl-delay|host|clean-param)[ \t]*:`)

// validRobotsTxt accepts a file with at least one robots directive, or one
// that is only comments (an intentionally empty policy).
func validRobotsTxt(body []byte) bool {
	text := trimBOM(body)
	if robotsDirectiveRE.MatchString(text) {
		return true
	}
	return commentsOnly(text)
}

// commentsOnly reports whether every non-blank line starts with "#" and
// there is at least one.
func commentsOnly(text string) bool {
	seen := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			return false
		}
		seen = true
	}
	return seen
}

// validSitemap accepts sitemap XML (a urlset or a sitemap index), a feed
// used as a sitemap, or a gzip stream for the .gz variants.
func validSitemap(body []byte) bool {
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		return true
	}
	head := body
	if len(head) > 8192 {
		head = head[:8192]
	}
	lower := strings.ToLower(trimBOM(head))
	for _, root := range []string{"<urlset", "<sitemapindex", "<rss", "<feed"} {
		if strings.Contains(lower, root) {
			return true
		}
	}
	return false
}

// validPlainText accepts text that is not a page, not JSON, and not an
// error message.
func validPlainText(body []byte) bool {
	text := strings.TrimSpace(trimBOM(body))
	if text == "" || strings.HasPrefix(text, "<") || json.Valid([]byte(text)) {
		return false
	}
	return !looksLikeErrorBody(text)
}

// validLLMsTxt accepts markdown-ish text: llms.txt is a markdown file that
// opens with a heading and lists links.
func validLLMsTxt(body []byte) bool {
	if !validPlainText(body) {
		return false
	}
	text := trimBOM(body)
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			return true
		}
	}
	return strings.Contains(text, "](") || len(strings.TrimSpace(text)) >= 80
}

// validAdsTxt accepts a file with at least one seller record (domain,
// account ID, relationship) or variable (contact=, subdomain=), or one that
// is only comments.
func validAdsTxt(body []byte) bool {
	if !validPlainText(body) {
		return false
	}
	text := trimBOM(body)
	for _, line := range strings.Split(text, "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(strings.Split(line, ",")) >= 3 {
			return true
		}
		if key, value, ok := strings.Cut(line, "="); ok && strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" && !strings.ContainsAny(key, " \t") {
			return true
		}
	}
	return commentsOnly(text)
}
