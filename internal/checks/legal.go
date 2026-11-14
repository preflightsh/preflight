package checks

import (
	"crypto/sha256"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

type LegalPagesCheck struct{}

func (c LegalPagesCheck) ID() string {
	return "legal_pages"
}

func (c LegalPagesCheck) Title() string {
	return "Privacy & Terms pages"
}

// Candidate paths for the deployed legal pages. The .html variants cover
// static sites that serve files as written.
var (
	legalPrivacyURLs = []string{
		"/privacy", "/privacy-policy", "/privacypolicy",
		"/legal/privacy", "/legal/privacy-policy",
		"/policies/privacy", "/policies/privacy-policy",
		"/privacy-notice", "/privacy-statement",
		"/info/privacy", "/about/privacy",
		"/privacy.html", "/privacy-policy.html",
	}
	legalTermsURLs = []string{
		"/terms", "/terms-of-service", "/termsofservice", "/tos",
		"/legal/terms", "/legal/terms-of-service", "/legal/tos",
		"/policies/terms", "/policies/terms-of-service",
		"/terms-and-conditions", "/terms-conditions",
		"/info/terms", "/about/terms", "/eula",
		"/terms.html", "/terms-of-service.html",
	}
	legalPrivacyKeywords = []string{"privacy"}
	legalTermsKeywords   = []string{"terms", "tos", "eula"}
)

func (c LegalPagesCheck) Run(ctx Context) (CheckResult, error) {
	hasPrivacy := false
	hasTerms := false
	var privacyPath, termsPath string

	// First, try over HTTP (handles CMS-generated pages), staging then
	// production, until both pages are found. Trim the trailing slash so
	// base+"/privacy" doesn't become "…//privacy", which servers
	// 301-redirect (path cleaning) and would be miscounted as the page
	// existing.
	//
	// conclusive counts probe answers that say something about the page:
	// a 403 from a WAF, a 5xx, a redirect off the site, or a catch-all
	// shell does not. When no answer was conclusive (or no host could be
	// probed at all) the source search below decides instead.
	var conclusive atomic.Int32
	var bases []string
	if ctx.Client != nil {
		bases = ctx.probeBaseURLs()
	}
	for _, baseURL := range bases {
		if hasPrivacy && hasTerms {
			break
		}
		// An SPA rewrite (/* -> /index.html 200) or catch-all route answers
		// 200 for every path. On such a host a 200 that serves the same
		// shell as a path that cannot exist proves nothing, so it falls
		// through to the source-file search below.
		shell := ctx.catchAllFor(baseURL)

		// A candidate counts when the response it finally lands on, after
		// any redirect that stays on the site, is a real page at a URL that
		// still names the page. Judging the redirect itself got both
		// directions wrong: an apex-to-www redirect read as "missing", and
		// a site that adds a trailing slash to every path before answering
		// 404 read as "found".
		accepting := func(keywords ...string) func(string, probeAnswer) bool {
			return func(reqPath string, answer probeAnswer) bool {
				if !answer.conclusive() {
					return false
				}
				if answer.status < 200 || answer.status >= 300 {
					conclusive.Add(1)
					return false
				}
				if shell.serves(answer.digest(reqPath)) {
					return false
				}
				conclusive.Add(1)
				return !answer.redirected || redirectMentions(answer.url, keywords...)
			}
		}

		if !hasPrivacy {
			if path, ok := probeFirstHit(ctx, baseURL, legalPrivacyURLs, accepting(legalPrivacyKeywords...)); ok {
				hasPrivacy = true
				privacyPath = path + " (via HTTP)"
			}
		}

		if !hasTerms {
			if path, ok := probeFirstHit(ctx, baseURL, legalTermsURLs, accepting(legalTermsKeywords...)); ok {
				hasTerms = true
				termsPath = path + " (via HTTP)"
			}
		}
	}

	// The homepage the scan already fetched usually links both pages from
	// its footer. That covers what no path list can: a policy hosted
	// elsewhere, a localized slug, a page under a prefix.
	if !hasPrivacy || !hasTerms {
		for _, page := range []string{ctx.PageHTMLStaging, ctx.PageHTMLProduction} {
			privacyLink, termsLink := legalLinksIn(page)
			if !hasPrivacy && privacyLink != "" {
				hasPrivacy = true
				privacyPath = privacyLink + " (linked from the homepage)"
			}
			if !hasTerms && termsLink != "" {
				hasTerms = true
				termsPath = termsLink + " (linked from the homepage)"
			}
		}
	}

	// If we found both on the deployed site, return early
	if hasPrivacy && hasTerms {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Found privacy at " + privacyPath + ", terms at " + termsPath,
		}, nil
	}
	// unverified is the reason the deployed site could not answer, when a
	// URL is configured but no probe was conclusive.
	unverified := ""
	if ctx.urlConfigured() {
		switch {
		case len(bases) == 0:
			unverified = "unreachable"
		case conclusive.Load() == 0:
			unverified = "blocked or no conclusive answer"
		}
		// The scan's homepage request names what actually happened.
		if reason := ctx.siteUnverified(); unverified != "" && reason != "" {
			unverified = reason
		}
	}
	// deployedMiss is true when the deployed site answered and the pages
	// were not at any probed URL. The source search still runs: a page in
	// the repo under a URL the list does not cover is not a missing page.
	deployedMiss := ctx.urlConfigured() && unverified == ""

	// Common privacy policy paths/filenames
	privacyPatterns := []string{
		"privacy", "privacy-policy", "privacy_policy", "privacypolicy",
		"legal/privacy", "legal/privacy-policy",
		"pages/privacy", "pages/privacy-policy",
		"policies/privacy", "policies/privacy-policy",
		"legalese/privacy", "legalese/privacy-policy",
		"info/privacy", "about/privacy",
		"privacy-notice", "privacy-statement",
	}

	// Common terms paths/filenames
	termsPatterns := []string{
		"terms", "terms-of-service", "terms_of_service", "tos", "termsofservice",
		"legal/terms", "legal/terms-of-service", "legal/tos",
		"pages/terms", "pages/terms-of-service",
		"policies/terms", "policies/terms-of-service",
		"legalese/terms", "legalese/terms-of-service",
		"info/terms", "about/terms",
		"terms-and-conditions", "terms-conditions", "eula",
	}

	// Extensions to check
	extensions := []string{
		"", ".html", ".htm", ".php", ".md", ".mdx",
		".tsx", ".jsx", ".js", ".ts", ".vue", ".svelte",
		".erb", ".erb.html", ".html.erb",
		".blade.php", ".twig", ".njk", ".liquid",
		".astro",
	}

	// Directories to search
	searchDirs := []string{
		"",
		"app",
		"src/app",
		"src/pages",
		"pages",
		"views",
		"resources/views",
		"templates",
		"content",
		"public",
		"static",
		"web",
		"www",
		"htdocs",
		"public_html",
	}

	// Check for privacy policy
	for _, dir := range searchDirs {
		if hasPrivacy {
			break
		}
		for _, pattern := range privacyPatterns {
			if hasPrivacy {
				break
			}
			for _, ext := range extensions {
				checkPath := filepath.Join(ctx.RootDir, dir, pattern+ext)
				if regularFileExists(checkPath) {
					hasPrivacy = true
					privacyPath = path.Join(dir, pattern+ext)
					break
				}
				// Also check with /page pattern for Next.js app router
				if dir == "app" || dir == "src/app" {
					pagePath := filepath.Join(ctx.RootDir, dir, pattern, "page"+ext)
					if regularFileExists(pagePath) {
						hasPrivacy = true
						privacyPath = path.Join(dir, pattern, "page"+ext)
						break
					}
				}
			}
		}
	}

	// Check for terms
	for _, dir := range searchDirs {
		if hasTerms {
			break
		}
		for _, pattern := range termsPatterns {
			if hasTerms {
				break
			}
			for _, ext := range extensions {
				checkPath := filepath.Join(ctx.RootDir, dir, pattern+ext)
				if regularFileExists(checkPath) {
					hasTerms = true
					termsPath = path.Join(dir, pattern+ext)
					break
				}
				// Also check with /page pattern for Next.js app router
				if dir == "app" || dir == "src/app" {
					pagePath := filepath.Join(ctx.RootDir, dir, pattern, "page"+ext)
					if regularFileExists(pagePath) {
						hasTerms = true
						termsPath = path.Join(dir, pattern, "page"+ext)
						break
					}
				}
			}
		}
	}

	// Flexible search: walk common source directories for legal page files
	// Only match actual page files, not utilities like "privacy-settings.tsx" or "usePrivacy.ts"
	if !hasPrivacy || !hasTerms {
		flexSearchDirs := []string{"app", "src", "pages", "views", "templates", "content"}
		for _, dir := range flexSearchDirs {
			if hasPrivacy && hasTerms {
				break
			}
			dirPath := filepath.Join(ctx.RootDir, dir)
			if _, err := os.Stat(dirPath); err != nil {
				continue
			}
			_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
				if err != nil || (hasPrivacy && hasTerms) {
					return nil
				}
				// Skip node_modules, vendor, etc.
				if info.IsDir() {
					name := info.Name()
					if name == "node_modules" || name == "vendor" || name == ".git" || name == "dist" || name == "build" {
						return filepath.SkipDir
					}
					return nil
				}

				if !info.Mode().IsRegular() {
					return nil
				}
				nameLower := strings.ToLower(info.Name())
				relPath := relPath(ctx.RootDir, path)
				parentDir := strings.ToLower(filepath.Base(filepath.Dir(path)))

				// For Next.js app router: page.tsx in a privacy/terms directory
				isPageFile := strings.HasPrefix(nameLower, "page.")
				if isPageFile {
					if !hasPrivacy && strings.Contains(parentDir, "privacy") {
						hasPrivacy = true
						privacyPath = relPath
					}
					if !hasTerms && (strings.Contains(parentDir, "terms") || parentDir == "tos" || parentDir == "eula") {
						hasTerms = true
						termsPath = relPath
					}
					return nil
				}

				// For other frameworks: match files that ARE the page (not containing the word)
				// e.g., "privacy.tsx", "privacy-policy.html", "terms.vue" - but NOT "privacy-settings.tsx"
				nameNoExt := strings.TrimSuffix(nameLower, filepath.Ext(nameLower))

				// Privacy page patterns (exact matches or specific suffixes)
				privacyPageNames := []string{"privacy", "privacy-policy", "privacy_policy", "privacypolicy", "privacy-notice", "privacy-statement"}
				for _, p := range privacyPageNames {
					if !hasPrivacy && nameNoExt == p {
						hasPrivacy = true
						privacyPath = relPath
						break
					}
				}

				// Terms page patterns
				termsPageNames := []string{"terms", "terms-of-service", "terms_of_service", "termsofservice", "tos", "terms-and-conditions", "terms-conditions", "eula"}
				for _, t := range termsPageNames {
					if !hasTerms && nameNoExt == t {
						hasTerms = true
						termsPath = relPath
						break
					}
				}

				return nil
			})
		}
	}

	// Check layout and common partials for links to privacy/terms
	if !hasPrivacy || !hasTerms {
		filesToCheck := []string{}

		// Add main layout if configured
		mainLayout := ""
		if ctx.Config.Checks.SEOMeta != nil {
			mainLayout = ctx.Config.Checks.SEOMeta.MainLayout
		}
		if mainLayout != "" {
			filesToCheck = append(filesToCheck, mainLayout)
		}
		// Layouts rarely hold the legal links themselves: they include a
		// footer that does. Follow those includes so a link in, say, Craft's
		// templates/globals/_footer.twig counts as the page existing.
		filesToCheck = append(filesToCheck, layoutChrome(ctx.RootDir, mainLayout)...)

		// Common footer/partial files that often contain legal links
		commonPartials := []string{
			"footer.php", "includes/footer.php", "inc/footer.php", "partials/footer.php",
			"_footer.php", "_includes/footer.php",
			"footer.html", "includes/footer.html", "_includes/footer.html",
			"components/Footer.tsx", "components/Footer.jsx", "components/footer.tsx",
			"src/components/Footer.tsx", "src/components/Footer.jsx",
			"app/components/Footer.tsx", "app/components/footer.tsx",
			"templates/_footer.twig", "templates/partials/footer.twig",
			"templates/_partials/footer.twig", "templates/footer.twig",
			"templates/partials/_footer.twig", "templates/_partials/_footer.twig",
			"templates/globals/_footer.twig", "templates/globals/footer.twig",
			"templates/_globals/_footer.twig", "templates/_includes/_footer.twig",
			"templates/_includes/footer.twig", "templates/components/footer.twig",
			"resources/views/partials/footer.blade.php",
			"resources/views/layouts/partials/footer.blade.php",
			"app/views/layouts/_footer.html.erb", "app/views/shared/_footer.html.erb",
			"_includes/footer.html", "layouts/partials/footer.html",
			"index.php", "index.html", "public/index.html",
		}
		filesToCheck = append(filesToCheck, commonPartials...)

		for _, file := range filesToCheck {
			if hasPrivacy && hasTerms {
				break
			}
			filePath := filepath.Join(ctx.RootDir, file)
			if content, err := readSourceFile(filePath); err == nil {
				contentLower := strings.ToLower(stripComments(string(content)))
				if !hasPrivacy && (strings.Contains(contentLower, "/privacy") ||
					strings.Contains(contentLower, "privacy-policy") ||
					strings.Contains(contentLower, "privacy.php") ||
					strings.Contains(contentLower, "privacy.html")) {
					hasPrivacy = true
					privacyPath = "linked in " + file
				}
				if !hasTerms && (strings.Contains(contentLower, "/terms") ||
					strings.Contains(contentLower, "terms-of-service") ||
					strings.Contains(contentLower, "terms.php") ||
					strings.Contains(contentLower, "terms.html")) {
					hasTerms = true
					termsPath = "linked in " + file
				}
			}
		}
	}

	if hasPrivacy && hasTerms {
		msg := "Found"
		if strings.HasPrefix(privacyPath, "linked in") {
			msg += " privacy link"
		} else {
			msg += " privacy at " + privacyPath
		}
		if strings.HasPrefix(termsPath, "linked in") {
			msg += ", terms link"
		} else {
			msg += ", terms at " + termsPath
		}
		switch {
		case unverified != "":
			msg += " (not verified on the deployed site: " + unverified + ")"
		case deployedMiss:
			msg += " (from source; not at the URLs probed on the deployed site)"
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  msg,
		}, nil
	}

	var missing []string
	if !hasPrivacy {
		missing = append(missing, "privacy policy")
	}
	if !hasTerms {
		missing = append(missing, "terms of service")
	}

	// The deployed site could not be checked and the source doesn't show
	// the pages either: they may well be CMS pages, so this is not a miss.
	if unverified != "" {
		return CheckResult{
			ID:           c.ID(),
			Title:        c.Title(),
			Severity:     SeverityWarn,
			Passed:       false,
			Inconclusive: true,
			Message:      "Could not verify " + strings.Join(missing, ", ") + " on the deployed site (" + unverified + "), and not found in source",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Missing: " + strings.Join(missing, ", "),
		Suggestions: []string{
			"Add a privacy policy page (e.g., /privacy)",
			"Add terms of service page (e.g., /terms)",
		},
	}, nil
}

// templateIncludeRE matches the quoted template name in the include-style
// tags of the layout languages Preflight parses: Twig and Nunjucks
// ({% include %}, {% embed %}, {{ include() }}), Blade (@include), Liquid
// ({% render %}, {% section %}) and ERB (<%= render %>). Word boundaries
// keep JavaScript's includes() from matching.
var templateIncludeRE = regexp.MustCompile(`(?i)\b(?:include|includeif|includewhen|embed|render|section|component)\b(?:\s*\(\s*|\s+)['"]([^'"\n]+)['"]`)

// conventionalLayouts are the layout files to walk when preflight.yml
// doesn't name one, covering the stacks whose include syntax we parse.
var conventionalLayouts = []string{
	"templates/_layout.twig",
	"templates/_layout/index.twig",
	"resources/views/layouts/app.blade.php",
	"app/views/layouts/application.html.erb",
	"_layouts/default.html",
	"layouts/default.vue",
}

// layoutChrome returns the site-wide template files reachable from the main
// layout through include tags, relative to rootDir. Depth and file count are
// capped: the goal is the layout's chrome (header, footer, nav), not a walk
// of the whole template tree.
func layoutChrome(rootDir, mainLayout string) []string {
	const (
		maxDepth = 3
		maxFiles = 40
		// Cap per-file matches so a layout with a wall of inline JS can't
		// turn every include-shaped string into a directory probe.
		maxIncludes = 60
	)

	seen := map[string]bool{}
	var queue []string
	for _, layout := range append([]string{mainLayout}, conventionalLayouts...) {
		if layout == "" {
			continue
		}
		abs := filepath.Join(rootDir, filepath.FromSlash(layout))
		if seen[abs] {
			continue
		}
		if !regularFileExists(abs) {
			continue
		}
		seen[abs] = true
		queue = append(queue, abs)
	}

	var found []string
	for depth := 0; depth < maxDepth && len(queue) > 0; depth++ {
		var next []string
		for _, file := range queue {
			content, err := readSourceFile(file)
			if err != nil {
				continue
			}
			fromDir := relPath(rootDir, filepath.Dir(file))
			for _, match := range templateIncludeRE.FindAllStringSubmatch(string(content), maxIncludes) {
				resolved := resolveTemplate(rootDir, fromDir, match[1])
				if resolved == "" || seen[resolved] {
					continue
				}
				seen[resolved] = true
				found = append(found, relPath(rootDir, resolved))
				next = append(next, resolved)
				if len(found) >= maxFiles {
					return found
				}
			}
		}
		queue = next
	}
	return found
}

// resolveTemplate maps an include target as written in a template to a file
// on disk, covering the directory roots and extensions of the template
// languages we parse. Blade's dotted names and the leading underscore Craft
// and Rails give partials are both tried. Returns "" when nothing matches,
// including for dynamic targets we can't resolve statically.
func resolveTemplate(rootDir, fromDir, target string) string {
	target = strings.TrimSpace(strings.Trim(strings.TrimSpace(target), "/"))
	if target == "" || strings.ContainsAny(target, "{}$~*") || strings.Contains(target, "..") {
		return ""
	}
	target = strings.TrimPrefix(target, "./")

	names := []string{target}
	// Blade addresses templates as partials.footer rather than partials/footer.
	if !strings.Contains(target, "/") && strings.Contains(target, ".") {
		names = append(names, strings.ReplaceAll(target, ".", "/"))
	}
	for _, name := range names[:len(names):len(names)] {
		dir, base := path.Split(name)
		if !strings.HasPrefix(base, "_") {
			names = append(names, dir+"_"+base)
		}
	}

	exts := []string{"", ".twig", ".html.twig", ".njk", ".liquid", ".blade.php", ".php", ".html", ".html.erb", ".erb", ".vue"}
	dirs := []string{fromDir, "templates", "resources/views", "views", "app/views", "src", "."}

	for _, dir := range dirs {
		for _, name := range names {
			for _, ext := range exts {
				candidate := filepath.Join(rootDir, dir, filepath.FromSlash(name)+ext)
				if regularFileExists(candidate) {
					return candidate
				}
			}
		}
	}
	return ""
}

// isAuthRedirect reports whether a redirect Location points to a login or
// authentication page. Apps that gate everything behind auth redirect unknown
// paths to /login, which must not be miscounted as the requested page existing.
func isAuthRedirect(location string) bool {
	if location == "" {
		return false
	}
	p := strings.ToLower(location)
	if u, err := url.Parse(location); err == nil && u.Path != "" {
		p = strings.ToLower(u.Path)
	}
	for _, marker := range []string{"login", "signin", "sign-in", "sign_in", "/auth", "authenticate", "session/new", "/account"} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

// redirectMentions reports whether a redirect Location's path contains any of the
// given keywords, so a 3xx is only counted as the legal page when it actually
// lands on a matching URL (e.g. /privacy -> /privacy-policy) rather than a
// path-clean or homepage bounce.
func redirectMentions(location string, keywords ...string) bool {
	if location == "" {
		return false
	}
	p := strings.ToLower(location)
	if u, err := url.Parse(location); err == nil && u.Path != "" {
		p = strings.ToLower(u.Path)
	}
	for _, kw := range keywords {
		if strings.Contains(p, kw) {
			return true
		}
	}
	return false
}

// legalAnchorRE matches an anchor with its href and its text.
var legalAnchorRE = regexp.MustCompile(`(?is)<a\b[^>]*?\bhref\s*=\s*["']?([^"'\s>]+)[^>]*>(.*?)</a>`)

var legalTagRE = regexp.MustCompile(`(?s)<[^>]*>`)

// legalLinksIn returns the hrefs of the privacy and terms links on a
// rendered page, "" for each that is not linked. A link counts when its
// href or its visible text names the page. Comments are removed first, so
// a commented-out footer link is not evidence.
func legalLinksIn(page string) (privacy, terms string) {
	if strings.TrimSpace(page) == "" {
		return "", ""
	}
	page = reHTMLComment.ReplaceAllString(page, "")
	for _, m := range legalAnchorRE.FindAllStringSubmatch(page, 2000) {
		href := strings.TrimSpace(m[1])
		lowerHref := strings.ToLower(href)
		if href == "" || strings.HasPrefix(lowerHref, "#") || strings.HasPrefix(lowerHref, "javascript:") || strings.HasPrefix(lowerHref, "mailto:") {
			continue
		}
		text := strings.ToLower(strings.Join(strings.Fields(legalTagRE.ReplaceAllString(m[2], " ")), " "))
		if privacy == "" && (redirectMentions(href, legalPrivacyKeywords...) || strings.Contains(text, "privacy")) {
			privacy = href
		}
		if terms == "" && (redirectMentions(href, "terms", "/tos", "eula") ||
			strings.Contains(text, "terms of") || strings.Contains(text, "terms and") || strings.Contains(text, "terms &") || text == "terms") {
			terms = href
		}
		if privacy != "" && terms != "" {
			break
		}
	}
	return privacy, terms
}

// pageDigest is the sha256 of the first MiB of a response body after
// removing what a server stamps fresh on every request (CSP nonces, CSRF
// tokens, hidden form values) and the request path itself, which soft-404
// pages often echo ("/privacy was not found"). Hashing the raw body made
// every path of a nonce-stamping catch-all look unique, so every legal page
// read as present.
func pageDigest(r io.Reader, reqPath string) []byte {
	body, _ := io.ReadAll(io.LimitReader(r, 1<<20))
	s := string(body)
	if reqPath != "" {
		s = strings.ReplaceAll(s, reqPath, "")
	}
	s = perRequestTagRe.ReplaceAllString(s, "")
	s = perRequestValueRe.ReplaceAllString(s, "")
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

var (
	// Whole tags that only carry a per-request token: hidden inputs and
	// csrf meta tags (<meta name="csrf-token" content="...">).
	perRequestTagRe = regexp.MustCompile(`(?i)<input\b[^>]*\btype\s*=\s*["']?hidden\b[^>]*>|<meta\b[^>]*(?:csrf|xsrf|_token)[^>]*>`)
	// nonce="...", data-csrf='...', "csrfToken":"...", xsrf_token = '...'.
	perRequestValueRe = regexp.MustCompile(`(?i)[\w-]*(?:nonce|csrf|xsrf|authenticity_token)[\w-]*["']?\s*[:=]\s*(?:"[^"]*"|'[^']*')`)
)

// legalProbeBatch is how many candidate paths probeFirstHit requests at once.
const legalProbeBatch = 5

// probeFirstHit requests candidate paths in batches, concurrently within a
// batch, and returns the first path in list order whose final answer accept
// approves. Batching keeps the common case (an early candidate exists) to
// one round of requests, while a miss no longer costs one timeout per
// candidate in series: on a slow host, 14 sequential probes at the scan
// timeout was over two minutes for one check.
//
// accept gets the request path and the answer the host finally gave after
// any redirect that stayed on the site, so a catch-all host's shell page
// can be told apart from a real page.
func probeFirstHit(ctx Context, baseURL string, paths []string, accept func(reqPath string, answer probeAnswer) bool) (string, bool) {
	for start := 0; start < len(paths); start += legalProbeBatch {
		end := min(start+legalProbeBatch, len(paths))
		hits := make([]bool, end-start)
		var wg sync.WaitGroup
		for i, path := range paths[start:end] {
			wg.Add(1)
			go func(i int, path string) {
				defer wg.Done()
				hits[i] = accept(path, fetchOnSite(ctx, baseURL+path))
			}(i, path)
		}
		wg.Wait()
		for i, hit := range hits {
			if hit {
				return paths[start+i], true
			}
		}
		if ctx.reqContext().Err() != nil {
			return "", false
		}
	}
	return "", false
}

func regularFileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}
