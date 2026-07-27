package checks

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// getWithContext is a context-aware GET that, unlike doGet, does not set
// a User-Agent. Used by legal-page probing where we historically called
// http.Client.Get directly so as not to identify Preflight to the
// scanned host.
func getWithContext(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

type LegalPagesCheck struct{}

func (c LegalPagesCheck) ID() string {
	return "legal_pages"
}

func (c LegalPagesCheck) Title() string {
	return "Privacy & Terms pages"
}

func (c LegalPagesCheck) Run(ctx Context) (CheckResult, error) {
	hasPrivacy := false
	hasTerms := false
	var privacyPath, termsPath string

	// First, try to check via HTTP if URLs are configured (handles CMS-generated pages)
	baseURL := ctx.Config.URLs.Staging
	if baseURL == "" {
		baseURL = ctx.Config.URLs.Production
	}
	// Trim the trailing slash so baseURL+"/privacy" doesn't become "…//privacy",
	// which servers 301-redirect (path cleaning) and would be miscounted as the
	// page existing.
	baseURL = strings.TrimSuffix(baseURL, "/")

	if baseURL != "" {
		// Reuse ctx.Client (which already handles the local-vs-safe choice
		// based on the configured URLs) but override CheckRedirect so 3xx
		// is treated as "page exists" rather than followed. Copy the
		// client by value so we don't mutate the shared one.
		clientCopy := *ctx.Client
		clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		client := &clientCopy

		privacyURLs := []string{
			"/privacy", "/privacy-policy", "/privacypolicy",
			"/legal/privacy", "/legal/privacy-policy",
			"/policies/privacy", "/policies/privacy-policy",
			"/privacy-notice", "/privacy-statement",
			"/info/privacy", "/about/privacy",
		}
		for _, path := range privacyURLs {
			if hasPrivacy {
				break
			}
			resp, err := getWithContext(ctx.reqContext(), client, baseURL+path)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					hasPrivacy = true
					privacyPath = path + " (via HTTP)"
				} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
					// Count a redirect as "found" only if it stays on the same
					// domain, isn't a login/auth bounce, and actually lands on a
					// privacy-looking URL (not a path-clean or homepage bounce).
					loc := resp.Header.Get("Location")
					if isSameDomainRedirect(baseURL, loc) && !isAuthRedirect(loc) && redirectMentions(loc, "privacy") {
						hasPrivacy = true
						privacyPath = path + " (via HTTP)"
					}
				}
			}
		}

		termsURLs := []string{
			"/terms", "/terms-of-service", "/termsofservice", "/tos",
			"/legal/terms", "/legal/terms-of-service", "/legal/tos",
			"/policies/terms", "/policies/terms-of-service",
			"/terms-and-conditions", "/terms-conditions",
			"/info/terms", "/about/terms", "/eula",
		}
		for _, path := range termsURLs {
			if hasTerms {
				break
			}
			resp, err := getWithContext(ctx.reqContext(), client, baseURL+path)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					hasTerms = true
					termsPath = path + " (via HTTP)"
				} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
					loc := resp.Header.Get("Location")
					if isSameDomainRedirect(baseURL, loc) && !isAuthRedirect(loc) && redirectMentions(loc, "terms", "tos", "eula") {
						hasTerms = true
						termsPath = path + " (via HTTP)"
					}
				}
			}
		}

		// If we found both via HTTP, return early
		if hasPrivacy && hasTerms {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "Found privacy at " + privacyPath + ", terms at " + termsPath,
			}, nil
		}
	}

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
				if _, err := os.Stat(checkPath); err == nil {
					hasPrivacy = true
					privacyPath = filepath.Join(dir, pattern+ext)
					break
				}
				// Also check with /page pattern for Next.js app router
				if dir == "app" || dir == "src/app" {
					pagePath := filepath.Join(ctx.RootDir, dir, pattern, "page"+ext)
					if _, err := os.Stat(pagePath); err == nil {
						hasPrivacy = true
						privacyPath = filepath.Join(dir, pattern, "page"+ext)
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
				if _, err := os.Stat(checkPath); err == nil {
					hasTerms = true
					termsPath = filepath.Join(dir, pattern+ext)
					break
				}
				// Also check with /page pattern for Next.js app router
				if dir == "app" || dir == "src/app" {
					pagePath := filepath.Join(ctx.RootDir, dir, pattern, "page"+ext)
					if _, err := os.Stat(pagePath); err == nil {
						hasTerms = true
						termsPath = filepath.Join(dir, pattern, "page"+ext)
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
			if content, err := os.ReadFile(filePath); err == nil {
				contentLower := strings.ToLower(string(content))
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
		if info, err := os.Stat(abs); err != nil || info.IsDir() {
			continue
		}
		seen[abs] = true
		queue = append(queue, abs)
	}

	var found []string
	for depth := 0; depth < maxDepth && len(queue) > 0; depth++ {
		var next []string
		for _, file := range queue {
			content, err := os.ReadFile(file)
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
				if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
					return candidate
				}
			}
		}
	}
	return ""
}

// isSameDomainRedirect checks if a redirect Location stays on the same domain
func isSameDomainRedirect(baseURL, location string) bool {
	if location == "" {
		return false
	}
	// Relative redirects are same-domain
	if strings.HasPrefix(location, "/") {
		return true
	}
	baseU, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	locU, err := url.Parse(location)
	if err != nil {
		return false
	}
	return strings.EqualFold(baseU.Hostname(), locU.Hostname())
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
