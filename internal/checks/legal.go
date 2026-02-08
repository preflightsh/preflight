package checks

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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

	if baseURL != "" {
		client := &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}

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
			resp, err := client.Get(baseURL + path)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 400 {
					hasPrivacy = true
					privacyPath = path + " (via HTTP)"
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
			resp, err := client.Get(baseURL + path)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 400 {
					hasTerms = true
					termsPath = path + " (via HTTP)"
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
			filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
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
		if ctx.Config.Checks.SEOMeta != nil && ctx.Config.Checks.SEOMeta.MainLayout != "" {
			filesToCheck = append(filesToCheck, ctx.Config.Checks.SEOMeta.MainLayout)
		}

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
