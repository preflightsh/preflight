package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type SEOMetadataCheck struct{}

func (c SEOMetadataCheck) ID() string {
	return "seoMeta"
}

func (c SEOMetadataCheck) Title() string {
	return "SEO metadata"
}

func (c SEOMetadataCheck) Run(ctx Context) (CheckResult, error) {
	cfg := ctx.Config.Checks.SEOMeta
	if cfg == nil || cfg.MainLayout == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Check not configured",
		}, nil
	}

	layoutPath := filepath.Join(ctx.RootDir, cfg.MainLayout)
	content, err := os.ReadFile(layoutPath)
	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Could not read layout file: " + cfg.MainLayout,
			Suggestions: []string{
				"Check that the mainLayout path is correct in preflight.yml",
			},
		}, nil
	}

	contentStr := string(content)

	// Required SEO elements
	checks := map[string]*regexp.Regexp{
		"title":          regexp.MustCompile(`<title[^>]*>`),
		"description":    regexp.MustCompile(`<meta[^>]+name=["']description["'][^>]*>`),
		"og:title":       regexp.MustCompile(`<meta[^>]+property=["']og:title["'][^>]*>`),
		"og:description": regexp.MustCompile(`<meta[^>]+property=["']og:description["'][^>]*>`),
	}

	var missing []string
	for name, pattern := range checks {
		if !pattern.MatchString(contentStr) {
			// Check for alternate patterns (some frameworks use different formats)
			if !checkAlternatePatterns(contentStr, name) {
				missing = append(missing, name)
			}
		}
	}

	if len(missing) == 0 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "All required SEO metadata present",
		}, nil
	}

	return CheckResult{
		ID:       c.ID(),
		Title:    c.Title(),
		Severity: SeverityWarn,
		Passed:   false,
		Message:  "Missing SEO metadata: " + strings.Join(missing, ", "),
		Suggestions: []string{
			"Add missing meta tags to your layout",
			"Consider using a SEO component or helper",
		},
	}, nil
}

func checkAlternatePatterns(content, name string) bool {
	alternates := map[string][]*regexp.Regexp{
		"title": {
			regexp.MustCompile(`\btitle\s*[:=]`),  // JSX/React
			regexp.MustCompile(`<Title>`),         // Next.js Head
		},
		"description": {
			regexp.MustCompile(`name:\s*["']description["']`),
			regexp.MustCompile(`<meta\s+name="description"`),
		},
		"og:title": {
			regexp.MustCompile(`property:\s*["']og:title["']`),
			regexp.MustCompile(`openGraph.*title`),
		},
		"og:description": {
			regexp.MustCompile(`property:\s*["']og:description["']`),
			regexp.MustCompile(`openGraph.*description`),
		},
	}

	if patterns, ok := alternates[name]; ok {
		for _, pattern := range patterns {
			if pattern.MatchString(content) {
				return true
			}
		}
	}

	return false
}
