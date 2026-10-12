package checks

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/preflightsh/preflight/internal/netutil"

	_ "golang.org/x/image/webp"
)

type OGTwitterCheck struct{}

func (c OGTwitterCheck) ID() string {
	return "og_twitter"
}

func (c OGTwitterCheck) Title() string {
	return "OG & Twitter cards configured"
}

// Recommended dimensions for social images
const (
	ogRecommendedWidth  = 1200
	ogRecommendedHeight = 630
	ogMinWidth          = 200
	ogMinHeight         = 200

	twitterRecommendedWidth  = 1200
	twitterRecommendedHeight = 600
	twitterMinWidth          = 300
	twitterMinHeight         = 157
)

func (c OGTwitterCheck) Run(ctx Context) (CheckResult, error) {
	if ctx.Config.URLs.Production != "" || ctx.Config.URLs.Staging != "" {
		return c.runRendered(ctx), nil
	}
	cfg := ctx.Config.Checks.SEOMeta

	// Get configured layout or auto-detect
	var configuredLayout string
	if cfg != nil {
		configuredLayout = cfg.MainLayout
	}
	layoutFile := getLayoutFile(ctx.RootDir, ctx.Config.Stack, configuredLayout)

	if layoutFile == "" {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "No layout file found, skipping",
		}, nil
	}

	layoutPath := filepath.Join(ctx.RootDir, layoutFile)
	content, err := readSourceFile(layoutPath)
	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Could not read layout file: " + layoutFile,
		}, nil
	}

	// Strip comments to avoid false positives on commented-out code
	contentStr := stripComments(string(content))

	// For the Next.js App Router, the root page and top-level route group
	// layouts can carry the Metadata API export instead of the root layout;
	// a nested page's export only covers that page (see nextRootRouteSources).
	var nextSources []string
	if strings.Contains(layoutFile, "app/") {
		nextSources = nextRootRouteSources(filepath.Dir(layoutPath))
	}

	// OG and Twitter card elements
	checks := map[string]*regexp.Regexp{
		"og:image":      regexp.MustCompile(`(?i)<meta[^>]+property=["']og:image["'][^>]*>`),
		"og:url":        regexp.MustCompile(`(?i)<meta[^>]+property=["']og:url["'][^>]*>`),
		"og:type":       regexp.MustCompile(`(?i)<meta[^>]+property=["']og:type["'][^>]*>`),
		"twitter:card":  regexp.MustCompile(`(?i)<meta[^>]+name=["']twitter:card["'][^>]*>`),
		"twitter:image": regexp.MustCompile(`(?i)<meta[^>]+name=["']twitter:image["'][^>]*>`),
	}

	// Alternate patterns for Next.js/React metadata API
	alternates := map[string][]*regexp.Regexp{
		"og:image": {
			regexp.MustCompile(`(?i)og:image`),
			regexp.MustCompile(`(?i)opengraph-image\.(png|jpg|jpeg|svg|webp)`),
		},
		"og:url": {
			regexp.MustCompile(`(?i)metadataBase`),
		},
		"og:type": {},
		"twitter:card": {
			regexp.MustCompile(`(?i)twitter-image\.(png|jpg|jpeg|svg|webp)`),
		},
		"twitter:image": {
			regexp.MustCompile(`(?i)twitter-image\.(png|jpg|jpeg|svg|webp)`),
		},
	}

	var missing []string
	var found []string
	var dimensionWarnings []string
	var details []string

	// Extract image URLs for dimension checking
	ogImageURL := extractMetaContent(contentStr, `property=["']og:image["']`)
	twitterImageURL := extractMetaContent(contentStr, `name=["']twitter:image["']`)

	for name, pattern := range checks {
		matched := pattern.MatchString(contentStr)

		// Try alternate patterns
		if !matched {
			if alts, ok := alternates[name]; ok {
				for _, alt := range alts {
					if alt.MatchString(contentStr) {
						matched = true
						break
					}
				}
			}
		}

		// Try Next.js Metadata API patterns (multi-line aware)
		if !matched {
			matched = hasNextJSOGTwitterMeta(contentStr, name) || anyNextSource(nextSources, name, hasNextJSOGTwitterMeta)
		}

		if matched {
			found = append(found, name)
		} else {
			missing = append(missing, name)
		}
	}

	// Per-env rendered HTML fallback for items that weren't in the static
	// template. Catches CMS-driven sites (Craft+SEOmatic, WordPress+Yoast,
	// etc.) where meta tags are emitted at runtime. We do this before the
	// image-dimension checks so a fully-passing rendered HTML doesn't get
	// downgraded by image-size warnings on a non-authoritative env.
	staticMissing := append([]string(nil), missing...)
	var perEnvSummary string
	var perEnvProdPassed bool
	if len(staticMissing) > 0 && (ctx.Config.URLs.Production != "" || ctx.Config.URLs.Staging != "") {
		perEnvSummary, perEnvProdPassed = RunPerEnv(ctx, func(html string) []string {
			doc := parseRenderedHTML(html)
			var stillMissing []string
			for _, name := range staticMissing {
				if !doc.hasMeta(name) {
					stillMissing = append(stillMissing, name)
				}
			}
			return stillMissing
		})
		if perEnvProdPassed {
			// Production has all the OG/Twitter tags. Treat the static
			// template as "good enough" and clear missing so dimension
			// checks below run against the rendered values.
			missing = nil
			found = append(found, staticMissing...)
			// A CMS-rendered og:image never appears in the template, so take
			// the rendered production values for the dimension checks.
			rendered := parseRenderedHTML(ctx.PageHTMLProduction)
			if ogImageURL == "" {
				ogImageURL = rendered.metaProperty["og:image"]
			}
			if twitterImageURL == "" {
				twitterImageURL = rendered.metaName["twitter:image"]
				if twitterImageURL == "" {
					twitterImageURL = rendered.metaProperty["twitter:image"]
				}
			}
		}
	}

	// Also check for opengraph-image and twitter-image files in app directory
	ogImageFiles := []string{
		"app/opengraph-image.png",
		"app/opengraph-image.jpg",
		"app/twitter-image.png",
		"app/twitter-image.jpg",
		"public/og-image.png",
		"public/og-image.jpg",
		"public/og.png",
		"public/opengraph.png",
		"public/opengraph-image.png",
		"public/twitter-image.png",
	}

	var localOGImagePath, localTwitterImagePath string
	for _, imgPath := range ogImageFiles {
		fullPath := filepath.Join(ctx.RootDir, imgPath)
		if _, err := os.Stat(fullPath); err == nil {
			if strings.Contains(imgPath, "opengraph") || strings.Contains(imgPath, "og") {
				missing = removeString(missing, "og:image")
				if !slices.Contains(found, "og:image") {
					found = append(found, "og:image (file)")
				}
				if localOGImagePath == "" {
					localOGImagePath = fullPath
				}
			}
			if strings.Contains(imgPath, "twitter") {
				missing = removeString(missing, "twitter:image")
				if !slices.Contains(found, "twitter:image") {
					found = append(found, "twitter:image (file)")
				}
				if localTwitterImagePath == "" {
					localTwitterImagePath = fullPath
				}
			}
		}
	}

	// Flexible search: walk app directories for dynamic image generation files
	flexImageDirs := []string{"app", "src/app"}
	for _, dir := range flexImageDirs {
		dirPath := filepath.Join(ctx.RootDir, dir)
		if _, err := os.Stat(dirPath); err != nil {
			continue
		}
		_ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				if info != nil && info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if info.IsDir() {
				name := info.Name()
				if name == "node_modules" || name == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			nameLower := strings.ToLower(info.Name())
			relPath := relPath(ctx.RootDir, path)

			// Check for opengraph-image files (static or dynamic)
			if strings.HasPrefix(nameLower, "opengraph-image.") {
				missing = removeString(missing, "og:image")
				if !slices.Contains(found, "og:image") && !slices.Contains(found, "og:image (file)") {
					found = append(found, "og:image ("+relPath+")")
				}
				if localOGImagePath == "" && (strings.HasSuffix(nameLower, ".png") || strings.HasSuffix(nameLower, ".jpg") || strings.HasSuffix(nameLower, ".jpeg")) {
					localOGImagePath = path
				}
			}

			// Check for twitter-image files (static or dynamic)
			if strings.HasPrefix(nameLower, "twitter-image.") {
				missing = removeString(missing, "twitter:image")
				missing = removeString(missing, "twitter:card") // twitter-image implies twitter:card
				if !slices.Contains(found, "twitter:image") && !slices.Contains(found, "twitter:image (file)") {
					found = append(found, "twitter:image ("+relPath+")")
				}
				if !slices.Contains(found, "twitter:card") {
					found = append(found, "twitter:card")
				}
				if localTwitterImagePath == "" && (strings.HasSuffix(nameLower, ".png") || strings.HasSuffix(nameLower, ".jpg") || strings.HasSuffix(nameLower, ".jpeg")) {
					localTwitterImagePath = path
				}
			}

			return nil
		})
	}

	// Check dimensions of images. Relative image URLs resolve against the
	// first environment that answered the homepage prefetch, so a staging
	// server that is not running does not stop production's og:image from
	// being measured.
	baseURL := ""
	if bases := ctx.probeBaseURLs(); len(bases) > 0 {
		baseURL = bases[0]
	}

	// Check OG image dimensions
	if ogImageURL != "" && ctx.Client != nil {
		fullURL := resolveImageURL(ogImageURL, baseURL)
		if fullURL != "" && imageFetchable(ctx, fullURL, baseURL) {
			width, height, err := fetchImageDimensions(ctx, fullURL)
			if err == nil {
				details = append(details, fmt.Sprintf("og:image dimensions: %dx%d", width, height))
				if width < ogMinWidth || height < ogMinHeight {
					dimensionWarnings = append(dimensionWarnings,
						fmt.Sprintf("og:image too small (%dx%d, min %dx%d)", width, height, ogMinWidth, ogMinHeight))
				} else if width < ogRecommendedWidth || height < ogRecommendedHeight {
					dimensionWarnings = append(dimensionWarnings,
						fmt.Sprintf("og:image below recommended (%dx%d, recommended %dx%d)", width, height, ogRecommendedWidth, ogRecommendedHeight))
				}
			} else if ctx.Verbose {
				details = append(details, fmt.Sprintf("og:image fetch error: %v", err))
			}
		}
	} else if localOGImagePath != "" {
		width, height, err := getLocalImageDimensions(localOGImagePath)
		if err == nil {
			details = append(details, fmt.Sprintf("og:image dimensions: %dx%d", width, height))
			if width < ogMinWidth || height < ogMinHeight {
				dimensionWarnings = append(dimensionWarnings,
					fmt.Sprintf("og:image too small (%dx%d, min %dx%d)", width, height, ogMinWidth, ogMinHeight))
			} else if width < ogRecommendedWidth || height < ogRecommendedHeight {
				dimensionWarnings = append(dimensionWarnings,
					fmt.Sprintf("og:image below recommended (%dx%d, recommended %dx%d)", width, height, ogRecommendedWidth, ogRecommendedHeight))
			}
		}
	}

	// Check Twitter image dimensions
	if twitterImageURL != "" && ctx.Client != nil {
		fullURL := resolveImageURL(twitterImageURL, baseURL)
		if fullURL != "" && imageFetchable(ctx, fullURL, baseURL) {
			width, height, err := fetchImageDimensions(ctx, fullURL)
			if err == nil {
				details = append(details, fmt.Sprintf("twitter:image dimensions: %dx%d", width, height))
				if width < twitterMinWidth || height < twitterMinHeight {
					dimensionWarnings = append(dimensionWarnings,
						fmt.Sprintf("twitter:image too small (%dx%d, min %dx%d)", width, height, twitterMinWidth, twitterMinHeight))
				} else if width < twitterRecommendedWidth || height < twitterRecommendedHeight {
					dimensionWarnings = append(dimensionWarnings,
						fmt.Sprintf("twitter:image below recommended (%dx%d, recommended %dx%d)", width, height, twitterRecommendedWidth, twitterRecommendedHeight))
				}
			} else if ctx.Verbose {
				details = append(details, fmt.Sprintf("twitter:image fetch error: %v", err))
			}
		}
	} else if localTwitterImagePath != "" {
		width, height, err := getLocalImageDimensions(localTwitterImagePath)
		if err == nil {
			details = append(details, fmt.Sprintf("twitter:image dimensions: %dx%d", width, height))
			if width < twitterMinWidth || height < twitterMinHeight {
				dimensionWarnings = append(dimensionWarnings,
					fmt.Sprintf("twitter:image too small (%dx%d, min %dx%d)", width, height, twitterMinWidth, twitterMinHeight))
			} else if width < twitterRecommendedWidth || height < twitterRecommendedHeight {
				dimensionWarnings = append(dimensionWarnings,
					fmt.Sprintf("twitter:image below recommended (%dx%d, recommended %dx%d)", width, height, twitterRecommendedWidth, twitterRecommendedHeight))
			}
		}
	}

	// Build result
	if len(missing) == 0 && len(dimensionWarnings) == 0 {
		msg := "OG and Twitter card metadata configured"
		if perEnvSummary != "" {
			msg = perEnvSummary
		}
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  msg,
			Details:  details,
		}, nil
	}

	var messages []string
	if perEnvSummary != "" {
		messages = append(messages, perEnvSummary)
	} else if len(missing) > 0 {
		messages = append(messages, "Missing: "+strings.Join(missing, ", "))
	}
	if len(dimensionWarnings) > 0 {
		messages = append(messages, dimensionWarnings...)
	}

	severity := SeverityWarn
	suggestions := []string{}
	if len(missing) > 0 && slices.Contains(missing, "og:image") {
		suggestions = append(suggestions, "Add og:image for rich social media previews")
	}
	if len(missing) > 0 && slices.Contains(missing, "twitter:card") {
		suggestions = append(suggestions, "Add twitter:card for Twitter/X previews")
	}
	if len(dimensionWarnings) > 0 {
		suggestions = append(suggestions, fmt.Sprintf("Use %dx%d for OG images, %dx%d for Twitter", ogRecommendedWidth, ogRecommendedHeight, twitterRecommendedWidth, twitterRecommendedHeight))
	}

	return CheckResult{
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    severity,
		Passed:      false,
		Message:     strings.Join(messages, "; "),
		Suggestions: suggestions,
		Details:     details,
	}, nil
}

// hasNextJSOGTwitterMeta checks for Next.js Metadata API OG/Twitter patterns
func hasNextJSOGTwitterMeta(content, name string) bool {
	// Check if this looks like a Next.js metadata export or generateMetadata function
	metadataExport := regexp.MustCompile(`(?s)export\s+(const|let|var)\s+metadata\s*[=:]`)
	generateMetadata := regexp.MustCompile(`(?s)export\s+(async\s+)?function\s+generateMetadata`)

	// A dynamic generator is not evidence that any required field exists.
	if generateMetadata.MatchString(content) {
		return false
	}

	if !metadataExport.MatchString(content) {
		return false
	}

	// Extract the metadata object
	metadataBlock := regexp.MustCompile(`(?s)export\s+(?:const|let|var)\s+metadata[^=]*=\s*\{`)
	loc := metadataBlock.FindStringIndex(content)
	if loc == nil {
		return false
	}

	// Find the matching closing brace for the metadata object
	metadataContent := extractBraceBlock(content, loc[1]-1)
	if metadataContent == "" {
		return false
	}

	switch name {
	case "og:image":
		ogBlock := extractNestedBlockOG(metadataContent, "openGraph")
		if ogBlock != "" {
			// Check for images array or image property
			imagesPattern := regexp.MustCompile(`(?m)images\s*:\s*\[`)
			imagePattern := regexp.MustCompile(`(?m)image\s*:\s*[^\s,}]`)
			return imagesPattern.MatchString(ogBlock) || imagePattern.MatchString(ogBlock)
		}
		return false

	case "og:url":
		// metadataBase or openGraph.url
		if regexp.MustCompile(`(?m)metadataBase\s*:`).MatchString(metadataContent) {
			return true
		}
		ogBlock := extractNestedBlockOG(metadataContent, "openGraph")
		if ogBlock != "" {
			urlPattern := regexp.MustCompile(`(?m)url\s*:\s*[^\s,}]`)
			return urlPattern.MatchString(ogBlock)
		}
		return false

	case "og:type":
		ogBlock := extractNestedBlockOG(metadataContent, "openGraph")
		if ogBlock != "" {
			typePattern := regexp.MustCompile(`(?m)type\s*:\s*[^\s,}]`)
			return typePattern.MatchString(ogBlock)
		}
		return false

	case "twitter:card":
		twitterBlock := extractNestedBlockOG(metadataContent, "twitter")
		if twitterBlock != "" {
			cardPattern := regexp.MustCompile(`(?m)card\s*:\s*[^\s,}]`)
			return cardPattern.MatchString(twitterBlock)
		}
		return false

	case "twitter:image":
		twitterBlock := extractNestedBlockOG(metadataContent, "twitter")
		if twitterBlock != "" {
			imagesPattern := regexp.MustCompile(`(?m)images\s*:\s*\[`)
			imagePattern := regexp.MustCompile(`(?m)image\s*:\s*[^\s,}]`)
			return imagesPattern.MatchString(twitterBlock) || imagePattern.MatchString(twitterBlock)
		}
		return false
	}

	return false
}

// extractBraceBlock extracts content between matching braces starting at pos
func extractBraceBlock(content string, pos int) string {
	if pos >= len(content) || content[pos] != '{' {
		return ""
	}
	depth := 0
	inString := false
	stringChar := byte(0)
	for i := pos; i < len(content); i++ {
		c := content[i]
		if !inString && (c == '"' || c == '\'' || c == '`') {
			inString = true
			stringChar = c
		} else if inString && c == stringChar && (i == 0 || content[i-1] != '\\') {
			inString = false
		} else if !inString {
			if c == '{' {
				depth++
			} else if c == '}' {
				depth--
				if depth == 0 {
					return content[pos : i+1]
				}
			}
		}
	}
	return ""
}

// extractNestedBlockOG extracts a nested object block like openGraph: { ... }
func extractNestedBlockOG(content, key string) string {
	pattern := regexp.MustCompile(`(?s)` + regexp.QuoteMeta(key) + `\s*:\s*\{`)
	loc := pattern.FindStringIndex(content)
	if loc == nil {
		return ""
	}
	return extractBraceBlock(content, loc[1]-1)
}

// extractMetaContent extracts the content attribute from a meta tag matching the given pattern
func extractMetaContent(html, attrPattern string) string {
	// Match the full meta tag
	tagPattern := regexp.MustCompile(`(?i)<meta[^>]+` + attrPattern + `[^>]*>`)
	tag := tagPattern.FindString(html)
	if tag == "" {
		return ""
	}

	// Extract content attribute
	contentPattern := regexp.MustCompile(`(?i)content=["']([^"']+)["']`)
	matches := contentPattern.FindStringSubmatch(tag)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// resolveImageURL resolves a potentially relative image URL to an absolute URL
func resolveImageURL(imageURL, baseURL string) string {
	if imageURL == "" {
		return ""
	}

	// Already absolute
	if strings.HasPrefix(imageURL, "http://") || strings.HasPrefix(imageURL, "https://") {
		return imageURL
	}

	// Relative URL - need base URL
	if baseURL == "" {
		return ""
	}

	// Ensure base URL has protocol
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}

	// Remove trailing slash from base
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Handle absolute path
	if strings.HasPrefix(imageURL, "/") {
		return baseURL + imageURL
	}

	// Handle relative path
	return baseURL + "/" + imageURL
}

// imageFetchable reports whether an image URL is worth requesting: an image
// on a base the homepage prefetch already found unreachable is skipped so
// the check doesn't wait out another timeout. CDN-hosted images on other
// hosts are always tried.
func imageFetchable(ctx Context, imageURL, baseURL string) bool {
	base := strings.TrimSuffix(baseURL, "/")
	return base == "" || !strings.HasPrefix(imageURL, base) || !ctx.HostUnreachable(baseURL)
}

// fetchImageDimensions fetches an image from a URL and returns its dimensions
func fetchImageDimensions(ctx Context, url string) (width, height int, err error) {
	resp, err := doGet(ctx.reqContext(), ctx.Client, url)
	if err != nil {
		return 0, 0, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, 0, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}

	// DecodeConfig allocates based on header-declared dimensions, so a
	// malicious image could OOM the scanner. Cap the reader.
	img, _, err := image.DecodeConfig(io.LimitReader(resp.Body, netutil.MaxResponseBody))
	if err != nil {
		return 0, 0, fmt.Errorf("decode %s: %w", url, err)
	}

	return img.Width, img.Height, nil
}

// getLocalImageDimensions reads a local image file and returns its dimensions
func getLocalImageDimensions(path string) (width, height int, err error) {
	f, err := openRegular(path)
	if err != nil {
		return 0, 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	img, _, err := image.DecodeConfig(io.LimitReader(f, netutil.MaxResponseBody))
	if err != nil {
		return 0, 0, fmt.Errorf("decode %s: %w", path, err)
	}

	return img.Width, img.Height, nil
}

// removeString returns slice with all occurrences of item removed.
// Thin wrapper over slices.DeleteFunc for readability at call sites.
func removeString(slice []string, item string) []string {
	return slices.DeleteFunc(slice, func(s string) bool { return s == item })
}
