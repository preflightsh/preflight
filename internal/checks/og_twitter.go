package checks

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	_ "golang.org/x/image/webp"
)

type OGTwitterCheck struct{}

func (c OGTwitterCheck) ID() string {
	return "ogTwitter"
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
	content, err := os.ReadFile(layoutPath)
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

	// For Next.js, check if metadata/generateMetadata exists anywhere in app
	if strings.Contains(layoutFile, "app/") {
		hasMetadataInApp := false
		appDir := filepath.Dir(filepath.Join(ctx.RootDir, layoutFile))
		generateMetadataPattern := regexp.MustCompile(`(?s)export\s+(async\s+)?function\s+generateMetadata`)
		metadataExportPattern := regexp.MustCompile(`(?s)export\s+(const|let|var)\s+metadata\s*[=:]`)

		filepath.Walk(appDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || hasMetadataInApp {
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
			if !strings.HasSuffix(nameLower, ".tsx") && !strings.HasSuffix(nameLower, ".ts") &&
				!strings.HasSuffix(nameLower, ".jsx") && !strings.HasSuffix(nameLower, ".js") {
				return nil
			}
			fileContent, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if generateMetadataPattern.Match(fileContent) || metadataExportPattern.Match(fileContent) {
				hasMetadataInApp = true
			}
			return nil
		})

		if hasMetadataInApp {
			return CheckResult{
				ID:       c.ID(),
				Title:    c.Title(),
				Severity: SeverityInfo,
				Passed:   true,
				Message:  "OG and Twitter metadata configured via Next.js Metadata API",
			}, nil
		}
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
			matched = hasNextJSOGTwitterMeta(contentStr, name)
		}

		if matched {
			found = append(found, name)
		} else {
			missing = append(missing, name)
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
				missing = removeFromSlice(missing, "og:image")
				if !contains(found, "og:image") {
					found = append(found, "og:image (file)")
				}
				if localOGImagePath == "" {
					localOGImagePath = fullPath
				}
			}
			if strings.Contains(imgPath, "twitter") {
				missing = removeFromSlice(missing, "twitter:image")
				if !contains(found, "twitter:image") {
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
		filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
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
				missing = removeFromSlice(missing, "og:image")
				if !contains(found, "og:image") && !contains(found, "og:image (file)") {
					found = append(found, "og:image ("+relPath+")")
				}
				if localOGImagePath == "" && (strings.HasSuffix(nameLower, ".png") || strings.HasSuffix(nameLower, ".jpg") || strings.HasSuffix(nameLower, ".jpeg")) {
					localOGImagePath = path
				}
			}

			// Check for twitter-image files (static or dynamic)
			if strings.HasPrefix(nameLower, "twitter-image.") {
				missing = removeFromSlice(missing, "twitter:image")
				missing = removeFromSlice(missing, "twitter:card") // twitter-image implies twitter:card
				if !contains(found, "twitter:image") && !contains(found, "twitter:image (file)") {
					found = append(found, "twitter:image ("+relPath+")")
				}
				if !contains(found, "twitter:card") {
					found = append(found, "twitter:card")
				}
				if localTwitterImagePath == "" && (strings.HasSuffix(nameLower, ".png") || strings.HasSuffix(nameLower, ".jpg") || strings.HasSuffix(nameLower, ".jpeg")) {
					localTwitterImagePath = path
				}
			}

			return nil
		})
	}

	// Check dimensions of images
	baseURL := ""
	if ctx.Config.URLs.Staging != "" {
		baseURL = ctx.Config.URLs.Staging
	} else if ctx.Config.URLs.Production != "" {
		baseURL = ctx.Config.URLs.Production
	}

	// Check OG image dimensions
	if ogImageURL != "" && ctx.Client != nil {
		fullURL := resolveImageURL(ogImageURL, baseURL)
		if fullURL != "" {
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
		if fullURL != "" {
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
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "OG and Twitter card metadata configured",
			Details:  details,
		}, nil
	}

	var messages []string
	if len(missing) > 0 {
		messages = append(messages, "Missing: "+strings.Join(missing, ", "))
	}
	if len(dimensionWarnings) > 0 {
		messages = append(messages, dimensionWarnings...)
	}

	severity := SeverityWarn
	suggestions := []string{}
	if len(missing) > 0 && contains(missing, "og:image") {
		suggestions = append(suggestions, "Add og:image for rich social media previews")
	}
	if len(missing) > 0 && contains(missing, "twitter:card") {
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

	// If using generateMetadata, assume all metadata is handled dynamically
	if generateMetadata.MatchString(content) {
		return true
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
			imagePattern := regexp.MustCompile(`(?m)image\s*:\s*["'\x60]`)
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
			urlPattern := regexp.MustCompile(`(?m)url\s*:\s*["'\x60]`)
			return urlPattern.MatchString(ogBlock)
		}
		return false

	case "og:type":
		ogBlock := extractNestedBlockOG(metadataContent, "openGraph")
		if ogBlock != "" {
			typePattern := regexp.MustCompile(`(?m)type\s*:\s*["'\x60]`)
			return typePattern.MatchString(ogBlock)
		}
		return false

	case "twitter:card":
		twitterBlock := extractNestedBlockOG(metadataContent, "twitter")
		if twitterBlock != "" {
			cardPattern := regexp.MustCompile(`(?m)card\s*:\s*["'\x60]`)
			return cardPattern.MatchString(twitterBlock)
		}
		return false

	case "twitter:image":
		twitterBlock := extractNestedBlockOG(metadataContent, "twitter")
		if twitterBlock != "" {
			imagesPattern := regexp.MustCompile(`(?m)images\s*:\s*\[`)
			imagePattern := regexp.MustCompile(`(?m)image\s*:\s*["'\x60]`)
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
	for i := pos; i < len(content); i++ {
		if content[i] == '{' {
			depth++
		} else if content[i] == '}' {
			depth--
			if depth == 0 {
				return content[pos : i+1]
			}
		}
	}
	return ""
}

// extractNestedBlockOG extracts a nested object block like openGraph: { ... }
func extractNestedBlockOG(content, key string) string {
	pattern := regexp.MustCompile(`(?s)` + key + `\s*:\s*\{`)
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

// fetchImageDimensions fetches an image from a URL and returns its dimensions
func fetchImageDimensions(ctx Context, url string) (width, height int, err error) {
	resp, err := doGet(ctx.Client, url)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	img, _, err := image.DecodeConfig(resp.Body)
	if err != nil {
		return 0, 0, err
	}

	return img.Width, img.Height, nil
}

// getLocalImageDimensions reads a local image file and returns its dimensions
func getLocalImageDimensions(path string) (width, height int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	img, _, err := image.DecodeConfig(f)
	if err != nil {
		return 0, 0, err
	}

	return img.Width, img.Height, nil
}

func removeFromSlice(slice []string, item string) []string {
	var result []string
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
