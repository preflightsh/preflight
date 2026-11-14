package cmd

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/preflightsh/preflight/internal/catalog"
	"github.com/preflightsh/preflight/internal/config"
	"github.com/preflightsh/preflight/internal/fsutil"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize preflight configuration for your project",
	Long: `Initialize preflight by detecting your stack and services,
then generating a preflight.yml configuration file.`,
	Args: cobra.NoArgs,
	RunE: runInit,
}

var initForce bool

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().BoolVar(&initForce, "force", false, "Overwrite an existing preflight.yml")
}

func runInit(cmd *cobra.Command, args []string) error {
	CheckForUpdates()

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("🚀 Initializing Preflight...")
	fmt.Println()

	// Get current directory
	cwd, err := os.Getwd()
	if err != nil {
		return couldNotRun(fmt.Errorf("failed to get current directory: %w", err))
	}

	// Re-running init used to overwrite preflight.yml without asking,
	// wiping the ignore list, the secrets allowlist and any comments.
	if _, err := os.Lstat(filepath.Join(cwd, "preflight.yml")); err == nil && !initForce {
		fmt.Println("preflight.yml already exists. Init would replace it, dropping your ignore list,")
		fmt.Println("secrets allowlist and comments.")
		if !promptYesNo(reader, "Overwrite preflight.yml?", false) {
			fmt.Println("Kept the existing preflight.yml. Edit it directly, or use 'preflight ignore'.")
			return nil
		}
	}

	// Detect stack
	fmt.Print("Detecting stack... ")
	stack := config.DetectStack(cwd)
	stackDisplay := formatStackName(stack)
	if version := detectStackVersion(cwd, stack); version != "" {
		stackDisplay += " " + version
	}
	fmt.Printf("detected: %s\n", stackDisplay)

	// Detect services
	fmt.Println("Detecting services...")
	services := config.DetectServices(cwd)

	// Collect and sort detected services
	var detectedServices []string
	for name, detected := range services {
		if detected {
			detectedServices = append(detectedServices, name)
		}
	}
	sort.Strings(detectedServices)

	for _, name := range detectedServices {
		fmt.Printf("  ✓ %s detected\n", formatServiceName(name))
	}
	fmt.Println()

	// Get project name
	projectName := promptWithDefault(reader, "Project name", getDefaultProjectName(cwd))

	// Get URLs
	fmt.Println()
	stagingURL := config.NormalizeURL(promptOptional(reader, "Staging URL (optional)"))
	productionURL := config.NormalizeURL(promptOptional(reader, "Production URL (optional)"))

	// Confirm services
	fmt.Println()
	fmt.Println("Confirm detected services (y/n for each):")
	confirmedServices := make(map[string]config.ServiceConfig)
	for _, name := range detectedServices {
		confirm := promptYesNo(reader, fmt.Sprintf("  Use %s?", formatServiceName(name)), true)
		if confirm {
			confirmedServices[name] = config.ServiceConfig{Declared: true}
		}
	}

	// Ask about additional services not detected
	fmt.Println()
	fmt.Println("Any other services to check for?")
	fmt.Println("  1. Skip (use only detected services)")
	fmt.Println("  2. Go through full list (recommended for first setup)")
	choice := promptWithDefault(reader, "  Choose", "1")
	if choice == "2" {
		fmt.Println()
		for _, svc := range config.AllServices {
			if _, exists := confirmedServices[svc]; !exists {
				if promptYesNo(reader, fmt.Sprintf("  Use %s?", formatServiceName(svc)), false) {
					confirmedServices[svc] = config.ServiceConfig{Declared: true}
				}
			}
		}
	}

	// Ask about license file
	fmt.Println()
	hasLicense := promptYesNo(reader, "Does this project have a LICENSE file (e.g., MIT, Apache, GPL)?", false)

	// Ask about ads
	hasAds := promptYesNo(reader, "Does this site serve ads or advertisements?", false)

	// Ask about email authentication
	checkEmailAuth := promptYesNo(reader, "Check email authentication (SPF/DMARC)?", false)
	mailDomain := ""
	if checkEmailAuth {
		mailDomain = promptMailDomain(reader)
		if mailDomain == "" {
			checkEmailAuth = false
			fmt.Println("Email authentication disabled until emailAuth.domain is configured.")
		}
	}

	// Ask about humans.txt
	checkHumansTxt := promptYesNo(reader, "Got a humans.txt crediting the team?", false)

	// Handle IndexNow - user already confirmed/declined in services section
	var indexNowKey string
	writeKeyFile := false
	if confirmedServices["indexnow"].Declared {
		indexNowKey, writeKeyFile = chooseIndexNowKey(reader, cwd)
		// Remove from confirmedServices since we handle it separately
		delete(confirmedServices, "indexnow")
	}

	// Build full services map with all services (declared: true or false)
	allServices := make(map[string]config.ServiceConfig)
	for _, svc := range config.AllServices {
		if svc == "indexnow" {
			continue // handled in checks.indexNow
		}
		if _, confirmed := confirmedServices[svc]; confirmed {
			allServices[svc] = config.ServiceConfig{Declared: true}
		} else {
			allServices[svc] = config.ServiceConfig{Declared: false}
		}
	}

	// Build config
	cfg := config.PreflightConfig{
		ProjectName: projectName,
		Stack:       stack,
		URLs: config.URLConfig{
			Staging:    stagingURL,
			Production: productionURL,
		},
		Services: allServices,
		Checks:   buildDefaultChecks(cwd, stack, allServices, productionURL, hasLicense, hasAds, indexNowKey, checkEmailAuth, checkHumansTxt),
	}

	if cfg.Checks.EmailAuth != nil {
		cfg.Checks.EmailAuth.Domain = mailDomain
	}
	// Each answer was checked at its prompt, so this should not fail. It
	// stays as the last gate, and it runs before anything is written:
	// nothing reaches the disk (the IndexNow key file included) for a
	// config that would not load.
	if err := config.Validate(&cfg); err != nil {
		return couldNotRun(fmt.Errorf("configuration: %w", err))
	}
	// Write config file
	configPath := "preflight.yml"
	if err := writeConfig(configPath, &cfg); err != nil {
		return couldNotRun(fmt.Errorf("failed to write config: %w", err))
	}

	fmt.Println()
	fmt.Printf("✅ Created %s\n", configPath)

	if writeKeyFile {
		createIndexNowKeyFile(cwd, stack, indexNowKey)
	}

	if !offerGitignore(reader, cwd) {
		fmt.Println()
		fmt.Println("⚠️  Remember: preflight.yml may contain sensitive URLs.")
		fmt.Println("   Consider adding it to your .gitignore")
	}

	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Review and customize preflight.yml")
	fmt.Println("  2. Run 'preflight scan' to check your project")
	fmt.Println()

	// Show star message on first init
	if isFirstRun("init_done") {
		showStarMessage()
		markFirstRunComplete("init_done")
	}

	return nil
}

// promptMailDomain asks for the email sending domain until the answer is
// a usable DNS name or empty. A bad answer used to be accepted here and
// rejected only when the finished config was validated, after every other
// prompt, which threw all the answers away.
func promptMailDomain(reader *bufio.Reader) string {
	for {
		answer, ok := promptLine(reader, "Email sending domain (e.g. mail.example.com)")
		domain, err := config.NormalizeMailDomain(answer)
		if err == nil {
			return domain
		}
		fmt.Printf("  %q is not a domain name: enter just the domain, such as mail.example.com, or leave it empty to skip.\n", answer)
		if !ok {
			// Input ended; there is nobody to ask again.
			return ""
		}
	}
}

// chooseIndexNowKey finds the project's IndexNow key or asks for one. It
// reports whether a newly generated key still needs its key file; the
// file is written only after preflight.yml has been.
func chooseIndexNowKey(reader *bufio.Reader, cwd string) (key string, generated bool) {
	// Try to extract key from .env files
	if key = detectIndexNowKey(cwd); key != "" {
		fmt.Printf("IndexNow key found: %s\n", key)
		return key, false
	}
	fmt.Println("IndexNow enabled but no key found in .env files or web root")
	fmt.Println("  1. Paste existing key")
	fmt.Println("  2. Generate new key")
	if promptWithDefault(reader, "  Choose", "2") == "1" {
		return promptOptional(reader, "  Paste your IndexNow key"), false
	}
	key = generateIndexNowKey()
	if key == "" {
		return "", false
	}
	fmt.Printf("  Generated key: %s\n", key)
	return key, true
}

// createIndexNowKeyFile writes <key>.txt where the site will serve it from
// its root, or says where to put it when it cannot.
func createIndexNowKeyFile(cwd, stack, key string) {
	rel := filepath.Join(detectWebRoot(cwd, stack), key+".txt")
	keyFilePath := filepath.Join(cwd, rel)
	if err := os.MkdirAll(filepath.Dir(keyFilePath), 0755); err != nil {
		fmt.Printf("  ⚠️  Could not create directory: %v\n", err)
		fmt.Printf("     Create %s containing: %s\n", rel, key)
		return
	}
	if err := fsutil.WriteFile(keyFilePath, []byte(key+"\n"), 0644); err != nil {
		fmt.Printf("  ⚠️  Could not create key file: %v\n", err)
		fmt.Printf("     Create %s containing: %s\n", rel, key)
		return
	}
	fmt.Printf("✅ Created %s\n", rel)
	if stack == "eleventy" {
		fmt.Println("   Eleventy copies only the files it is told to: add it with addPassthroughCopy in your config.")
	}
}

// offerGitignore offers to list preflight.yml in .gitignore and reports
// whether it ended up there.
func offerGitignore(reader *bufio.Reader, cwd string) bool {
	gitignorePath := filepath.Join(cwd, ".gitignore")
	content, err := fsutil.ReadFile(gitignorePath, 8<<20)
	switch {
	case err == nil:
		// .gitignore exists, check if preflight.yml is already covered
		// by an effective rule (handles globs, leading "/", comments,
		// and "!preflight.yml" negations).
		if gitignoreCoversPreflightYml(content) {
			return true
		}
		if !promptYesNo(reader, "Add preflight.yml to .gitignore?", true) {
			return false
		}
		updated := append([]byte{}, content...)
		if len(updated) > 0 && updated[len(updated)-1] != '\n' {
			updated = append(updated, '\n')
		}
		updated = append(updated, "preflight.yml\n"...)
		if err := fsutil.WriteFile(gitignorePath, updated, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "⚠️  Could not update .gitignore:", err)
			return false
		}
		fmt.Println("✅ Added preflight.yml to .gitignore")
		return true
	case os.IsNotExist(err):
		// No .gitignore exists, offer to create one
		if !promptYesNo(reader, "Create .gitignore with preflight.yml?", true) {
			return false
		}
		if err := fsutil.WriteFile(gitignorePath, []byte("preflight.yml\n"), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Could not create .gitignore: %v\n", err)
			return false
		}
		fmt.Println("✅ Created .gitignore with preflight.yml")
		return true
	}
	return false
}

// gitignoreCoversPreflightYml reports whether the given .gitignore
// content has an effective rule that ignores `preflight.yml` at the
// project root. Honors comments, a leading "/" anchor, glob patterns
// supported by filepath.Match, and "!pattern" negations (later rules
// override earlier ones, matching git's own evaluation order).
// Does not understand `**` recursive globs; users relying on those
// will just get the prompt again, which is harmless.
func gitignoreCoversPreflightYml(content []byte) bool {
	const target = "preflight.yml"
	ignored := false
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		negate := strings.HasPrefix(line, "!")
		if negate {
			line = line[1:]
		}
		line = strings.TrimPrefix(line, "/")
		// Directory-only patterns can't match a file.
		if strings.HasSuffix(line, "/") {
			continue
		}
		match := line == target
		if !match {
			if ok, err := filepath.Match(line, target); err == nil && ok {
				match = true
			}
		}
		if match {
			ignored = !negate
		}
	}
	return ignored
}

func promptWithDefault(reader *bufio.Reader, prompt, defaultVal string) string {
	fmt.Printf("%s [%s]: ", prompt, defaultVal)
	input, err := reader.ReadString('\n')
	if err != nil {
		return defaultVal
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

func promptOptional(reader *bufio.Reader, prompt string) string {
	answer, _ := promptLine(reader, prompt)
	return answer
}

// promptLine asks for one line. ok is false once input has ended (EOF or
// a read error), which tells a caller that would ask again to stop.
func promptLine(reader *bufio.Reader, prompt string) (answer string, ok bool) {
	fmt.Printf("%s: ", prompt)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(input), true
}

func promptYesNo(reader *bufio.Reader, prompt string, defaultYes bool) bool {
	defaultStr := "Y/n"
	if !defaultYes {
		defaultStr = "y/N"
	}
	fmt.Printf("%s [%s]: ", prompt, defaultStr)
	input, err := reader.ReadString('\n')
	if err != nil {
		return defaultYes
	}
	input = strings.ToLower(strings.TrimSpace(input))

	if input == "" {
		return defaultYes
	}
	return input == "y" || input == "yes"
}

func getDefaultProjectName(cwd string) string {
	base := filepath.Base(cwd)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "my-project"
	}
	return base
}

func buildDefaultChecks(cwd, stack string, services map[string]config.ServiceConfig, productionURL string, hasLicense bool, hasAds bool, indexNowKey string, checkEmailAuth bool, checkHumansTxt bool) config.ChecksConfig {
	checks := config.ChecksConfig{
		EnvParity: &config.EnvParityConfig{
			Enabled:     true,
			EnvFile:     ".env",
			ExampleFile: ".env.example",
		},
		Security: &config.SecurityConfig{
			Enabled: productionURL != "",
		},
		Secrets: &config.SecretsConfig{
			Enabled: true,
		},
		License: &config.LicenseConfig{
			Enabled: hasLicense,
		},
		AdsTxt: &config.AdsTxtConfig{
			Enabled: hasAds,
		},
		IndexNow: &config.IndexNowConfig{
			Enabled: indexNowKey != "",
			Key:     indexNowKey,
		},
		EmailAuth: &config.EmailAuthConfig{
			Enabled: checkEmailAuth,
		},
		HumansTxt: &config.HumansTxtConfig{
			Enabled: checkHumansTxt,
		},
	}

	// App stacks are expected to expose /health. Other stacks get no block,
	// which runs the lenient check (common paths, then the site itself)
	// whenever a URL is set; writing enabled: false for them would turn it
	// off without the user having chosen that.
	if stackNeedsHealthEndpoint(stack) {
		checks.HealthEndpoint = &config.HealthEndpointConfig{Enabled: true, Path: "/health"}
	}

	// Configure Stripe webhook if Stripe is declared
	if services["stripe"].Declared {
		checks.StripeWebhook = &config.StripeWebhookConfig{
			Enabled: true,
			URL:     "", // User must configure
		}
	}

	// Configure SEO check based on stack
	mainLayout := detectMainLayout(cwd, stack)
	if mainLayout != "" {
		checks.SEOMeta = &config.SEOMetaConfig{
			Enabled:    true,
			MainLayout: mainLayout,
		}
	}

	return checks
}

// writeConfig writes cfg with the 2-space indent `preflight ignore` uses
// when it has to re-encode the file. yaml.Marshal indents by 4, so the
// first edit after init used to reflow every nested line.
func writeConfig(path string, cfg *config.PreflightConfig) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	return fsutil.WriteFile(path, buf.Bytes(), 0644)
}

func formatServiceName(svc string) string {
	return catalog.ServiceName(svc)
}

func formatStackName(stack string) string {
	names := map[string]string{
		// Frameworks
		"rails":   "Ruby on Rails",
		"next":    "Next.js",
		"node":    "Node.js",
		"react":   "React",
		"vue":     "Vue.js",
		"vite":    "Vite",
		"svelte":  "Svelte",
		"angular": "Angular",
		"remix":   "Remix",
		"nuxt":    "Nuxt",
		"laravel": "Laravel",
		"django":  "Django",
		"python":  "Python",
		"go":      "Go",
		"rust":    "Rust",
		"php":     "PHP",
		"static":  "Static Site",

		// Traditional CMS
		"wordpress": "WordPress",
		"craft":     "Craft CMS",
		"drupal":    "Drupal",
		"ghost":     "Ghost",

		// Static Site Generators
		"hugo":     "Hugo",
		"jekyll":   "Jekyll",
		"gatsby":   "Gatsby",
		"eleventy": "Eleventy (11ty)",
		"astro":    "Astro",

		// Headless CMS
		"strapi":     "Strapi",
		"sanity":     "Sanity",
		"contentful": "Contentful",
		"prismic":    "Prismic",
	}
	if name, ok := names[stack]; ok {
		return name
	}
	return stack
}

func detectStackVersion(cwd, stack string) string {
	switch stack {
	case "craft":
		return detectComposerVersion(cwd, "craftcms/cms")
	case "laravel":
		return detectComposerVersion(cwd, "laravel/framework")
	case "drupal":
		return detectComposerVersion(cwd, "drupal/core")
	case "wordpress":
		// Check wp-includes/version.php for WordPress version
		versionFile := filepath.Join(cwd, "wp-includes", "version.php")
		if content, err := fsutil.ReadFile(versionFile, 8<<20); err == nil {
			re := regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)
			if matches := re.FindStringSubmatch(string(content)); len(matches) > 1 {
				return matches[1]
			}
		}
	case "next":
		return detectNpmVersion(cwd, "next")
	case "gatsby":
		return detectNpmVersion(cwd, "gatsby")
	case "astro":
		return detectNpmVersion(cwd, "astro")
	case "eleventy":
		return detectNpmVersion(cwd, "@11ty/eleventy")
	case "hugo":
		// Check hugo.toml or config.toml for version info (usually not present)
		// Hugo version is CLI-based, not project-based
		return ""
	case "jekyll":
		return detectGemVersion(cwd, "jekyll")
	case "rails":
		return detectGemVersion(cwd, "rails")
	case "ghost":
		return detectNpmVersion(cwd, "ghost")
	case "strapi":
		return detectNpmVersion(cwd, "@strapi/strapi")
	case "sanity":
		return detectNpmVersion(cwd, "sanity")
	}
	return ""
}

func detectComposerVersion(cwd, pkg string) string {
	composerLock := filepath.Join(cwd, "composer.lock")
	if content, err := fsutil.ReadFile(composerLock, 8<<20); err == nil {
		var lock struct {
			Packages []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"packages"`
		}
		if json.Unmarshal(content, &lock) == nil {
			for _, p := range lock.Packages {
				if p.Name == pkg {
					return strings.TrimPrefix(p.Version, "v")
				}
			}
		}
	}
	// Fallback to composer.json
	composerJSON := filepath.Join(cwd, "composer.json")
	if content, err := fsutil.ReadFile(composerJSON, 8<<20); err == nil {
		var composer struct {
			Require map[string]string `json:"require"`
		}
		if json.Unmarshal(content, &composer) == nil {
			if version, ok := composer.Require[pkg]; ok {
				return strings.TrimPrefix(version, "^")
			}
		}
	}
	return ""
}

func detectNpmVersion(cwd, pkg string) string {
	packageLock := filepath.Join(cwd, "package-lock.json")
	if content, err := fsutil.ReadFile(packageLock, 8<<20); err == nil {
		var lock struct {
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
			Dependencies map[string]struct {
				Version string `json:"version"`
			} `json:"dependencies"`
		}
		if json.Unmarshal(content, &lock) == nil {
			// Check packages (npm v7+)
			if p, ok := lock.Packages["node_modules/"+pkg]; ok {
				return p.Version
			}
			// Check dependencies (npm v6)
			if d, ok := lock.Dependencies[pkg]; ok {
				return d.Version
			}
		}
	}
	// Fallback to package.json
	packageJSON := filepath.Join(cwd, "package.json")
	if content, err := fsutil.ReadFile(packageJSON, 8<<20); err == nil {
		var pkg2 struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(content, &pkg2) == nil {
			if version, ok := pkg2.Dependencies[pkg]; ok {
				return strings.TrimPrefix(version, "^")
			}
			if version, ok := pkg2.DevDependencies[pkg]; ok {
				return strings.TrimPrefix(version, "^")
			}
		}
	}
	return ""
}

func detectGemVersion(cwd, gem string) string {
	gemfileLock := filepath.Join(cwd, "Gemfile.lock")
	if content, err := fsutil.ReadFile(gemfileLock, 8<<20); err == nil {
		// Parse Gemfile.lock for gem version
		re := regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(gem) + ` \(([^)]+)\)`)
		if matches := re.FindStringSubmatch(string(content)); len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

func generateIndexNowKey() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Could not generate random key: %v\n", err)
		return ""
	}
	return hex.EncodeToString(bytes)
}

func detectIndexNowKey(cwd string) string {
	// First check .env files
	envFiles := []string{".env", ".env.example", ".env.local", ".env.development"}
	keyPatterns := []string{"INDEXNOW_API_KEY=", "INDEXNOW_KEY=", "INDEX_NOW_KEY="}

	for _, envFile := range envFiles {
		path := filepath.Join(cwd, envFile)
		content, err := fsutil.ReadFile(path, 8<<20)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			for _, pattern := range keyPatterns {
				if strings.HasPrefix(strings.ToUpper(line), pattern) {
					// Extract the value after the =
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[1])
						// Remove quotes if present
						key = strings.Trim(key, "\"'")
						if key != "" && key != "your_key_here" {
							return key
						}
					}
				}
			}
		}
	}

	// Also check for existing key files in web root (32-char hex filename.txt)
	webRoots := []string{"public", "web", "static", "_site", "dist", ""}
	hexPattern := regexp.MustCompile(`^[a-f0-9]{32}\.txt$`)

	for _, root := range webRoots {
		dir := filepath.Join(cwd, root)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() && hexPattern.MatchString(entry.Name()) {
				// Found a key file, extract the key from filename
				key := strings.TrimSuffix(entry.Name(), ".txt")
				// Verify file content matches the key
				content, ok := fsutil.ReadRegularFile(filepath.Join(dir, entry.Name()), 1024)
				if ok && strings.TrimSpace(string(content)) == key {
					return key
				}
			}
		}
	}

	// Finally, look for a dynamically served key (source constant, route serving
	// {key}.txt, or a deploy script pinging the API) when no env var or key file
	// exists. Covers apps that serve the key from a handler rather than a file.
	if _, key := config.DetectIndexNowDynamic(cwd); key != "" {
		return key
	}

	return ""
}

// detectWebRoot returns the directory, relative to the project root, whose
// files the site serves at its own root. "." is the project root itself.
func detectWebRoot(cwd, stack string) string {
	// Where each stack keeps files it serves verbatim. The entry is the
	// source directory, never the build output: Jekyll copies files from
	// the project root into _site and wipes _site on every build, and a
	// WordPress install serves its own root.
	stackRoots := map[string]string{
		"rails":     "public",
		"laravel":   "public",
		"next":      "public",
		"node":      "public",
		"craft":     "web",
		"django":    "static",
		"hugo":      "static",
		"jekyll":    ".",
		"gatsby":    "static",
		"astro":     "public",
		"wordpress": ".",
		"drupal":    "web",
		"ghost":     "content",
	}
	if root, ok := stackRoots[stack]; ok {
		return root
	}
	// Eleventy has no fixed static directory. Use the input directory:
	// src when the project has one, else the project root.
	if stack == "eleventy" {
		for _, dir := range []string{"src", "public"} {
			if info, err := os.Stat(filepath.Join(cwd, dir)); err == nil && info.IsDir() {
				return dir
			}
		}
		return "."
	}

	// Check for common web root directories
	commonRoots := []string{"public", "static", "web", "www", "dist", "build", "_site", "out"}
	for _, root := range commonRoots {
		if info, err := os.Stat(filepath.Join(cwd, root)); err == nil && info.IsDir() {
			return root
		}
	}

	// Default to public
	return "public"
}

// stackNeedsHealthEndpoint returns true for application stacks that typically have health endpoints
// CMS and static sites don't need dedicated health endpoints
func stackNeedsHealthEndpoint(stack string) bool {
	appStacks := map[string]bool{
		"rails":   true,
		"node":    true,
		"next":    true,
		"laravel": true,
		"django":  true,
		"python":  true,
		"go":      true,
		"rust":    true,
	}
	return appStacks[stack]
}
