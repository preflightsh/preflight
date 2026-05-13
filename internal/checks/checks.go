package checks

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/preflightsh/preflight/internal/config"
	"github.com/preflightsh/preflight/internal/netutil"
)

func relPath(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		// Fall back to filepath.Base so we never leak the full absolute
		// path (which typically contains the user's home directory) into
		// user-facing output.
		return filepath.Base(target)
	}
	return rel
}

type Severity string

const (
	SeverityInfo  Severity = "info"
	SeverityWarn  Severity = "warn"
	SeverityError Severity = "error"
)

type CheckResult struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Passed      bool     `json:"passed"`
	Message     string   `json:"message"`
	Suggestions []string `json:"suggestions,omitempty"`
	Details     []string `json:"details,omitempty"` // Verbose output details
}

type Context struct {
	RootDir string
	Config  *config.PreflightConfig
	Client  *http.Client
	Verbose bool
	// PageHTML is the rendered HTML of the configured site's homepage,
	// fetched once at scan start. Empty when no URL is configured, the
	// site is unreachable, or fetching is skipped. Checks that look for
	// dynamically-generated meta tags (Craft+SEOmatic, WordPress+Yoast,
	// etc.) can use this as a fallback when static template scanning
	// turns up nothing.
	PageHTML string
}

type Check interface {
	ID() string
	Title() string
	Run(ctx Context) (CheckResult, error)
}

// Registry of all available checks
var Registry = []Check{
	EnvParityCheck{},
	HealthCheck{},
	StripeWebhookCheck{},
	SentryCheck{},
	PlausibleCheck{},
	FathomCheck{},
	GoogleAnalyticsCheck{},
	RedisCheck{},
	SidekiqCheck{},
	SEOMetadataCheck{},
	OGTwitterCheck{},
	SecurityHeadersCheck{},
	SSLCheck{},
	SecretScanCheck{},
	VulnerabilityCheck{},
	FaviconCheck{},
	RobotsTxtCheck{},
	SitemapCheck{},
	LLMsTxtCheck{},
	AdsTxtCheck{},
	LicenseCheck{},
	ErrorPagesCheck{},
	CanonicalURLCheck{},
	ViewportCheck{},
	LangAttributeCheck{},
	DebugStatementsCheck{},
	StructuredDataCheck{},
	ImageOptimizationCheck{},
	EmailAuthCheck{},
	HumansTxtCheck{},
	WWWRedirectCheck{},
	LegalPagesCheck{},
	IndexNowCheck{},
	// Cookie Consent checks
	CookieConsentJSCheck{},
	CookiebotCheck{},
	OneTrustCheck{},
	TermlyCheck{},
	CookieYesCheck{},
	IubendaCheck{},
	// Payment checks
	PayPalCheck{},
	BraintreeCheck{},
	PaddleCheck{},
	LemonSqueezyCheck{},
	// Email Marketing checks
	MailchimpCheck{},
	ConvertKitCheck{},
	BeehiivCheck{},
	AWeberCheck{},
	ActiveCampaignCheck{},
	CampaignMonitorCheck{},
	DripCheck{},
	KlaviyoCheck{},
	ButtondownCheck{},
	// Transactional Email checks
	PostmarkCheck{},
	SendGridCheck{},
	MailgunCheck{},
	ResendCheck{},
	AWSSESCheck{},
	// Auth checks
	Auth0Check{},
	ClerkCheck{},
	WorkOSCheck{},
	FirebaseCheck{},
	SupabaseCheck{},
	// Communication checks
	TwilioCheck{},
	SlackCheck{},
	DiscordCheck{},
	IntercomCheck{},
	CrispCheck{},
	// Infrastructure checks
	RabbitMQCheck{},
	ElasticsearchCheck{},
	ConvexCheck{},
	// Storage & CDN checks
	AWSS3Check{},
	CloudinaryCheck{},
	CloudflareCheck{},
	// Search checks
	AlgoliaCheck{},
	// AI checks
	OpenAICheck{},
	AnthropicCheck{},
	GoogleAICheck{},
	MistralCheck{},
	CohereCheck{},
	ReplicateCheck{},
	HuggingFaceCheck{},
	GrokCheck{},
	PerplexityCheck{},
	TogetherAICheck{},
	// Analytics (extended)
	UmamiCheck{},
	FullresCheck{},
	DatafastCheck{},
	PostHogCheck{},
	MixpanelCheck{},
	HotjarCheck{},
	AmplitudeCheck{},
	SegmentCheck{},
	// Error Tracking (extended)
	BugsnagCheck{},
	RollbarCheck{},
	HoneybadgerCheck{},
	DatadogCheck{},
	NewRelicCheck{},
	LogRocketCheck{},
}

// IsLocalURL reports whether rawURL points at a developer's own machine
// or a local-only TLD that conventionally maps to it (mDNS, ddev, etc.).
// Uses strict hostname parsing rather than substring search on the whole
// URL, so it cannot be tricked by patterns like
// "https://localhost.attacker.com/" or "https://attacker.com/?h=127.0.0.1"
// — this matters when callers use IsLocalURL as a security gate (see
// cmd/scan.go's choice of HTTP client).
func IsLocalURL(rawURL string) bool {
	candidate := rawURL
	if !strings.HasPrefix(candidate, "http://") && !strings.HasPrefix(candidate, "https://") {
		candidate = "http://" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return false
	}
	switch host {
	case "localhost", "127.0.0.1", "0.0.0.0", "::1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	for _, tld := range []string{".local", ".test", ".localhost", ".ddev.site", ".lndo.site"} {
		if strings.HasSuffix(host, tld) {
			return true
		}
	}
	return false
}

// FetchPageHTML fetches the homepage of the configured site (prefers
// staging, falls back to production) and returns its body as a string.
// Used to populate Context.PageHTML so multiple checks can scan the
// rendered HTML without each making their own request. Body is capped at
// netutil.MaxResponseBody. Returns empty string on any error.
func FetchPageHTML(client *http.Client, cfg *config.PreflightConfig) string {
	var baseURL string
	if cfg.URLs.Staging != "" {
		baseURL = cfg.URLs.Staging
	} else if cfg.URLs.Production != "" {
		baseURL = cfg.URLs.Production
	}
	if baseURL == "" {
		return ""
	}
	baseURL = strings.TrimSuffix(baseURL, "/")
	resp, _, err := tryURL(client, baseURL+"/")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, netutil.MaxResponseBody))
	if err != nil {
		return ""
	}
	return string(body)
}

// doGet performs an HTTP GET with a User-Agent header
func doGet(client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Preflight/1.0")
	return client.Do(req)
}

// tryURL attempts to reach a URL, trying both protocols for local URLs
func tryURL(client *http.Client, url string) (*http.Response, string, error) {
	// If it's a local URL without protocol, try both
	if IsLocalURL(url) && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		// Try https first (for ddev, etc.)
		httpsURL := "https://" + url
		resp, err := doGet(client, httpsURL)
		if err == nil {
			return resp, httpsURL, nil
		}

		// Fall back to http
		httpURL := "http://" + url
		resp, err = doGet(client, httpURL)
		if err == nil {
			return resp, httpURL, nil
		}
		return nil, url, err
	}

	// If it already has a protocol, or it's a local URL with protocol, just try it
	// But for local URLs, also try the alternate protocol
	if IsLocalURL(url) {
		resp, err := doGet(client, url)
		if err == nil {
			return resp, url, nil
		}

		// Try alternate protocol
		var altURL string
		if strings.HasPrefix(url, "http://") {
			altURL = "https://" + strings.TrimPrefix(url, "http://")
		} else if strings.HasPrefix(url, "https://") {
			altURL = "http://" + strings.TrimPrefix(url, "https://")
		}

		if altURL != "" {
			resp, err = doGet(client, altURL)
			if err == nil {
				return resp, altURL, nil
			}
		}
		return nil, url, err
	}

	// Non-local URL, just try it directly
	resp, err := doGet(client, url)
	return resp, url, err
}

// Comment-stripping regexes, compiled once at package init.
var (
	reSingleLineComment = regexp.MustCompile(`//[^\n]*`)
	reMultiLineComment  = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reHTMLComment       = regexp.MustCompile(`(?s)<!--.*?-->`)
	reTwigComment       = regexp.MustCompile(`(?s)\{#.*?#\}`)
	reERBComment        = regexp.MustCompile(`(?s)<%#.*?%>`)
	reHashLineComment   = regexp.MustCompile(`(?m)^\s*#[^{].*$`)
)

// stripComments removes common comment syntax from code to avoid false
// positives when pattern matching. Supports JS/TS, HTML, Twig/Jinja,
// ERB, PHP, and shell/Python/Ruby style comments.
func stripComments(content string) string {
	content = stripCodeComments(content)
	content = reHashLineComment.ReplaceAllString(content, "")
	return content
}

// stripCodeComments removes only the language-specific block and line
// comments (JS/HTML/Twig/ERB). It does not touch hash-style comments,
// which makes it safer for content that legitimately uses `#` at line
// starts (CSS selectors, YAML keys, etc.).
func stripCodeComments(content string) string {
	content = reSingleLineComment.ReplaceAllString(content, "")
	content = reMultiLineComment.ReplaceAllString(content, "")
	content = reHTMLComment.ReplaceAllString(content, "")
	content = reTwigComment.ReplaceAllString(content, "")
	content = reERBComment.ReplaceAllString(content, "")
	return content
}
