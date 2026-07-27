package checks

import (
	"context"
	"fmt"
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
	// Ctx is the scan-wide cancellation context. Checks that make
	// network requests must thread this into http.NewRequestWithContext
	// so the scan can be aborted by signal (SIGINT, SIGTERM) without
	// leaving in-flight requests dangling. A nil Ctx is treated as
	// context.Background() by the HTTP helpers below.
	Ctx     context.Context
	RootDir string
	Config  *config.PreflightConfig
	Client  *http.Client
	Verbose bool
	// PageHTMLStaging and PageHTMLProduction hold the rendered homepage
	// HTML for each configured environment, fetched once at scan start.
	// Each is empty when the corresponding URL isn't configured or the
	// fetch failed. Checks that look for dynamically-generated metadata
	// (Craft+SEOmatic, WordPress+Yoast, etc.) scan these to detect output
	// that doesn't appear in the static template. Checks that care about
	// per-environment differences (SEO meta, canonical, structured data,
	// OG/Twitter) report each env separately.
	PageHTMLStaging    string
	PageHTMLProduction string
	// PageFetchStaging and PageFetchProduction carry everything else the
	// homepage request returned: the status, the response headers and the
	// URL actually requested. They let checks tell a host that refused the
	// scan (bot protection answering 403, an auth wall, a rate limit) from
	// one that is genuinely unreachable, and let a check that would
	// otherwise re-request the homepage reuse this one instead, so every
	// row agrees about a host that is slow, blocked or down.
	PageFetchStaging    PageFetch
	PageFetchProduction PageFetch
	// PageHTML is the first-available rendered homepage HTML (staging
	// preferred). Convenience for env-agnostic checks like favicon
	// detection that don't care which environment the markup came from.
	PageHTML string
}

// reqContext returns ctx.Ctx if set, otherwise context.Background(). Lets
// helpers be called from places (tests, init flows) where the scan
// context hasn't been wired up.
func (c Context) reqContext() context.Context {
	if c.Ctx == nil {
		return context.Background()
	}
	return c.Ctx
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
	CookieConsentJSCheck,
	CookiebotCheck{},
	OneTrustCheck{},
	TermlyCheck{},
	CookieYesCheck{},
	IubendaCheck{},
	// Payment checks
	PayPalCheck,
	BraintreeCheck,
	PaddleCheck,
	LemonSqueezyCheck,
	// Email Marketing checks
	MailchimpCheck,
	ConvertKitCheck,
	BeehiivCheck,
	AWeberCheck,
	ActiveCampaignCheck,
	CampaignMonitorCheck,
	DripCheck,
	KlaviyoCheck,
	ButtondownCheck,
	// Transactional Email checks
	PostmarkCheck{},
	SendGridCheck{},
	MailgunCheck{},
	ResendCheck{},
	AWSSESCheck{},
	// Auth checks
	Auth0Check,
	ClerkCheck,
	WorkOSCheck,
	FirebaseCheck,
	SupabaseCheck,
	// Communication checks
	TwilioCheck,
	SlackCheck,
	DiscordCheck,
	IntercomCheck,
	CrispCheck,
	// Infrastructure checks
	RabbitMQCheck,
	ElasticsearchCheck,
	ConvexCheck,
	// Storage & CDN checks
	AWSS3Check,
	CloudinaryCheck,
	CloudflareCheck,
	// Search checks
	AlgoliaCheck,
	// AI checks
	OpenAICheck,
	AnthropicCheck,
	GoogleAICheck,
	MistralCheck,
	CohereCheck,
	ReplicateCheck,
	HuggingFaceCheck,
	GrokCheck,
	PerplexityCheck,
	TogetherAICheck,
	// Analytics (extended)
	UmamiCheck,
	FullresCheck,
	DatafastCheck,
	PostHogCheck,
	MixpanelCheck,
	HotjarCheck,
	AmplitudeCheck,
	SegmentCheck,
	// Error Tracking (extended)
	BugsnagCheck,
	RollbarCheck,
	HoneybadgerCheck,
	DatadogCheck,
	NewRelicCheck,
	LogRocketCheck,
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

// blockedStatus reports whether a status means the host refused to serve
// the scanner rather than the site being down. Bot protection (Cloudflare
// answers 403 with a cf-mitigated challenge page), auth walls and rate
// limits all return a real response whose headers and markup belong to the
// edge rather than to the app, so checks must report them as blocked
// instead of measuring the block page.
func blockedStatus(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return true
	}
	return false
}

// fetchFailure renders the per-env note for a fetch that produced no usable
// page, naming the status so "the WAF is blocking us" doesn't read as "the
// site is down".
func fetchFailure(status int) string {
	switch {
	case status == 0:
		return "unreachable"
	case blockedStatus(status):
		return fmt.Sprintf("blocked (HTTP %d)", status)
	default:
		return fmt.Sprintf("unreachable (HTTP %d)", status)
	}
}

// PerEnvResult is one environment's outcome from a per-env check.
type PerEnvResult struct {
	Name    string   // "prod" or "staging"
	Missing []string // items not found; empty means env passed
	Failed  bool     // true on either unreachable OR missing items
}

// RunPerEnv invokes scanRenderedHTML against each configured environment's
// rendered homepage HTML and reports per-env results. Production is listed
// first because it's treated as the authoritative source of truth: callers
// generally want to pass when production has the metadata, even if
// staging is intentionally different (SEOmatic dev mode, robots=none,
// etc.). authoritativePassed reflects production's outcome, or staging's
// when production isn't configured. unreachable envs are surfaced
// verbatim but never flip authoritativePassed to true.
func RunPerEnv(ctx Context, scanRenderedHTML func(html string) []string) (summary string, authoritativePassed bool) {
	type envR struct {
		name   string
		html   string
		status int
	}
	var envs []envR
	if ctx.Config.URLs.Production != "" {
		envs = append(envs, envR{name: "prod", html: ctx.PageHTMLProduction, status: ctx.PageFetchProduction.Status})
	}
	if ctx.Config.URLs.Staging != "" {
		envs = append(envs, envR{name: "staging", html: ctx.PageHTMLStaging, status: ctx.PageFetchStaging.Status})
	}
	if len(envs) == 0 {
		return "", false
	}
	var lines []string
	for i, e := range envs {
		if e.html == "" {
			lines = append(lines, fmt.Sprintf("%s: %s", e.name, fetchFailure(e.status)))
			continue
		}
		missing := scanRenderedHTML(e.html)
		if len(missing) == 0 {
			lines = append(lines, fmt.Sprintf("%s: ✓", e.name))
			if i == 0 {
				authoritativePassed = true
			}
		} else {
			lines = append(lines, fmt.Sprintf("%s missing: %s", e.name, strings.Join(missing, ", ")))
		}
	}
	return strings.Join(lines, "\n                    └─ "), authoritativePassed
}

// PageFetch describes how a homepage request went, apart from the body.
// A zero value means no request was made; Attempted separates that from a
// request that was made and got nothing back.
type PageFetch struct {
	// URL actually requested, with the protocol resolved for local URLs
	// that were configured without one.
	URL string
	// Status is the HTTP status, or 0 when nothing answered.
	Status int
	// Headers is nil unless a response arrived.
	Headers http.Header
}

// Attempted reports whether a request was made for this environment,
// however it went. Checks use it to avoid re-requesting a page the scan
// already failed to fetch.
func (f PageFetch) Attempted() bool { return f.URL != "" }

// FetchPage fetches a single URL's body and reports how the request went.
// html is empty unless the response was usable, so callers can separate
// "nothing there" from "the host answered but refused us". Body is capped
// at netutil.MaxResponseBody. The caller picks the client so
// SafeHTTPClient can guard fetches to production URLs while a relaxed
// client can reach local dev URLs. A nil ctx is treated as
// context.Background().
func FetchPage(ctx context.Context, client *http.Client, rawURL string) (html string, fetch PageFetch) {
	if rawURL == "" {
		return "", PageFetch{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	baseURL := strings.TrimSuffix(rawURL, "/")
	resp, requested, err := tryURL(ctx, client, baseURL+"/")
	fetch = PageFetch{URL: requested}
	if err != nil {
		return "", fetch
	}
	defer resp.Body.Close()
	fetch.Status = resp.StatusCode
	fetch.Headers = resp.Header
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", fetch
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, netutil.MaxResponseBody))
	if err != nil {
		return "", fetch
	}
	return string(body), fetch
}

// FetchPageHTML is FetchPage for callers that only need the body.
func FetchPageHTML(ctx context.Context, client *http.Client, rawURL string) string {
	html, _ := FetchPage(ctx, client, rawURL)
	return html
}

// doGet performs an HTTP GET with a User-Agent header. A nil ctx is
// treated as context.Background().
func doGet(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Preflight/1.0")
	return client.Do(req)
}

// tryURL attempts to reach a URL, trying both protocols for local URLs.
// A nil ctx is treated as context.Background().
func tryURL(ctx context.Context, client *http.Client, url string) (*http.Response, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// If it's a local URL without protocol, try both
	if IsLocalURL(url) && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		// Try https first (for ddev, etc.)
		httpsURL := "https://" + url
		resp, err := doGet(ctx, client, httpsURL)
		if err == nil {
			return resp, httpsURL, nil
		}

		// Fall back to http
		httpURL := "http://" + url
		resp, err = doGet(ctx, client, httpURL)
		if err == nil {
			return resp, httpURL, nil
		}
		return nil, url, err
	}

	// If it already has a protocol, or it's a local URL with protocol, just try it
	// But for local URLs, also try the alternate protocol
	if IsLocalURL(url) {
		resp, err := doGet(ctx, client, url)
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
			resp, err = doGet(ctx, client, altURL)
			if err == nil {
				return resp, altURL, nil
			}
		}
		return nil, url, err
	}

	// Non-local URL, just try it directly
	resp, err := doGet(ctx, client, url)
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

	// reProtocolRelative matches the leading "//" of a protocol-relative
	// URL (src="//cdn.example.com/x.js"). Unlike a scheme, the only thing
	// marking it as a URL rather than a comment is the quote or "=" that
	// introduces it.
	reProtocolRelative = regexp.MustCompile(`([="'])//`)
)

// URL slashes are indistinguishable from a "//" line comment to a regex:
// without protection, reSingleLineComment turns
//
//	<link rel="canonical" href="https://example.com/">
//
// into `<link rel="canonical" href="https:` and every downstream pattern
// silently stops matching. Hide the slashes behind sentinels for the
// duration of the strip and restore them afterwards. NUL bytes never
// appear in the templates we scan, so the sentinels cannot collide with
// real content.
const (
	urlSchemeSentinel = "\x00preflight-scheme\x00"
	urlSlashSentinel  = "\x00preflight-slashes\x00"
)

func protectURLSlashes(content string) string {
	content = strings.ReplaceAll(content, "://", urlSchemeSentinel)
	return reProtocolRelative.ReplaceAllString(content, "${1}"+urlSlashSentinel)
}

func restoreURLSlashes(content string) string {
	content = strings.ReplaceAll(content, urlSchemeSentinel, "://")
	return strings.ReplaceAll(content, urlSlashSentinel, "//")
}

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
	content = protectURLSlashes(content)
	content = reSingleLineComment.ReplaceAllString(content, "")
	content = reMultiLineComment.ReplaceAllString(content, "")
	content = reHTMLComment.ReplaceAllString(content, "")
	content = reTwigComment.ReplaceAllString(content, "")
	content = reERBComment.ReplaceAllString(content, "")
	return restoreURLSlashes(content)
}
