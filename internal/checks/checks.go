package checks

import (
	"net/http"
	"strings"

	"github.com/preflightsh/preflight/internal/config"
)

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
}

type Context struct {
	RootDir string
	Config  *config.PreflightConfig
	Client  *http.Client
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
}

// isLocalURL checks if a URL points to localhost or local IP
func isLocalURL(url string) bool {
	url = strings.ToLower(url)
	return strings.Contains(url, "localhost") ||
		strings.Contains(url, "127.0.0.1") ||
		strings.Contains(url, "0.0.0.0") ||
		strings.HasSuffix(url, ".local") ||
		strings.HasSuffix(url, ".test") ||
		strings.HasSuffix(url, ".ddev.site")
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
	if isLocalURL(url) && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
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
	if isLocalURL(url) {
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
