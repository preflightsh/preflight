package checks

import (
	"net/http"

	"github.com/phillips-jon/preflight/internal/config"
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
	SEOMetadataCheck{},
	SecurityHeadersCheck{},
	SecretScanCheck{},
}
