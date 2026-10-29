package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/preflightsh/preflight/internal/catalog"
	"github.com/preflightsh/preflight/internal/fsutil"

	"gopkg.in/yaml.v3"
)

type PreflightConfig struct {
	ProjectName string                   `yaml:"projectName"`
	Stack       string                   `yaml:"stack"`
	URLs        URLConfig                `yaml:"urls,omitempty"`
	Services    map[string]ServiceConfig `yaml:"services,omitempty"`
	Checks      ChecksConfig             `yaml:"checks,omitempty"`
	Ignore      []string                 `yaml:"ignore,omitempty"`
}

type URLConfig struct {
	Staging    string `yaml:"staging,omitempty"`
	Production string `yaml:"production,omitempty"`
}

type ServiceConfig struct {
	Declared bool `yaml:"declared"`
}

type ChecksConfig struct {
	EnvParity      *EnvParityConfig      `yaml:"envParity,omitempty"`
	HealthEndpoint *HealthEndpointConfig `yaml:"healthEndpoint,omitempty"`
	StripeWebhook  *StripeWebhookConfig  `yaml:"stripeWebhook,omitempty"`
	SEOMeta        *SEOMetaConfig        `yaml:"seoMeta,omitempty"`
	Security       *SecurityConfig       `yaml:"security,omitempty"`
	Secrets        *SecretsConfig        `yaml:"secrets,omitempty"`
	AdsTxt         *AdsTxtConfig         `yaml:"adsTxt,omitempty"`
	License        *LicenseConfig        `yaml:"license,omitempty"`
	IndexNow       *IndexNowConfig       `yaml:"indexNow,omitempty"`
	EmailAuth      *EmailAuthConfig      `yaml:"emailAuth,omitempty"`
	HumansTxt      *HumansTxtConfig      `yaml:"humansTxt,omitempty"`
}

type EnvParityConfig struct {
	Enabled     bool   `yaml:"enabled"`
	EnvFile     string `yaml:"envFile"`
	ExampleFile string `yaml:"exampleFile"`
}

type HealthEndpointConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

type StripeWebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
}

type SEOMetaConfig struct {
	Enabled    bool   `yaml:"enabled"`
	MainLayout string `yaml:"mainLayout"`
}

type SecurityConfig struct {
	Enabled bool `yaml:"enabled"`
}

type SecretsConfig struct {
	Enabled   bool                   `yaml:"enabled"`
	Allowlist []SecretAllowlistEntry `yaml:"allowlist,omitempty"`
}

type SecretAllowlistEntry struct {
	Path        string `yaml:"path"`
	Fingerprint string `yaml:"fingerprint,omitempty"`
	Reason      string `yaml:"reason,omitempty"`
}

type AdsTxtConfig struct {
	Enabled bool `yaml:"enabled"`
}

type LicenseConfig struct {
	Enabled bool `yaml:"enabled"`
}

type IndexNowConfig struct {
	Enabled bool   `yaml:"enabled"`
	Key     string `yaml:"key"`
}

type EmailAuthConfig struct {
	Enabled bool   `yaml:"enabled"`
	Domain  string `yaml:"domain,omitempty"`
}

type HumansTxtConfig struct {
	Enabled bool `yaml:"enabled"`
}

// Load reads and parses the preflight.yml config file
func Load(rootDir string) (*PreflightConfig, error) {
	configPath := filepath.Join(rootDir, "preflight.yml")

	data, err := fsutil.ReadFile(configPath, 8<<20)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("preflight.yml not found in %s", rootDir)
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// Unknown keys are an error. Without this a misspelled key such as
	// healthEndpont: is silently ignored, the check quietly never runs,
	// and nothing tells the user. Failing here maps to the usage exit
	// code, which is the contract for "preflight could not run".
	var cfg PreflightConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to parse preflight.yml: %w", err)
	}

	// Apply defaults
	applyDefaults(&cfg)
	if err := Validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid preflight.yml: %w", err)
	}

	return &cfg, nil
}

// Validate checks values that yaml's KnownFields cannot validate, including
// map keys and ignore IDs. Source-file globs remain supported for debug checks.
func Validate(cfg *PreflightConfig) error {
	for id := range cfg.Services {
		if _, ok := catalog.LookupService(id); !ok {
			return fmt.Errorf("unknown service ID %q", id)
		}
	}
	for _, id := range cfg.Ignore {
		current := catalog.Canonical(id)
		_, check := catalog.LookupCheck(current)
		_, service := catalog.LookupService(current)
		if check || service {
			continue
		}
		if !strings.ContainsAny(id, "/*?[.") || !doublestar.ValidatePattern(filepath.ToSlash(id)) {
			return fmt.Errorf("unknown check ID or invalid glob %q", id)
		}
	}
	if c := cfg.Checks.Secrets; c != nil {
		for _, entry := range c.Allowlist {
			if entry.Path == "" || !doublestar.ValidatePattern(filepath.ToSlash(entry.Path)) {
				return fmt.Errorf("invalid secrets allowlist path %q", entry.Path)
			}
		}
	}
	if c := cfg.Checks.EmailAuth; c != nil && c.Enabled {
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.Domain)), ".")
		if domain == "" {
			c.Domain = ""
			return nil
		}
		if strings.ContainsAny(domain, "/:@ ?#") || !strings.Contains(domain, ".") {
	// An empty emailAuth.domain is left to the check, which reports it as
	// an inconclusive warning. Rejecting it here failed every scan of a
	// pre-0.24 config that had emailAuth enabled, since those had no
	// domain key.
			return fmt.Errorf("emailAuth.domain must name the email sending domain, e.g. mail.example.com")
		}
		for _, label := range strings.Split(domain, ".") {
			if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return fmt.Errorf("invalid emailAuth.domain")
			}
			for _, r := range label {
				letter := r >= 'a' && r <= 'z'
				digit := r >= '0' && r <= '9'
				if !letter && !digit && r != '-' {
					return fmt.Errorf("emailAuth.domain must be an ASCII DNS name")
				}
			}
		}
		c.Domain = domain
	}
	return nil
}

func applyDefaults(cfg *PreflightConfig) {
	// init writes URLs with a scheme, but a hand-edited "production:
	// example.com" used to cascade into a dozen false errors (SSL "does not
	// use HTTPS", every page "missing").
	cfg.URLs.Staging = NormalizeURL(cfg.URLs.Staging)
	cfg.URLs.Production = NormalizeURL(cfg.URLs.Production)

	if cfg.Stack == "" {
		cfg.Stack = "unknown"
	}

	if cfg.Checks.EnvParity != nil {
		if cfg.Checks.EnvParity.EnvFile == "" {
			cfg.Checks.EnvParity.EnvFile = ".env"
		}
		if cfg.Checks.EnvParity.ExampleFile == "" {
			cfg.Checks.EnvParity.ExampleFile = ".env.example"
		}
	}

	if cfg.Checks.HealthEndpoint != nil {
		if cfg.Checks.HealthEndpoint.Path == "" {
			cfg.Checks.HealthEndpoint.Path = "/health"
		}
	}
}

// NormalizeURL adds a scheme to a URL written without one: http:// for
// localhost and 127.0.0.1, https:// for everything else. A URL that already
// has a scheme is returned unchanged.
func NormalizeURL(url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return ""
	}
	if strings.Contains(url, "://") {
		return url
	}
	if strings.HasPrefix(url, "localhost") || strings.HasPrefix(url, "127.0.0.1") {
		return "http://" + url
	}
	return "https://" + url
}
