package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type PreflightConfig struct {
	ProjectName string                   `yaml:"projectName"`
	Stack       string                   `yaml:"stack"`
	URLs        URLConfig                `yaml:"urls,omitempty"`
	Services    map[string]ServiceConfig `yaml:"services,omitempty"`
	Checks      ChecksConfig             `yaml:"checks,omitempty"`
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
	Sentry         *SentryConfig         `yaml:"sentry,omitempty"`
	Plausible      *PlausibleConfig      `yaml:"plausible,omitempty"`
	Security       *SecurityConfig       `yaml:"security,omitempty"`
	Secrets        *SecretsConfig        `yaml:"secrets,omitempty"`
	AdsTxt         *AdsTxtConfig         `yaml:"adsTxt,omitempty"`
	License        *LicenseConfig        `yaml:"license,omitempty"`
	IndexNow       *IndexNowConfig       `yaml:"indexNow,omitempty"`
	EmailAuth      *EmailAuthConfig      `yaml:"emailAuth,omitempty"`
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

type SentryConfig struct {
	Enabled bool `yaml:"enabled"`
}

type PlausibleConfig struct {
	Enabled bool `yaml:"enabled"`
}

type SecurityConfig struct {
	Enabled bool `yaml:"enabled"`
}

type SecretsConfig struct {
	Enabled bool `yaml:"enabled"`
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
	Enabled bool `yaml:"enabled"`
}

// Load reads and parses the preflight.yml config file
func Load(rootDir string) (*PreflightConfig, error) {
	configPath := filepath.Join(rootDir, "preflight.yml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("preflight.yml not found in %s", rootDir)
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg PreflightConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse preflight.yml: %w", err)
	}

	// Apply defaults
	applyDefaults(&cfg)

	return &cfg, nil
}

func applyDefaults(cfg *PreflightConfig) {
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
