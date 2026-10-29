package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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

	// Notes are messages about how the file was read (a legacy shape kept
	// working, an entry that does nothing) for the caller to print on
	// stderr. They are never written back to the file.
	Notes []string `yaml:"-"`
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
	// EnabledSet records that the file had an enabled key. Health runs by
	// default when a URL is set, so a block that only names a path must not
	// read as enabled: false.
	EnabledSet bool `yaml:"-"`
}

// Resolve reports whether the health check runs, given whether it runs by
// default. Only an explicit enabled: false turns a default-on check off.
func (c *HealthEndpointConfig) Resolve(byDefault bool) bool {
	if c == nil || (!c.Enabled && !c.EnabledSet) {
		return byDefault
	}
	return c.Enabled
}

type StripeWebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
}

type SEOMetaConfig struct {
	Enabled    bool   `yaml:"enabled"`
	MainLayout string `yaml:"mainLayout"`
	// EnabledSet records that the file had an enabled key; see
	// HealthEndpointConfig.EnabledSet.
	EnabledSet bool `yaml:"-"`
}

// Resolve reports whether the SEO checks run, given whether they run by
// default. A block that names a layout without an enabled key runs them.
func (c *SEOMetaConfig) Resolve(byDefault bool) bool {
	if c == nil || (!c.Enabled && !c.EnabledSet) {
		return byDefault || (c != nil && c.MainLayout != "")
	}
	return c.Enabled
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
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err == nil {
		markExplicitEnabled(&cfg, &doc)
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
	if err := validateServices(cfg); err != nil {
		return err
	}
	for _, id := range cfg.Ignore {
		if err := catalog.RenamedError(id); err != nil {
			return err
		}
		current := catalog.Canonical(id)
		_, check := catalog.LookupCheck(current)
		_, service := catalog.LookupService(current)
		if check || service {
			continue
		}
		if strings.ContainsAny(id, "/*?[.") {
			if !doublestar.ValidatePattern(filepath.ToSlash(id)) {
				return fmt.Errorf("invalid glob %q in ignore", id)
			}
			continue
		}
		// v0.23 loaded any entry, and the source scans read every entry
		// as a path pattern, so a bare word still loads. It matches only
		// a file of that name at the project root, which is rarely what
		// was meant, so say so.
		note := fmt.Sprintf("ignore entry %q is not a check or service ID, so it only skips a file named %q at the project root in source scans", id, id)
		if near := catalog.Suggest(id); near != "" {
			note += fmt.Sprintf("; did you mean %q?", near)
		} else {
			note += fmt.Sprintf("; use %q to skip a directory", id+"/**")
		}
		cfg.Notes = append(cfg.Notes, note)
	}
	if c := cfg.Checks.Secrets; c != nil {
		for _, entry := range c.Allowlist {
			if entry.Path == "" || !doublestar.ValidatePattern(filepath.ToSlash(entry.Path)) {
				return fmt.Errorf("invalid secrets allowlist path %q", entry.Path)
			}
		}
	}
	// An empty emailAuth.domain is left to the check, which falls back to
	// the production URL's domain as v0.23 did. Rejecting it here failed
	// every scan of a pre-0.24 config that had emailAuth enabled, since
	// those had no domain key.
	if c := cfg.Checks.EmailAuth; c != nil && c.Enabled {
		if err := validateMailDomain(c); err != nil {
			return err
		}
	}
	return nil
}

// validateMailDomain normalizes checks.emailAuth.domain and rejects one
// that is not a plain ASCII DNS name. An empty domain is valid.
func validateMailDomain(c *EmailAuthConfig) error {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.Domain)), ".")
	c.Domain = domain
	if domain == "" {
		return nil
	}
	if strings.ContainsAny(domain, "/:@ ?#") || !strings.Contains(domain, ".") {
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
	return nil
}

// serviceRenames maps service IDs that preflight init once wrote to their
// current IDs. init v0.2.1 through v0.3.0 wrote the xAI service as groq.
var serviceRenames = map[string]string{
	"groq": "grok",
}

// validateServices resolves renamed service IDs and rejects unknown ones
// that are declared. Service IDs are map keys rather than schema keys:
// init writes every service it knows with declared: false, so a config
// from a newer Preflight lists services this one has never heard of, and
// those are harmless. A declared unknown service is most likely a typo
// that would silently skip the check the user asked for, so it fails.
func validateServices(cfg *PreflightConfig) error {
	ids := make([]string, 0, len(cfg.Services))
	for id := range cfg.Services {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var unknown []string
	for _, id := range ids {
		svc := cfg.Services[id]
		if current, ok := serviceRenames[id]; ok {
			merged := cfg.Services[current]
			merged.Declared = merged.Declared || svc.Declared
			cfg.Services[current] = merged
			delete(cfg.Services, id)
			cfg.Notes = append(cfg.Notes, fmt.Sprintf("service ID %q is now %q; rename it under services: in preflight.yml.", id, current))
			continue
		}
		if _, ok := catalog.LookupService(id); ok {
			continue
		}
		if svc.Declared {
			msg := fmt.Sprintf("unknown service ID %q under services:", id)
			if near := catalog.Suggest(id); near != "" {
				msg += fmt.Sprintf(" (did you mean %q?)", near)
			}
			return fmt.Errorf("%s; run 'preflight checks' to list service IDs, or upgrade if this config came from a newer Preflight", msg)
		}
		unknown = append(unknown, id)
		delete(cfg.Services, id)
	}
	if len(unknown) > 0 {
		cfg.Notes = append(cfg.Notes, fmt.Sprintf("skipping undeclared service IDs this version does not know: %s (a newer Preflight may support them).", strings.Join(unknown, ", ")))
	}
	return nil
}

// markExplicitEnabled sets EnabledSet on the default-on check blocks whose
// enabled key is present in the file. The typed decode cannot tell a
// missing key from enabled: false.
func markExplicitEnabled(cfg *PreflightConfig, doc *yaml.Node) {
	checks := nodeAt(doc, "checks")
	if h := cfg.Checks.HealthEndpoint; h != nil {
		block := nodeAt(checks, "healthEndpoint")
		h.EnabledSet = nodeAt(block, "enabled") != nil
		// preflight init wrote exactly this block for CMS and static
		// stacks without asking, and before 0.24 it did not stop the check
		// running when a URL was set. It cannot be told apart from a
		// deliberate opt-out, so it keeps its old meaning and says how to
		// turn the check off.
		if h.EnabledSet && !h.Enabled && h.Path == "/health" && len(block.Content) == 4 {
			h.EnabledSet = false
			cfg.Notes = append(cfg.Notes, "checks.healthEndpoint has enabled: false with the default path, which preflight init used to write for CMS and static sites. "+
				"health_endpoint still runs when a URL is set, as it did before 0.24; run 'preflight ignore health_endpoint' to turn it off, or delete the block to silence this note.")
		}
	}
	if s := cfg.Checks.SEOMeta; s != nil {
		s.EnabledSet = nodeAt(nodeAt(checks, "seoMeta"), "enabled") != nil
	}
}

// nodeAt returns the value under key in a mapping node (or in a document
// node's top-level mapping), or nil.
func nodeAt(n *yaml.Node, key string) *yaml.Node {
	if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
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
