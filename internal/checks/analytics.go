package checks

import (
	"os"
	"path/filepath"
)

// serviceDeclared reports whether preflight.yml declares the service.
func serviceDeclared(ctx Context, id string) bool {
	service, ok := ctx.Config.Services[id]
	return ok && service.Declared
}

func serviceSkipped(id, title, name string) CheckResult {
	return CheckResult{ID: id, Title: title, Severity: SeverityInfo, Skipped: true, Message: name + " not declared, skipping"}
}

func servicePassed(id, title, msg string) CheckResult {
	return CheckResult{ID: id, Title: title, Severity: SeverityInfo, Passed: true, Message: msg}
}

func serviceWarned(id, title, msg string, suggestions ...string) CheckResult {
	return CheckResult{ID: id, Title: title, Severity: SeverityWarn, Passed: false, Message: msg, Suggestions: suggestions}
}

// serviceEnvPass is envKeyPass over the check's own env prefixes plus the
// ones detection declares the service from.
func serviceEnvPass(ctx Context, id, title string, own ...string) (CheckResult, bool) {
	return envKeyPass(id, title, ctx.RootDir, serviceEnvPrefixes(id, own...)...)
}

// FathomCheck verifies Fathom Analytics is properly set up
type FathomCheck struct{}

func (c FathomCheck) ID() string {
	return "fathom"
}

func (c FathomCheck) Title() string {
	return "Fathom Analytics"
}

func (c FathomCheck) Run(ctx Context) (CheckResult, error) {
	if !serviceDeclared(ctx, c.ID()) {
		return serviceSkipped(c.ID(), c.Title(), "Fathom"), nil
	}
	if ctx.serviceCodeMatch(c.ID()) != nil {
		return servicePassed(c.ID(), c.Title(), "Fathom Analytics script found"), nil
	}
	if r, ok := serviceEnvPass(ctx, c.ID(), c.Title()); ok {
		return r, nil
	}
	return serviceWarned(c.ID(), c.Title(), "Fathom is declared but script not found in templates",
		"Add the Fathom script tag to your main layout",
		"Example: <script src=\"https://cdn.usefathom.com/script.js\" data-site=\"XXXXX\" defer></script>",
	), nil
}

// GoogleAnalyticsCheck verifies Google Analytics is properly set up
type GoogleAnalyticsCheck struct{}

func (c GoogleAnalyticsCheck) ID() string {
	return "google_analytics"
}

func (c GoogleAnalyticsCheck) Title() string {
	return "Google Analytics"
}

func (c GoogleAnalyticsCheck) Run(ctx Context) (CheckResult, error) {
	if !serviceDeclared(ctx, c.ID()) {
		return serviceSkipped(c.ID(), c.Title(), "Google Analytics"), nil
	}
	if ctx.serviceCodeMatch(c.ID()) != nil {
		return servicePassed(c.ID(), c.Title(), "Google Analytics configuration found"), nil
	}
	if r, ok := serviceEnvPass(ctx, c.ID(), c.Title()); ok {
		return r, nil
	}
	return serviceWarned(c.ID(), c.Title(), "Google Analytics is declared but not found in templates",
		"Add Google Analytics/GTM script to your main layout",
		"Consider using GA4 with gtag.js for modern tracking",
	), nil
}

// RedisCheck verifies Redis connection is configured
type RedisCheck struct{}

func (c RedisCheck) ID() string {
	return "redis"
}

func (c RedisCheck) Title() string {
	return "Redis"
}

func (c RedisCheck) Run(ctx Context) (CheckResult, error) {
	if !serviceDeclared(ctx, c.ID()) {
		return serviceSkipped(c.ID(), c.Title(), "Redis"), nil
	}

	// A client, a connection URL, or framework config anywhere in the code.
	if ctx.serviceCodeMatch(c.ID()) != nil {
		return servicePassed(c.ID(), c.Title(), "Redis configuration found"), nil
	}

	// Config files of traditional setups.
	for _, file := range []string{
		"config/redis.yml",
		"config/cable.yml",
		"config/sidekiq.yml",
		"config/initializers/redis.rb",
		"config/initializers/sidekiq.rb",
	} {
		if _, err := os.Stat(filepath.Join(ctx.RootDir, file)); err == nil {
			return servicePassed(c.ID(), c.Title(), "Redis configuration found"), nil
		}
	}

	// REDIS_URL or REDIS_HOST in an env file: the connection is configured
	// where the framework reads it (stock Laravel never names Redis in
	// application code).
	if r, ok := serviceEnvPass(ctx, c.ID(), c.Title()); ok {
		return r, nil
	}

	return serviceWarned(c.ID(), c.Title(), "Redis is declared but configuration not found",
		"Ensure REDIS_URL is set in your environment",
		"Add Redis initializer or configuration file",
	), nil
}

// SidekiqCheck verifies Sidekiq is configured (Rails)
type SidekiqCheck struct{}

func (c SidekiqCheck) ID() string {
	return "sidekiq"
}

func (c SidekiqCheck) Title() string {
	return "Sidekiq"
}

func (c SidekiqCheck) Run(ctx Context) (CheckResult, error) {
	if !serviceDeclared(ctx, c.ID()) {
		return serviceSkipped(c.ID(), c.Title(), "Sidekiq"), nil
	}

	for _, file := range []string{"config/sidekiq.yml", "config/initializers/sidekiq.rb"} {
		if _, err := os.Stat(filepath.Join(ctx.RootDir, file)); err == nil {
			return servicePassed(c.ID(), c.Title(), "Sidekiq configuration found"), nil
		}
	}

	// Sidekiq runs on its defaults without either file: the gem and a job
	// class, or the queue adapter setting, are a working setup.
	if ctx.serviceCodeMatch(c.ID()) != nil {
		return servicePassed(c.ID(), c.Title(), "Sidekiq found (running on its default configuration)"), nil
	}
	if r, ok := serviceEnvPass(ctx, c.ID(), c.Title()); ok {
		return r, nil
	}

	return serviceWarned(c.ID(), c.Title(), "Sidekiq is declared but not found in the Gemfile or the code",
		"Add the sidekiq gem and a job class",
		"Optionally create config/sidekiq.yml with queue configuration",
	), nil
}
