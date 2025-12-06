package checks

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

type EnvParityCheck struct{}

func (c EnvParityCheck) ID() string {
	return "envParity"
}

func (c EnvParityCheck) Title() string {
	return "Environment variables are in sync"
}

func (c EnvParityCheck) Run(ctx Context) (CheckResult, error) {
	cfg := ctx.Config.Checks.EnvParity
	if cfg == nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "Check not configured",
		}, nil
	}

	envPath := filepath.Join(ctx.RootDir, cfg.EnvFile)
	examplePath := filepath.Join(ctx.RootDir, cfg.ExampleFile)

	// Parse both files
	envKeys, err := parseEnvFile(envPath)
	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Could not read " + cfg.EnvFile,
			Suggestions: []string{
				"Create a " + cfg.EnvFile + " file",
			},
		}, nil
	}

	exampleKeys, err := parseEnvFile(examplePath)
	if err != nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityWarn,
			Passed:   false,
			Message:  "Could not read " + cfg.ExampleFile,
			Suggestions: []string{
				"Create a " + cfg.ExampleFile + " file to document required environment variables",
			},
		}, nil
	}

	// Find keys in .env but not in .env.example
	var missingInExample []string
	for key := range envKeys {
		if _, exists := exampleKeys[key]; !exists {
			missingInExample = append(missingInExample, key)
		}
	}

	// Find keys in .env.example but not in .env
	var missingInEnv []string
	for key := range exampleKeys {
		if _, exists := envKeys[key]; !exists {
			missingInEnv = append(missingInEnv, key)
		}
	}

	if len(missingInExample) == 0 && len(missingInEnv) == 0 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "All environment variables are documented",
		}, nil
	}

	var messages []string
	var suggestions []string

	if len(missingInExample) > 0 {
		messages = append(messages, "Missing in "+cfg.ExampleFile+": "+strings.Join(missingInExample, ", "))
		suggestions = append(suggestions, "Add "+strings.Join(missingInExample, ", ")+" to "+cfg.ExampleFile)
	}

	if len(missingInEnv) > 0 {
		messages = append(messages, "Missing in "+cfg.EnvFile+": "+strings.Join(missingInEnv, ", "))
		suggestions = append(suggestions, "Add "+strings.Join(missingInEnv, ", ")+" to "+cfg.EnvFile)
	}

	return CheckResult{
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityWarn,
		Passed:      false,
		Message:     strings.Join(messages, "; "),
		Suggestions: suggestions,
	}, nil
}

func parseEnvFile(path string) (map[string]bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	keys := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Extract key (everything before =)
		if idx := strings.Index(line, "="); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			keys[key] = true
		}
	}

	return keys, scanner.Err()
}
