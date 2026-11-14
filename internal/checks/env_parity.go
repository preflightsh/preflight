package checks

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

type EnvParityCheck struct{}

func (c EnvParityCheck) ID() string {
	return "env_parity"
}

func (c EnvParityCheck) Title() string {
	return "Environment variables"
}

func (c EnvParityCheck) Run(ctx Context) (CheckResult, error) {
	cfg := ctx.Config.Checks.EnvParity
	if cfg == nil {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Skipped:  true,
			Message:  "Check not configured",
		}, nil
	}

	// Check if .env.example exists first. Both paths come from preflight.yml,
	// which the scanned repo controls, so they are opened inside the project
	// only (openProjectFile): "../other/.env" or a symlinked directory used
	// to put another project's variable names into Message.
	example, exampleErr := parseEnvFile(ctx.RootDir, cfg.ExampleFile)
	if exampleErr != nil {
		if !errors.Is(exampleErr, os.ErrNotExist) {
			return c.readFailure(exampleErr), nil
		}
		// No .env.example - that's fine, skip this check
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Skipped:  true,
			Message:  "No " + cfg.ExampleFile + " found (skipped)",
		}, nil
	}

	// .env.example exists - now check if .env exists
	env, envErr := parseEnvFile(ctx.RootDir, cfg.EnvFile)
	if envErr != nil {
		if !errors.Is(envErr, os.ErrNotExist) {
			return c.readFailure(envErr), nil
		}
		// .env.example exists but .env doesn't - this is expected for repos
		// Just note that .env.example documents the required vars
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Skipped:  true,
			Message:  cfg.ExampleFile + " documents " + fmt.Sprintf("%d", len(example.set)) + " required variables",
		}, nil
	}

	// Find keys in .env but not in .env.example. A key the example lists
	// commented out ("# SENTRY_DSN=") is documented as optional there.
	var missingInExample []string
	for key := range env.set {
		if !example.set[key] && !example.commented[key] {
			missingInExample = append(missingInExample, key)
		}
	}

	// Find keys in .env.example but not in .env
	var missingInEnv []string
	for key := range example.set {
		if !env.set[key] {
			missingInEnv = append(missingInEnv, key)
		}
	}

	// Map order is random; sort so the message is stable run to run (it is
	// compared across runs on the dashboard and in old-vs-new diffs).
	sort.Strings(missingInExample)
	sort.Strings(missingInEnv)

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

// envKeys are the variable names one env file declares.
type envKeys struct {
	set       map[string]bool // KEY=value lines
	commented map[string]bool // "# KEY=value" lines: named, but switched off
}

// envKeyName is what counts as a variable name. Anything else before an "="
// is not reported: the names end up in Message, and text that is not a name
// (a line of a multi-line value, a sentence) can be secret material.
var envKeyName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// parseEnvFile reads the variable names from rel, a path inside root taken
// from the config.
func parseEnvFile(root, rel string) (envKeys, error) {
	keys := envKeys{set: map[string]bool{}, commented: map[string]bool{}}
	file, err := openProjectFile(root, rel)
	if err != nil {
		return keys, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(io.LimitReader(file, maxSourceFileSize+1))
	scanner.Buffer(make([]byte, 64*1024), maxSourceFileSize)
	var consumed int
	// closing is the quote that ends a multi-line value in progress, or 0.
	// A PEM key pasted into a quoted value spans many lines, and its last
	// line of base64 ends in "=": read as a line of its own, it was
	// reported as a missing variable, key material and all.
	var closing byte
	first := true

	for scanner.Scan() {
		consumed += len(scanner.Bytes()) + 1
		if consumed > maxSourceFileSize {
			return keys, fmt.Errorf("%s: exceeds read limit", rel)
		}
		text := scanner.Text()
		if first {
			// A UTF-8 byte order mark (Windows editors add one) is not
			// part of the first variable's name.
			text = strings.TrimPrefix(text, "\uFEFF")
			first = false
		}
		if closing != 0 {
			if endsQuotedValue(text, closing) {
				closing = 0
			}
			continue
		}
		line := strings.TrimSpace(text)
		if line == "" {
			continue
		}

		commented := strings.HasPrefix(line, "#")
		if commented {
			// "# KEY=value" documents a variable without setting it.
			// Prose comments are told apart by the name test below.
			line = strings.TrimSpace(strings.TrimLeft(line, "#"))
		}

		// `export KEY=value` is valid dotenv (and what shells source).
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))

		// Extract key (everything before =)
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		if !envKeyName.MatchString(key) {
			continue
		}
		if commented {
			keys.commented[key] = true
			continue
		}
		keys.set[key] = true
		if value := strings.TrimSpace(line[idx+1:]); len(value) > 0 && (value[0] == '"' || value[0] == '\'') {
			if !endsQuotedValue(value[1:], value[0]) {
				closing = value[0]
			}
		}
	}

	return keys, scanner.Err()
}

// endsQuotedValue reports whether s holds the quote that closes a value. In
// double quotes a backslash escapes the next character; single quotes take
// everything literally.
func endsQuotedValue(s string, quote byte) bool {
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && quote == '"':
			i++
		case s[i] == quote:
			return true
		}
	}
	return false
}

func (c EnvParityCheck) readFailure(err error) CheckResult {
	return CheckResult{ID: c.ID(), Title: c.Title(), Severity: SeverityWarn, Inconclusive: true, Message: fmt.Sprintf("Environment comparison incomplete: %v", err)}
}
