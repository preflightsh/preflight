package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/preflightsh/preflight/internal/catalog"
	"github.com/preflightsh/preflight/internal/checks"
)

// Colors. Variables rather than constants so init() can blank them out
// when stdout isn't a terminal or NO_COLOR is set.
var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

func init() {
	if !shouldUseColor() {
		colorReset = ""
		colorRed = ""
		colorGreen = ""
		colorYellow = ""
		colorCyan = ""
		colorGray = ""
		colorBold = ""
	}
}

// shouldUseColor honors the NO_COLOR convention and detects whether
// stdout is a character device (terminal) vs. a pipe/file.
func shouldUseColor() bool {
	if _, noColor := os.LookupEnv("NO_COLOR"); noColor {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

type HumanOutputter struct {
	Verbose bool
}

func (h HumanOutputter) Output(w io.Writer, projectName string, results []checks.CheckResult) {
	// Header
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s%s ✈  Preflight Scan Results%s\n", colorBold, colorCyan, colorReset)
	fmt.Fprintf(w, "%s   Project: %s%s\n", colorGray, sanitize(projectName), colorReset)
	fmt.Fprintln(w)

	// Separate results into core checks and service checks, and drop
	// checks that only report they were skipped so they don't clutter
	// the output.
	var coreResults []checks.CheckResult
	var serviceResults []checks.CheckResult
	for _, r := range results {
		if r.Passed && (strings.Contains(strings.ToLower(r.Message), "skipping") ||
			strings.Contains(strings.ToLower(r.Message), "skipped")) {
			continue
		}
		if catalog.IsService(catalog.Canonical(r.ID)) {
			serviceResults = append(serviceResults, r)
		} else {
			coreResults = append(coreResults, r)
		}
	}

	printResult := func(r checks.CheckResult, isLast bool) {
		category := catalog.Category(catalog.Canonical(r.ID))
		if category == "" {
			category = strings.ToUpper(r.ID)
		}

		icon := catalog.CategoryIcons[category]
		if icon == "" {
			icon = "•"
		}

		status := formatStatus(r)
		categoryLabel := fmt.Sprintf("%s  %-10s", icon, category)

		fmt.Fprintf(w, "  %s %s%-45s%s %s\n", categoryLabel, colorReset, sanitize(r.Title), colorReset, status)

		// Show message for failed checks, or for passed checks with useful info
		if r.Message != "" {
			if !r.Passed || hasUsefulPassedMessage(r.Message) {
				fmt.Fprintf(w, "  %s                  └─ %s%s\n", colorGray, sanitize(r.Message), colorReset)
			}
		}

		// Suggestions are the actionable half of a finding (the file and
		// line of a debug statement, the header to add, the image to
		// shrink). They used to reach only the JSON output, which left
		// terminal users with "Found 1 debug statement(s)" and no path.
		if !r.Passed {
			for _, s := range r.Suggestions {
				fmt.Fprintf(w, "  %s                     • %s%s\n", colorGray, sanitize(s), colorReset)
			}
		}

		// Show verbose details if enabled
		if h.Verbose && len(r.Details) > 0 {
			for _, detail := range r.Details {
				fmt.Fprintf(w, "  %s                  │  %s%s\n", colorGray, sanitize(detail), colorReset)
			}
		}

		// Add subtle divider between checks (except after the last one)
		if !isLast {
			fmt.Fprintf(w, "  %s· · · · · · · · · · · · · · · · · · · · · · · · · · · ·%s\n", colorGray, colorReset)
		}
	}

	// Print core check results
	for i, r := range coreResults {
		isLast := i == len(coreResults)-1 && len(serviceResults) == 0
		printResult(r, isLast)
	}

	// Print service check results under a heading
	if len(serviceResults) > 0 {
		if len(coreResults) > 0 {
			fmt.Fprintln(w)
			fmt.Fprintf(w, "  %s────────────────────────────────────────────────────────%s\n", colorGray, colorReset)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s%s 🔌 Checked Services%s\n", colorBold, colorCyan, colorReset)
		fmt.Fprintln(w)

		for i, r := range serviceResults {
			isLast := i == len(serviceResults)-1
			printResult(r, isLast)
		}
	}

	// Summary
	summary := CalculateSummary(results)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s────────────────────────────────────────────────────────%s\n", colorGray, colorReset)
	fmt.Fprintln(w)

	// Summary with icons
	fmt.Fprintf(w, "  %s✓ Passed:%s  %s%d%s", colorGreen, colorReset, colorBold, summary.OK, colorReset)
	if summary.Warn > 0 {
		fmt.Fprintf(w, "    %s⚠ Warnings:%s %s%d%s", colorYellow, colorReset, colorBold, summary.Warn, colorReset)
	}
	if summary.Fail > 0 {
		fmt.Fprintf(w, "    %s✗ Failed:%s  %s%d%s", colorRed, colorReset, colorBold, summary.Fail, colorReset)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	// Final verdict
	if summary.Fail > 0 {
		fmt.Fprintf(w, "  %s%s✗ Not ready for launch%s\n", colorBold, colorRed, colorReset)
	} else if summary.Warn > 0 {
		fmt.Fprintf(w, "  %s%s⚠ Review warnings before launch%s\n", colorBold, colorYellow, colorReset)
	} else {
		fmt.Fprintf(w, "  %s%s✓ Ready for launch!%s\n", colorBold, colorGreen, colorReset)
	}
	fmt.Fprintln(w)
}

// sanitize strips the control characters a terminal would interpret. Titles
// are ours, but messages and suggestions carry file names and content
// harvested from the scanned project, and a file named with an escape
// sequence would otherwise reach the terminal verbatim (the JSON output is
// safe because encoding/json escapes them). Tabs are kept; C0 controls,
// DEL and the C1 range (U+0080 to U+009F, which some terminals treat as
// 8-bit escape introducers) are dropped.
func sanitize(s string) string {
	clean := true
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if isTerminalControl(r) || (r == utf8.RuneError && size == 1) {
			clean = false
			break
		}
		i += size
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		// A lone invalid byte is dropped too: 0x9b on its own is not valid
		// UTF-8, but a terminal in 8-bit mode still reads it as CSI.
		invalidByte := r == utf8.RuneError && size == 1
		if !isTerminalControl(r) && !invalidByte {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func isTerminalControl(r rune) bool {
	if r == '\t' {
		return false
	}
	return r < 0x20 || (r >= 0x7f && r <= 0x9f)
}

// hasUsefulPassedMessage returns true if the message contains info worth showing
// even when the check passed (e.g., license type, version info)
func hasUsefulPassedMessage(msg string) bool {
	// Show messages that identify specific types/versions
	usefulPatterns := []string{
		"license found", // License type detection
		"MIT", "Apache", "GPL", "AGPL", "BSD", "ISC", "MPL",
		"(at ",           // Location info for files found in parent dirs
		"not enabled",    // Check passed because it's disabled/not configured
		"not configured", // Check passed because it's not configured
		"skipped",        // Check was skipped
		"not declared",   // Service not declared
		"prod:",          // Per-environment summary (security headers, SEO checks)
		"staging:",
	}

	msgLower := strings.ToLower(msg)
	for _, pattern := range usefulPatterns {
		if strings.Contains(msgLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func formatStatus(r checks.CheckResult) string {
	if r.Passed {
		return fmt.Sprintf("%s%s✓ OK%s", colorBold, colorGreen, colorReset)
	}

	switch r.Severity {
	case checks.SeverityError:
		return fmt.Sprintf("%s%s✗ FAIL%s", colorBold, colorRed, colorReset)
	case checks.SeverityWarn:
		return fmt.Sprintf("%s%s⚠ WARN%s", colorBold, colorYellow, colorReset)
	default:
		return fmt.Sprintf("%s%s⚠ WARN%s", colorBold, colorYellow, colorReset)
	}
}
