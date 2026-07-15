package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/checks"
)

func sampleResults() []checks.CheckResult {
	return []checks.CheckResult{
		{
			ID:       "canonical",
			Title:    "Canonical URL",
			Severity: checks.SeverityInfo,
			Passed:   true,
			Message:  "Canonical URL configured",
		},
		{
			ID:          "ogTwitter",
			Title:       "OG & Twitter cards",
			Severity:    checks.SeverityWarn,
			Passed:      false,
			Message:     "og:image too small (64x64, min 200x200)",
			Suggestions: []string{"Use an image at least 1200x630"},
		},
		{
			ID:       "secrets",
			Title:    "Secrets scan",
			Severity: checks.SeverityError,
			Passed:   false,
			Message:  "Potential secrets detected",
			// Details is deliberately not part of the JSON contract.
			Details: []string{"should not be serialized"},
		},
	}
}

// JSONOutput is the run-data contract app.preflight.sh ingests. A field
// rename or a dropped key breaks the dashboard from another repo, with
// nothing in this repo's CI failing, so pin the exact bytes.
//
// Note the &: encoding/json HTML-escapes &, < and > unless
// SetEscapeHTML(false) is set. Consumers already depend on that (check
// suggestions routinely contain <script> tags), so it is pinned here
// deliberately rather than tidied away.
func TestJSONOutputterGolden(t *testing.T) {
	var buf bytes.Buffer
	JSONOutputter{}.Output(&buf, "demo", sampleResults())

	const want = `{
  "project": "demo",
  "summary": {
    "ok": 1,
    "warn": 1,
    "fail": 1
  },
  "checks": [
    {
      "id": "canonical",
      "title": "Canonical URL",
      "passed": true,
      "severity": "info",
      "message": "Canonical URL configured"
    },
    {
      "id": "ogTwitter",
      "title": "OG \u0026 Twitter cards",
      "passed": false,
      "severity": "warn",
      "message": "og:image too small (64x64, min 200x200)",
      "suggestions": [
        "Use an image at least 1200x630"
      ]
    },
    {
      "id": "secrets",
      "title": "Secrets scan",
      "passed": false,
      "severity": "error",
      "message": "Potential secrets detected"
    }
  ]
}
`
	if got := buf.String(); got != want {
		t.Errorf("JSON output drifted from the dashboard contract.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// The dashboard reads these keys by name; keep them from being renamed
// out from under it without a deliberate change here.
func TestJSONOutputContractKeys(t *testing.T) {
	var buf bytes.Buffer
	JSONOutputter{}.Output(&buf, "demo", sampleResults())

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, key := range []string{"project", "summary", "checks"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("top-level key %q missing from JSON contract", key)
		}
	}

	summary, ok := decoded["summary"].(map[string]any)
	if !ok {
		t.Fatal("summary is not an object")
	}
	for _, key := range []string{"ok", "warn", "fail"} {
		if _, ok := summary[key]; !ok {
			t.Errorf("summary key %q missing from JSON contract", key)
		}
	}

	firstCheck, ok := decoded["checks"].([]any)[0].(map[string]any)
	if !ok {
		t.Fatal("checks[0] is not an object")
	}
	for _, key := range []string{"id", "title", "passed", "severity"} {
		if _, ok := firstCheck[key]; !ok {
			t.Errorf("check key %q missing from JSON contract", key)
		}
	}
	// Details is verbose terminal output, not part of the wire format.
	if _, leaked := firstCheck["details"]; leaked {
		t.Error("checks[].details leaked into the JSON contract")
	}
}

func TestCalculateSummary(t *testing.T) {
	cases := []struct {
		name    string
		results []checks.CheckResult
		want    Summary
	}{
		{
			name: "counts passed as ok regardless of severity",
			results: []checks.CheckResult{
				{Passed: true, Severity: checks.SeverityError},
				{Passed: true, Severity: checks.SeverityInfo},
			},
			want: Summary{OK: 2},
		},
		{
			name:    "failed error counts as fail",
			results: []checks.CheckResult{{Passed: false, Severity: checks.SeverityError}},
			want:    Summary{Fail: 1},
		},
		{
			name:    "failed warn counts as warn",
			results: []checks.CheckResult{{Passed: false, Severity: checks.SeverityWarn}},
			want:    Summary{Warn: 1},
		},
		{
			// determineExitCode ignores severities it doesn't recognize on a
			// failed check, while this counts them as warnings. Nothing emits
			// that combination today; this documents the current behavior so
			// the divergence is visible if anything ever does.
			name:    "failed info counts as warn",
			results: []checks.CheckResult{{Passed: false, Severity: checks.SeverityInfo}},
			want:    Summary{Warn: 1},
		},
		{
			name:    "empty results",
			results: nil,
			want:    Summary{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CalculateSummary(tc.results); got != tc.want {
				t.Errorf("CalculateSummary = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestHumanOutputterWritesToWriter(t *testing.T) {
	var buf bytes.Buffer
	HumanOutputter{}.Output(&buf, "demo-project", sampleResults())

	got := buf.String()
	if got == "" {
		t.Fatal("HumanOutputter wrote nothing to the provided writer")
	}
	for _, want := range []string{"demo-project", "Canonical URL", "OG & Twitter cards"} {
		if !strings.Contains(got, want) {
			t.Errorf("human output missing %q", want)
		}
	}
}

// Verbose adds per-check Details; the non-verbose rendering must not.
func TestHumanOutputterVerboseDetails(t *testing.T) {
	results := []checks.CheckResult{{
		ID: "x", Title: "X", Severity: checks.SeverityInfo, Passed: true,
		Message: "fine", Details: []string{"extra-detail-line"},
	}}

	var quiet, loud bytes.Buffer
	HumanOutputter{Verbose: false}.Output(&quiet, "p", results)
	HumanOutputter{Verbose: true}.Output(&loud, "p", results)

	if strings.Contains(quiet.String(), "extra-detail-line") {
		t.Error("non-verbose output included Details")
	}
	if !strings.Contains(loud.String(), "extra-detail-line") {
		t.Error("verbose output omitted Details")
	}
}
