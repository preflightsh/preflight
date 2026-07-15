package cmd

import (
	"testing"

	"github.com/preflightsh/preflight/internal/checks"
)

func TestDetermineExitCode(t *testing.T) {
	cases := []struct {
		name    string
		results []checks.CheckResult
		want    int
	}{
		{
			name:    "no results",
			results: nil,
			want:    ExitOK,
		},
		{
			name: "all passed",
			results: []checks.CheckResult{
				{Passed: true, Severity: checks.SeverityInfo},
				{Passed: true, Severity: checks.SeverityWarn},
			},
			want: ExitOK,
		},
		{
			name:    "one warning",
			results: []checks.CheckResult{{Passed: false, Severity: checks.SeverityWarn}},
			want:    ExitWarn,
		},
		{
			name:    "one error",
			results: []checks.CheckResult{{Passed: false, Severity: checks.SeverityError}},
			want:    ExitFail,
		},
		{
			// An error outranks warnings no matter the ordering.
			name: "error wins over warning",
			results: []checks.CheckResult{
				{Passed: false, Severity: checks.SeverityWarn},
				{Passed: false, Severity: checks.SeverityError},
			},
			want: ExitFail,
		},
		{
			name: "error wins when it comes first",
			results: []checks.CheckResult{
				{Passed: false, Severity: checks.SeverityError},
				{Passed: false, Severity: checks.SeverityWarn},
			},
			want: ExitFail,
		},
		{
			// A passing check never contributes, even at error severity.
			name:    "passed error severity is still ok",
			results: []checks.CheckResult{{Passed: true, Severity: checks.SeverityError}},
			want:    ExitOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := determineExitCode(tc.results); got != tc.want {
				t.Errorf("determineExitCode = %d, want %d", got, tc.want)
			}
		})
	}
}

// The codes are a published contract (README, scan --help) that CI
// pipelines branch on. In particular ExitUsage must stay outside the
// 0-2 range so "preflight could not run" is distinguishable from "your
// project failed its checks".
func TestExitCodeContract(t *testing.T) {
	if ExitOK != 0 || ExitWarn != 1 || ExitFail != 2 || ExitCanceled != 130 {
		t.Errorf("documented exit codes changed: ok=%d warn=%d fail=%d canceled=%d",
			ExitOK, ExitWarn, ExitFail, ExitCanceled)
	}
	for _, resultCode := range []int{ExitOK, ExitWarn, ExitFail} {
		if ExitUsage == resultCode {
			t.Fatalf("ExitUsage (%d) collides with a scan result code", ExitUsage)
		}
	}
	if ExitUsage == ExitCanceled {
		t.Errorf("ExitUsage (%d) collides with ExitCanceled", ExitUsage)
	}
}

func TestFilterChecksByFlagsRejectsUnknownID(t *testing.T) {
	// A typo must be an error rather than silently scanning nothing, and
	// the caller maps that error to ExitUsage rather than ExitFail.
	if _, err := filterChecksByFlags(nil, []string{"definitely-not-a-check"}, nil); err == nil {
		t.Error("filterChecksByFlags accepted an unknown --only ID, want error")
	}
	if _, err := filterChecksByFlags(nil, nil, []string{"definitely-not-a-check"}); err == nil {
		t.Error("filterChecksByFlags accepted an unknown --skip ID, want error")
	}
}
