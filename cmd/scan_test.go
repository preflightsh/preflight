package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestDetermineExitCodeUnknownSeverityIsWarning(t *testing.T) {
	// output.CalculateSummary counts an unknown severity as a warning; the
	// exit code must agree or the report says "1 warning" and exits 0.
	if got := determineExitCode([]checks.CheckResult{{Passed: false, Severity: "info"}}); got != ExitWarn {
		t.Errorf("determineExitCode = %d, want %d", got, ExitWarn)
	}
}

func scanProject(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()
	if config != "" {
		if err := os.WriteFile(filepath.Join(dir, "preflight.yml"), []byte(config), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// stdout of `scan --format json` must be exactly one JSON document.
func TestExecuteScanJSONIsValid(t *testing.T) {
	dir := scanProject(t, "projectName: demo\nstack: unknown\n")
	var stdout, stderr bytes.Buffer
	code, err := executeScan(context.Background(), scanOptions{
		ProjectDir: dir, Format: "json", Only: []string{"robots_txt"}, Quiet: true,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Project string `json:"project"`
		Checks  []struct {
			ID     string `json:"id"`
			Passed bool   `json:"passed"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if doc.Project != "demo" || len(doc.Checks) != 1 || doc.Checks[0].ID != "robots_txt" || doc.Checks[0].Passed {
		t.Errorf("unexpected document: %+v", doc)
	}
	// A missing robots.txt is a warning, and warnings exit 1.
	if code != ExitWarn {
		t.Errorf("exit code = %d, want %d", code, ExitWarn)
	}
}

func TestExecuteScanExitCodes(t *testing.T) {
	t.Run("passing project exits 0", func(t *testing.T) {
		dir := scanProject(t, "projectName: demo\nstack: unknown\n")
		if err := os.WriteFile(filepath.Join(dir, "robots.txt"), []byte("User-agent: *\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		code, err := executeScan(context.Background(), scanOptions{ProjectDir: dir, Only: []string{"robots_txt"}, Quiet: true}, &out, &out)
		if err != nil || code != ExitOK {
			t.Errorf("code=%d err=%v, want 0 and nil", code, err)
		}
		if !strings.Contains(out.String(), "Ready for launch") {
			t.Errorf("human report missing verdict:\n%s", out.String())
		}
	})
	t.Run("missing config is a usage error", func(t *testing.T) {
		dir := scanProject(t, "")
		var out bytes.Buffer
		code, err := executeScan(context.Background(), scanOptions{ProjectDir: dir, Quiet: true}, &out, &out)
		if code != ExitUsage || err == nil {
			t.Errorf("code=%d err=%v, want %d and an error", code, err, ExitUsage)
		}
	})
	t.Run("unknown --only ID is a usage error", func(t *testing.T) {
		dir := scanProject(t, "projectName: demo\n")
		var out bytes.Buffer
		code, err := executeScan(context.Background(), scanOptions{ProjectDir: dir, Only: []string{"nope"}, Quiet: true}, &out, &out)
		if code != ExitUsage || err == nil {
			t.Errorf("code=%d err=%v, want %d and an error", code, err, ExitUsage)
		}
	})
}

type fakeCheck struct {
	id    string
	delay time.Duration
	err   error
	panic bool
}

func (f fakeCheck) ID() string    { return f.id }
func (f fakeCheck) Title() string { return "Fake " + f.id }
func (f fakeCheck) Run(checks.Context) (checks.CheckResult, error) {
	time.Sleep(f.delay)
	if f.panic {
		panic("boom")
	}
	if f.err != nil {
		return checks.CheckResult{}, f.err
	}
	return checks.CheckResult{ID: f.id, Passed: true, Severity: checks.SeverityInfo}, nil
}

// Checks run concurrently now; the report must still come out in list
// order, an erroring or panicking check must become a failed result rather
// than abort the scan, and progress must count every completion.
func TestRunChecksOrderErrorsAndProgress(t *testing.T) {
	list := []checks.Check{
		fakeCheck{id: "slow", delay: 40 * time.Millisecond},
		fakeCheck{id: "fast"},
		fakeCheck{id: "broken", err: errors.New("kaput")},
		fakeCheck{id: "panicky", panic: true},
		fakeCheck{id: "last", delay: 10 * time.Millisecond},
	}
	var mu sync.Mutex
	var progress []int
	results, cancelled := runChecks(context.Background(), checks.Context{}, list, 3, func(done int, _ string) {
		mu.Lock()
		progress = append(progress, done)
		mu.Unlock()
	})
	if cancelled {
		t.Fatal("scan reported cancelled")
	}
	for i, want := range []string{"slow", "fast", "broken", "panicky", "last"} {
		if results[i].ID != want {
			t.Errorf("results[%d].ID = %q, want %q", i, results[i].ID, want)
		}
	}
	if results[2].Passed || results[2].Severity != checks.SeverityError || !strings.Contains(results[2].Message, "kaput") {
		t.Errorf("erroring check not reported as failed: %+v", results[2])
	}
	if results[3].Passed || !strings.Contains(results[3].Message, "panic") {
		t.Errorf("panicking check not reported as failed: %+v", results[3])
	}
	if len(progress) != len(list) || progress[len(progress)-1] != len(list) {
		t.Errorf("progress = %v, want %d calls ending at %d", progress, len(list), len(list))
	}
}

func TestRunChecksHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, cancelled := runChecks(ctx, checks.Context{}, []checks.Check{fakeCheck{id: "a"}}, 2, func(int, string) {})
	if !cancelled {
		t.Error("a cancelled context should stop the scan before it starts")
	}
}

// The pre-1.0 camelCase IDs are accepted by --only/--skip and the ignore
// list, resolve to the same check, and produce a note rather than an error.
func TestRenamedIDsStillWork(t *testing.T) {
	if _, err := filterChecksByFlags(nil, []string{"llmsTxt"}, nil); err != nil && !strings.Contains(err.Error(), "no enabled checks match") {
		t.Errorf("old ID rejected by --only: %v", err)
	}
	dir := scanProject(t, "projectName: demo\nstack: unknown\nignore:\n  - robotsTxt\n")
	var stdout, stderr bytes.Buffer
	_, err := executeScan(context.Background(), scanOptions{ProjectDir: dir, Format: "json", Only: []string{"robotsTxt", "sitemap"}, Quiet: true}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), `"id": "robots_txt"`) {
		t.Error("robotsTxt in the ignore list should still silence the robots_txt check")
	}
	if !strings.Contains(stdout.String(), `"id": "sitemap"`) {
		t.Error("the --only list should still include sitemap")
	}
	if !strings.Contains(stderr.String(), `"robotsTxt" is now "robots_txt"`) {
		t.Errorf("expected a rename note on stderr, got:\n%s", stderr.String())
	}
	if strings.Count(stderr.String(), "robotsTxt") != 1 {
		t.Errorf("the note should appear once per ID, got:\n%s", stderr.String())
	}
}
