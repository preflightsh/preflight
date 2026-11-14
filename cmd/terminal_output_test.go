package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/dashboard"
)

// A skipped check is stored as passed: false at info severity, and used to
// print as a failure; an inconclusive one could print as a pass.
func TestWriteRunMarksSkippedAndInconclusive(t *testing.T) {
	run := &dashboard.RunDetail{
		ProjectName: "demo",
		OK:          1, Warn: 2, Fail: 1,
		Checks: []dashboard.PublishCheck{
			{Title: "Robots", Passed: true, Severity: "info", Message: "served"},
			{Title: "Vulnerability scan", Passed: false, Skipped: true, Severity: "info", Message: "No dependency manifests found"},
			{Title: "Legal pages", Passed: true, Inconclusive: true, Severity: "warn", Message: "Host unreachable"},
			{Title: "Sitemap", Passed: false, Severity: "warn", Message: "not found"},
			{Title: "Secrets", Passed: false, Severity: "error", Message: "1 place"},
		},
	}
	var buf bytes.Buffer
	writeRun(&buf, run)
	out := buf.String()
	for _, want := range []string{
		"  ✓  Robots\n",
		"  -  Vulnerability scan\n       No dependency manifests found\n",
		"  ?  Legal pages\n       Host unreachable\n",
		"  !  Sitemap\n       not found\n",
		"  ✗  Secrets\n       1 place\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "served") {
		t.Errorf("a plain pass should not print its message:\n%s", out)
	}
}

// Everything in a run came from the dashboard; none of it may carry
// escape sequences to the terminal.
func TestWriteRunStripsTerminalControls(t *testing.T) {
	run := &dashboard.RunDetail{
		ProjectName: "demo\x1b]0;spoofed\x07",
		Checks:      []dashboard.PublishCheck{{Title: "T\x1b[2K", Severity: "warn", Message: "m\x1b[31m\r"}},
	}
	var buf bytes.Buffer
	writeRun(&buf, run)
	if strings.ContainsAny(buf.String(), "\x1b\x07\r") {
		t.Errorf("control characters reached the output: %q", buf.String())
	}
}

// Error text quotes config values and dashboard response bodies.
func TestExitCodeStripsTerminalControls(t *testing.T) {
	for _, err := range []error{
		&ExitError{Code: ExitFail, Err: errors.New("history failed: 500: \x1b]0;x\x07body\nsecond line")},
		errors.New("unknown flag: \x1b[2K--x"),
	} {
		var stderr bytes.Buffer
		ExitCode(err, &stderr)
		if strings.ContainsAny(stderr.String(), "\x1b\x07") {
			t.Errorf("control characters reached stderr: %q", stderr.String())
		}
	}
	// Line breaks in a message are layout, not an attack, and survive.
	var stderr bytes.Buffer
	ExitCode(&ExitError{Code: ExitUsage, Err: errors.New("line one\nline two")}, &stderr)
	if stderr.String() != "line one\nline two\n" {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// A file that cannot be written is not a mistake on the command line, so
// it keeps exit 64 but does not point the user at --help.
func TestCouldNotRunHasNoUsageHint(t *testing.T) {
	var stderr bytes.Buffer
	code := ExitCode(couldNotRun(fmt.Errorf("failed to write config: permission denied")), &stderr)
	if code != ExitUsage {
		t.Errorf("code = %d, want %d", code, ExitUsage)
	}
	if got := stderr.String(); got != "Error: failed to write config: permission denied\n" {
		t.Errorf("stderr = %q", got)
	}
}

func TestIgnoreInReadOnlyDirHasNoUsageHint(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a read-only directory on Windows still allows writes to its files")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	path := inTempProject(t, "projectName: example\n")
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	var stderr bytes.Buffer
	code := ExitCode(runIgnore(nil, []string{"sitemap"}), &stderr)
	if code != ExitUsage || strings.Contains(stderr.String(), "--help") || !strings.Contains(stderr.String(), "failed to write config") {
		t.Errorf("code=%d stderr=%q", code, stderr.String())
	}
}

// `preflight auth logn` used to print help and exit 0.
func TestUnknownSubcommandAndStrayArgsAreUsageErrors(t *testing.T) {
	cases := [][]string{
		{"auth", "logn"},
		{"auth", "status", "extra"},
		{"auth", "logout", "extra"},
		{"checks", "extra"},
		{"version", "extra"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			var out bytes.Buffer
			rootCmd.SetOut(&out)
			rootCmd.SetErr(&out)
			rootCmd.SetArgs(args)
			t.Cleanup(func() { rootCmd.SetArgs(nil); rootCmd.SetOut(nil); rootCmd.SetErr(nil) })
			var stderr bytes.Buffer
			if code := ExitCode(rootCmd.Execute(), &stderr); code != ExitUsage {
				t.Errorf("code = %d, want %d (stderr %q)", code, ExitUsage, stderr.String())
			}
		})
	}
	// The bare group command still prints its help and succeeds.
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"auth"})
	t.Cleanup(func() { rootCmd.SetArgs(nil); rootCmd.SetOut(nil) })
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("auth with no subcommand: %v", err)
	}
	if !strings.Contains(out.String(), "login") {
		t.Errorf("auth help missing subcommands:\n%s", out.String())
	}
}

// --here needs a project to scope to. A directory with neither a config
// nor a repository remote has no key, so the caller reports a usage error
// instead of asking the dashboard about a project with no name.
func TestCurrentProjectKeyOutsideAProject(t *testing.T) {
	if key := currentProjectKey(t.TempDir()); key != "" {
		t.Errorf("key = %q, want empty", key)
	}
	dir := scanProject(t, "projectName: demo\n")
	if key := currentProjectKey(dir); key != "name:demo" {
		t.Errorf("key = %q, want name:demo", key)
	}
}
