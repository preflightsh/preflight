package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestExitCode pins the mapping from Execute's error to the process exit
// code. Plain errors (cobra flag and argument errors, failed commands) used to
// exit 1 with no message, which CI reads as "warnings only".
func TestExitCode(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		code    int
		wantMsg string
	}{
		{"nil", nil, ExitOK, ""},
		{"exit error with message", &ExitError{Code: ExitUsage, Err: errors.New("bad path")}, ExitUsage, "bad path"},
		{"exit error without message", &ExitError{Code: ExitWarn}, ExitWarn, ""},
		{"wrapped exit error", fmt.Errorf("wrap: %w", &ExitError{Code: ExitFail}), ExitFail, ""},
		{"plain error", errors.New("unknown flag: --bogus"), ExitUsage, "unknown flag: --bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if got := ExitCode(tc.err, &stderr); got != tc.code {
				t.Errorf("code = %d, want %d", got, tc.code)
			}
			if tc.wantMsg == "" && stderr.Len() != 0 {
				t.Errorf("unexpected stderr %q", stderr.String())
			}
			if tc.wantMsg != "" && !strings.Contains(stderr.String(), tc.wantMsg) {
				t.Errorf("stderr %q does not contain %q", stderr.String(), tc.wantMsg)
			}
		})
	}
}

func TestReleaseVersion(t *testing.T) {
	cases := map[string]bool{
		"v0.22.1":                               true,
		"v1.0.0":                                true,
		"v0.22.2-0.20261005132802-32d90f75e22f": false,
		"v0.22.2-0.20261005132802-32d90f75e22f+dirty": false,
		"v1.0.0-rc.1": false,
		"(devel)":     false,
		"":            false,
	}
	for v, want := range cases {
		if got := releaseVersion(v); got != want {
			t.Errorf("releaseVersion(%q) = %v, want %v", v, got, want)
		}
	}
}
