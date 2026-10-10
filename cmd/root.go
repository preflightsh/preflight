package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"
)

var (
	version = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "preflight",
	Short: "Preflight CLI - Launch readiness checker for your codebase",
	Long: `Preflight CLI scans your codebase and configuration for launch readiness.
It identifies missing configuration, integration issues, security concerns,
SEO metadata gaps, and other common mistakes that affect production deploys.`,
	Version: version,
}

func Execute() error {
	return rootCmd.Execute()
}

// ExitCode turns the error from Execute into the process exit code, printing
// the message to stderr. An *ExitError carries its own code. Any other error
// comes from cobra (unknown command or flag, wrong argument count, bad flag
// value) or from a command that could not do its job, so it is a usage error:
// exiting 1 would tell CI "warnings only" for a scan that never ran.
func ExitCode(err error, stderr io.Writer) int {
	if err == nil {
		return ExitOK
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		if exitErr.Err != nil {
			fmt.Fprintln(stderr, exitErr.Err)
		}
		return exitErr.Code
	}
	fmt.Fprintf(stderr, "Error: %v\nRun 'preflight --help' for usage.\n", err)
	return ExitUsage
}

// resolveVersion falls back to the module version stamped by
// `go install ...@vX.Y.Z` when the binary was not built with -ldflags
// (GoReleaser sets it there). Local builds get a VCS pseudo-version such as
// v0.22.2-0.2026...-abc+dirty; those stay "dev" so the update check keeps
// skipping them.
func resolveVersion(v string) string {
	if v != "dev" {
		return v
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if releaseVersion(info.Main.Version) {
			return strings.TrimPrefix(info.Main.Version, "v")
		}
	}
	return v
}

// releaseVersion reports whether v is a plain tagged release (vX.Y.Z), not a
// pseudo-version, pre-release, or dirty build.
func releaseVersion(v string) bool {
	return semver.IsValid(v) && semver.Prerelease(v) == "" && semver.Build(v) == ""
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "preflight version %s\n", rootCmd.Version)
	},
}

func init() {
	version = resolveVersion(version)
	rootCmd.Version = version
	rootCmd.AddCommand(versionCmd)
	rootCmd.SetVersionTemplate("preflight version {{.Version}}\n")
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
}

// Exit codes are a contract: CI pipelines branch on them and the README
// documents them, so they are named here rather than written as bare
// integers at each return.
//
// ExitUsage is deliberately distinct from ExitFail. Both mean "non-zero",
// but conflating them tells a pipeline that a mistyped path or an
// unreadable preflight.yml is the same event as a project that genuinely
// failed its checks. 64 follows the sysexits.h EX_USAGE convention, and
// like 130 (128 + SIGINT) it stays clear of the 0-2 result range.
const (
	ExitOK       = 0
	ExitWarn     = 1
	ExitFail     = 2
	ExitUsage    = 64
	ExitCanceled = 130
)

// ExitError is an error that carries a specific exit code
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit code %d", e.Code)
}

// getPreflightStateDir returns the path to the preflight state directory (~/.preflight)
func getPreflightStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".preflight")
}

// isFirstRun checks if this is the first time a command has been run
// Returns true if the marker file doesn't exist
func isFirstRun(marker string) bool {
	stateDir := getPreflightStateDir()
	if stateDir == "" {
		return false
	}
	markerPath := filepath.Join(stateDir, marker)
	_, err := os.Stat(markerPath)
	return os.IsNotExist(err)
}

// markFirstRunComplete creates a marker file to indicate a command has been run
func markFirstRunComplete(marker string) {
	stateDir := getPreflightStateDir()
	if stateDir == "" {
		return
	}
	// Create state directory if it doesn't exist
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return
	}
	markerPath := filepath.Join(stateDir, marker)
	_ = os.WriteFile(markerPath, []byte{}, 0644)
}

// showStarMessage displays the GitHub star prompt
func showStarMessage() {
	fmt.Println("⭐ If you found this useful, please star us on GitHub:")
	fmt.Println("   https://github.com/preflightsh/preflight")
	fmt.Println()
}
