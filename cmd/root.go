package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
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

func init() {
	rootCmd.SetVersionTemplate("preflight version {{.Version}}\n")
}

func exitWithError(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
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
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return
	}
	markerPath := filepath.Join(stateDir, marker)
	os.WriteFile(markerPath, []byte{}, 0644)
}

// showStarMessage displays the GitHub star prompt
func showStarMessage() {
	fmt.Println("⭐ If you found this useful, please star us on GitHub:")
	fmt.Println("   https://github.com/preflightsh/preflight")
	fmt.Println()
}
