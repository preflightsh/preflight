package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type githubRelease struct {
	TagName string `json:"tag_name"`
}

// CheckForUpdates checks if a newer version is available and prompts user to upgrade
func CheckForUpdates() {
	// Skip in CI mode or if version is dev
	if version == "dev" {
		return
	}

	latest, err := fetchLatestVersion()
	if err != nil {
		// Silently fail - don't interrupt user workflow for update check failures
		return
	}

	if isNewerVersion(latest, version) {
		fmt.Println()
		fmt.Printf("📦 A new version of Preflight is available: %s (current: %s)\n", latest, version)
		fmt.Printf("   %s\n", getUpgradeCommand())
		fmt.Println()
	}
}

func fetchLatestVersion() (string, error) {
	client := &http.Client{Timeout: 3 * time.Second}

	resp, err := client.Get("https://api.github.com/repos/preflightsh/preflight/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}

	// Remove 'v' prefix if present
	return strings.TrimPrefix(release.TagName, "v"), nil
}

// isNewerVersion returns true if latest is newer than current
func isNewerVersion(latest, current string) bool {
	// Simple string comparison works for semver if both have same format
	// For more robust comparison, could use a semver library
	latestParts := strings.Split(latest, ".")
	currentParts := strings.Split(current, ".")

	for i := 0; i < len(latestParts) && i < len(currentParts); i++ {
		if latestParts[i] > currentParts[i] {
			return true
		}
		if latestParts[i] < currentParts[i] {
			return false
		}
	}

	return len(latestParts) > len(currentParts)
}

// getUpgradeCommand returns the appropriate upgrade command based on install method
func getUpgradeCommand() string {
	executable, err := os.Executable()
	if err != nil {
		return "curl -sSL https://preflight.sh/install.sh | sh"
	}

	path := strings.ToLower(executable)

	if strings.Contains(path, "homebrew") || strings.Contains(path, "cellar") || strings.Contains(path, "/opt/homebrew") {
		return "brew upgrade preflightsh/preflight/preflight"
	}

	if strings.Contains(path, "node_modules") || strings.Contains(path, ".npm") {
		return "npm update -g @preflightsh/preflight"
	}

	if strings.Contains(path, "/go/bin") || strings.Contains(path, "gopath") {
		return "go install github.com/preflightsh/preflight@latest"
	}

	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker pull ghcr.io/preflightsh/preflight:latest"
	}

	return "curl -sSL https://preflight.sh/install.sh | sh"
}
