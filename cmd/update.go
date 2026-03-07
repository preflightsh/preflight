package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const updateCheckInterval = 24 * time.Hour

type githubRelease struct {
	TagName string `json:"tag_name"`
}

// CheckForUpdates checks if a newer version is available and prompts user to upgrade.
// Only checks once every 24 hours to avoid nagging the user.
func CheckForUpdates() {
	// Skip in CI mode or if version is dev
	if version == "dev" {
		return
	}

	if !shouldCheckForUpdate() {
		return
	}

	latest, err := fetchLatestVersion()
	if err != nil {
		// Silently fail - don't interrupt user workflow for update check failures
		return
	}

	// Record the check time regardless of whether an update is available
	markUpdateChecked()

	if isNewerVersion(latest, version) {
		fmt.Println()
		fmt.Printf("📦 A new version of Preflight is available: %s → %s\n", version, latest)
		fmt.Print("   Install now? [Y/n] ")

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			// If we can't read input, just show the command
			fmt.Printf("   Run: %s\n", getUpgradeCommand())
			return
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response == "" || response == "y" || response == "yes" {
			runUpgrade()
		} else {
			fmt.Printf("   To upgrade later: %s\n", getUpgradeCommand())
		}
		fmt.Println()
	}
}

// shouldCheckForUpdate returns true if enough time has passed since the last check
func shouldCheckForUpdate() bool {
	stateDir := getPreflightStateDir()
	if stateDir == "" {
		return true
	}

	checkFile := filepath.Join(stateDir, "last_update_check")
	data, err := os.ReadFile(checkFile)
	if err != nil {
		return true
	}

	lastCheck, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil {
		return true
	}

	return time.Since(lastCheck) >= updateCheckInterval
}

// markUpdateChecked records the current time as the last update check
func markUpdateChecked() {
	stateDir := getPreflightStateDir()
	if stateDir == "" {
		return
	}
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return
	}
	checkFile := filepath.Join(stateDir, "last_update_check")
	_ = os.WriteFile(checkFile, []byte(time.Now().UTC().Format(time.RFC3339)), 0644)
}

// runUpgrade executes the appropriate upgrade command
func runUpgrade() {
	upgradeCmd := getUpgradeCommand()
	fmt.Printf("   Running: %s\n", upgradeCmd)

	// Parse the command
	parts := strings.Fields(upgradeCmd)
	if len(parts) == 0 {
		fmt.Println("   ✗ Could not determine upgrade command")
		return
	}

	// Handle piped commands (curl ... | sh) safely without sh -c
	if strings.Contains(upgradeCmd, "|") {
		pipeParts := strings.SplitN(upgradeCmd, "|", 2)
		curlArgs := strings.Fields(strings.TrimSpace(pipeParts[0]))
		shArgs := strings.Fields(strings.TrimSpace(pipeParts[1]))

		curlCmd := exec.Command(curlArgs[0], curlArgs[1:]...)
		shCmd := exec.Command(shArgs[0])

		pipe, err := curlCmd.StdoutPipe()
		if err != nil {
			fmt.Printf("   ✗ Upgrade failed: %v\n", err)
			return
		}
		shCmd.Stdin = pipe
		shCmd.Stdout = os.Stdout
		shCmd.Stderr = os.Stderr
		curlCmd.Stderr = os.Stderr

		if err := shCmd.Start(); err != nil {
			fmt.Printf("   ✗ Upgrade failed: %v\n", err)
			return
		}
		if err := curlCmd.Run(); err != nil {
			fmt.Printf("   ✗ Upgrade failed: %v\n", err)
			return
		}
		if err := shCmd.Wait(); err != nil {
			fmt.Printf("   ✗ Upgrade failed: %v\n", err)
			return
		}
	} else {
		cmd := exec.Command(parts[0], parts[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("   ✗ Upgrade failed: %v\n", err)
			return
		}
	}

	fmt.Println("   ✓ Upgrade complete!")
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
	// Strip pre-release suffixes (e.g., "1.2.3-beta" -> "1.2.3")
	latest = strings.SplitN(latest, "-", 2)[0]
	current = strings.SplitN(current, "-", 2)[0]

	latestParts := strings.Split(latest, ".")
	currentParts := strings.Split(current, ".")

	// Compare up to the length of the shorter version
	maxLen := len(latestParts)
	if len(currentParts) > maxLen {
		maxLen = len(currentParts)
	}

	for i := 0; i < maxLen; i++ {
		var l, c int
		if i < len(latestParts) {
			l, _ = strconv.Atoi(latestParts[i])
		}
		if i < len(currentParts) {
			c, _ = strconv.Atoi(currentParts[i])
		}
		if l > c {
			return true
		}
		if l < c {
			return false
		}
	}

	return false
}

// getUpgradeCommand returns the appropriate upgrade command based on install method
func getUpgradeCommand() string {
	executable, err := os.Executable()
	if err != nil {
		return "curl -sSL https://preflight.sh/install.sh | sh"
	}

	// Resolve symlinks to detect the actual install method
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		resolved = executable
	}
	path := strings.ToLower(resolved)

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
