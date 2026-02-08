package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
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

	// Handle piped commands (curl ... | sh)
	if strings.Contains(upgradeCmd, "|") {
		cmd := exec.Command("sh", "-c", upgradeCmd)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
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
	latestParts := strings.Split(latest, ".")
	currentParts := strings.Split(current, ".")

	for i := 0; i < len(latestParts) && i < len(currentParts); i++ {
		l, err1 := strconv.Atoi(latestParts[i])
		c, err2 := strconv.Atoi(currentParts[i])
		if err1 != nil || err2 != nil {
			if latestParts[i] > currentParts[i] {
				return true
			}
			if latestParts[i] < currentParts[i] {
				return false
			}
			continue
		}
		if l > c {
			return true
		}
		if l < c {
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
