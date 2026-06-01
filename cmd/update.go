package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const updateCheckInterval = 24 * time.Hour

// noUpdateCheckEnv disables the update check entirely when set to a non-empty
// value. It is also set on the re-exec'd process after an in-place upgrade so
// the freshly launched binary doesn't immediately prompt again.
const noUpdateCheckEnv = "PREFLIGHT_NO_UPDATE_CHECK"

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

	// Allow opting out, and avoid re-prompting on the process we re-exec
	// after an in-place upgrade.
	if os.Getenv(noUpdateCheckEnv) != "" {
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
		upgradeCmd := getUpgradeCommand()
		fmt.Println()
		fmt.Printf("📦 A new version of Preflight is available: %s → %s\n", version, latest)

		// For the `curl ... | sh` path we refuse to auto-execute. Piping a
		// network-fetched script into a shell on the user's machine is too
		// risky for an auto-prompt, even over HTTPS. Just print the command.
		if strings.Contains(upgradeCmd, "|") {
			fmt.Printf("   To upgrade: %s\n", upgradeCmd)
			fmt.Println()
			return
		}

		// Print the command first so the user sees exactly what will run.
		fmt.Printf("   Will run: %s\n", upgradeCmd)
		fmt.Print("   Install now? [y/N] ")

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("   To upgrade later: %s\n", upgradeCmd)
			return
		}

		// Require explicit Y; default (empty input) is No.
		response = strings.TrimSpace(strings.ToLower(response))
		if response == "y" || response == "yes" {
			if runUpgrade(upgradeCmd) {
				// The current process still holds the pre-upgrade binary in
				// memory; without handing off, the rest of this invocation
				// runs stale logic. This does not return on success.
				relaunchAfterUpgrade()
			}
		} else {
			fmt.Printf("   To upgrade later: %s\n", upgradeCmd)
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

// runUpgrade executes an already-vetted upgrade command and reports whether it
// succeeded. The caller is responsible for gating any `curl | sh` style
// commands, which this function will refuse for safety.
func runUpgrade(upgradeCmd string) bool {
	if strings.Contains(upgradeCmd, "|") {
		// Defense in depth: CheckForUpdates is supposed to filter these
		// out already, but make sure we never pipe untrusted bytes into
		// a shell from this code path.
		fmt.Printf("   ✗ Refusing to auto-run piped shell command: %s\n", upgradeCmd)
		return false
	}

	fmt.Printf("   Running: %s\n", upgradeCmd)
	parts := strings.Fields(upgradeCmd)
	if len(parts) == 0 {
		fmt.Println("   ✗ Could not determine upgrade command")
		return false
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("   ✗ Upgrade failed: %v\n", err)
		return false
	}

	fmt.Println("   ✓ Upgrade complete!")
	return true
}

// relaunchAfterUpgrade hands the user's original command off to the
// just-installed binary. The current process still has the pre-upgrade binary
// loaded in memory, so without this the rest of the invocation keeps running
// stale logic (e.g. service detection from before a fix). On Unix this re-execs
// in place and never returns; if re-exec is unsupported (Windows) or fails, it
// prints a re-run hint and exits so we never silently continue on old code.
func relaunchAfterUpgrade() {
	fmt.Println("   ↻ Restarting with the new version...")
	fmt.Println()
	if err := execNewBinary(); err != nil {
		fmt.Println("   Please re-run your command to use the new version.")
	}
	os.Exit(0)
}

// resolveNewBinary returns an absolute path to the preflight binary to re-exec
// after an upgrade. It prefers a fresh PATH lookup of the invoked name because
// os.Executable() can point at the previous version's install directory (e.g. a
// Homebrew Cellar/<old-version> path) that the upgrade just deleted; the PATH
// entry (a symlink/shim) already targets the newly installed binary.
func resolveNewBinary() (string, error) {
	if name := os.Args[0]; name != "" {
		if bin, err := exec.LookPath(name); err == nil {
			if abs, err := filepath.Abs(bin); err == nil {
				return abs, nil
			}
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Abs(exe)
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

// isNewerVersion returns true if latest is newer than current. Uses
// semver comparison which understands pre-release ordering and handles
// non-numeric suffixes correctly (e.g. "1.2.3-rc1" < "1.2.3").
func isNewerVersion(latest, current string) bool {
	l := normalizeSemver(latest)
	c := normalizeSemver(current)
	if !semver.IsValid(l) || !semver.IsValid(c) {
		return false
	}
	return semver.Compare(l, c) > 0
}

// normalizeSemver ensures the version has a leading "v" for semver pkg.
func normalizeSemver(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
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
