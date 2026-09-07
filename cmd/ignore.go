package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/preflightsh/preflight/internal/catalog"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var ignoreCmd = &cobra.Command{
	Use:   "ignore <check-id> [path]",
	Short: "Add a check to the ignore list",
	Long: `Add a check ID to the ignore list in preflight.yml.
The check will be skipped in future scans.

Example:
  preflight ignore sitemap
  preflight ignore llmsTxt
  preflight ignore debug_statements

To allowlist a single file from the secrets scan (rather than silencing
the whole check), pass "secrets" and a project-relative path:

  preflight ignore secrets web/js/golden-hour.js`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runIgnore,
}

func init() {
	rootCmd.AddCommand(ignoreCmd)
}

func runIgnore(cmd *cobra.Command, args []string) error {
	checkID := args[0]

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	configPath := filepath.Join(cwd, "preflight.yml")

	// Read existing config
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("preflight.yml not found. Run 'preflight init' first")
		}
		return fmt.Errorf("failed to read config: %w", err)
	}

	// Parse as generic map to preserve structure
	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse preflight.yml: %w", err)
	}

	// Two-arg form: `preflight ignore secrets <path>` → append an
	// allowlist entry instead of silencing the whole check.
	if len(args) == 2 {
		if checkID != "secrets" {
			return fmt.Errorf("per-path ignore is only supported for 'secrets' (got %q)", checkID)
		}
		return addSecretsAllowlistEntry(configPath, cfg, args[1])
	}

	// Get or create ignore list
	var ignoreList []string
	if existing, ok := cfg["ignore"]; ok {
		if list, ok := existing.([]interface{}); ok {
			for _, item := range list {
				if s, ok := item.(string); ok {
					ignoreList = append(ignoreList, s)
				}
			}
		}
	}

	// Check if already ignored
	for _, id := range ignoreList {
		if id == checkID {
			fmt.Printf("'%s' is already in the ignore list\n", checkID)
			return nil
		}
	}

	// Add to ignore list
	ignoreList = append(ignoreList, checkID)
	cfg["ignore"] = ignoreList

	// Write back
	newData, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}

	if err := os.WriteFile(configPath, newData, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("Added '%s' to ignore list\n", checkID)
	return nil
}

// addSecretsAllowlistEntry appends {path: <path>} to
// checks.secrets.allowlist in preflight.yml. It does not set a
// fingerprint — users can edit the file to pin one (recommended; see
// README). Intermediate maps and lists are created as needed.
func addSecretsAllowlistEntry(configPath string, cfg map[string]interface{}, path string) error {
	checksRaw, _ := cfg["checks"].(map[string]interface{})
	if checksRaw == nil {
		checksRaw = map[string]interface{}{}
		cfg["checks"] = checksRaw
	}

	secretsRaw, _ := checksRaw["secrets"].(map[string]interface{})
	if secretsRaw == nil {
		secretsRaw = map[string]interface{}{"enabled": true}
		checksRaw["secrets"] = secretsRaw
	}

	var allowlist []interface{}
	if existing, ok := secretsRaw["allowlist"].([]interface{}); ok {
		allowlist = existing
	}

	// De-dupe: if an entry with the same path already exists, do nothing
	for _, item := range allowlist {
		if entry, ok := item.(map[string]interface{}); ok {
			if p, _ := entry["path"].(string); p == path {
				fmt.Printf("'%s' is already in the secrets allowlist\n", path)
				return nil
			}
		}
	}

	allowlist = append(allowlist, map[string]interface{}{"path": path})
	secretsRaw["allowlist"] = allowlist

	newData, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}
	if err := os.WriteFile(configPath, newData, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("Added '%s' to secrets allowlist. Consider adding a fingerprint to re-alert on key rotation (see README).\n", path)
	return nil
}

// Also add an unignore command
var unignoreCmd = &cobra.Command{
	Use:   "unignore <check-id>",
	Short: "Remove a check from the ignore list",
	Long: `Remove a check ID from the ignore list in preflight.yml.

Example:
  preflight unignore sitemap`,
	Args: cobra.ExactArgs(1),
	RunE: runUnignore,
}

func init() {
	rootCmd.AddCommand(unignoreCmd)
}

func runUnignore(cmd *cobra.Command, args []string) error {
	checkID := args[0]

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	configPath := filepath.Join(cwd, "preflight.yml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("preflight.yml not found. Run 'preflight init' first")
		}
		return fmt.Errorf("failed to read config: %w", err)
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse preflight.yml: %w", err)
	}

	// Get ignore list
	var ignoreList []string
	if existing, ok := cfg["ignore"]; ok {
		if list, ok := existing.([]interface{}); ok {
			for _, item := range list {
				if s, ok := item.(string); ok {
					ignoreList = append(ignoreList, s)
				}
			}
		}
	}

	// Find and remove
	found := false
	var newList []string
	for _, id := range ignoreList {
		if id == checkID {
			found = true
		} else {
			newList = append(newList, id)
		}
	}

	if !found {
		fmt.Printf("'%s' is not in the ignore list\n", checkID)
		return nil
	}

	// Update or remove ignore key
	if len(newList) > 0 {
		cfg["ignore"] = newList
	} else {
		delete(cfg, "ignore")
	}

	newData, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}

	if err := os.WriteFile(configPath, newData, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("Removed '%s' from ignore list\n", checkID)
	return nil
}

// listChecksCmd prints every ignorable ID, grouped the way the catalog
// groups them, so a service added there is listed here without a second
// hand-maintained list drifting out of date.
var listChecksCmd = &cobra.Command{
	Use:   "checks",
	Short: "List all available check and service IDs that can be ignored",
	RunE: func(cmd *cobra.Command, args []string) error {
		printCatalog(os.Stdout)
		return nil
	},
}

func printCatalog(w io.Writer) {
	fmt.Fprintln(w, "=== Checks ===")
	fmt.Fprintln(w)
	group := ""
	for _, c := range catalog.Checks {
		if c.Group != group {
			if group != "" {
				fmt.Fprintln(w)
			}
			group = c.Group
			fmt.Fprintf(w, "%s:\n", group)
		}
		suffix := ""
		if c.OptIn {
			suffix = " (opt-in)"
		}
		fmt.Fprintf(w, "  - %s%s\n", c.ID, suffix)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "=== Services (with validation checks) ===")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "These services have checks that verify proper integration:")
	fmt.Fprintln(w)
	group = ""
	for _, s := range catalog.Services {
		if s.ID == "indexnow" {
			continue // listed above as the indexNow check
		}
		if s.Group != group {
			if group != "" {
				fmt.Fprintln(w)
			}
			group = s.Group
			fmt.Fprintf(w, "%s:\n", group)
		}
		fmt.Fprintf(w, "  - %s: %s\n", s.ID, s.Description)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Use 'preflight ignore <id>' to silence a check or service")
	fmt.Fprintln(w, "Use 'preflight unignore <id>' to re-enable it")
}

func init() {
	rootCmd.AddCommand(listChecksCmd)
}
