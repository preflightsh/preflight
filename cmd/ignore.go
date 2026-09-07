package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/preflightsh/preflight/internal/catalog"
	"github.com/preflightsh/preflight/internal/checks"
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

	configPath, root, err := loadConfigDocument()
	if err != nil {
		return err
	}

	// Two-arg form: `preflight ignore secrets <path>` appends an allowlist
	// entry instead of silencing the whole check.
	if len(args) == 2 {
		if checkID != "secrets" {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("per-path ignore is only supported for 'secrets' (got %q)", checkID)}
		}
		return addSecretsAllowlistEntry(configPath, root, args[1])
	}

	// A typo used to be accepted and written to the file, so `preflight
	// ignore sitemapp` reported success and silenced nothing. The list
	// also holds file globs for the debug-statements scan, which are let
	// through by shape.
	if !checks.KnownID(checkID) && !looksLikeGlob(checkID) {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("unknown check ID %q (run 'preflight checks' to list IDs)", checkID)}
	}

	ignoreList := ensureSequence(root, "ignore")
	for _, item := range ignoreList.Content {
		if item.Value == checkID {
			fmt.Printf("'%s' is already in the ignore list\n", checkID)
			return nil
		}
	}
	ignoreList.Content = append(ignoreList.Content, scalarNode(checkID))

	if err := writeConfigDocument(configPath, root); err != nil {
		return err
	}
	fmt.Printf("Added '%s' to ignore list\n", checkID)
	return nil
}

// looksLikeGlob reports whether an ignore entry is a file pattern rather
// than a check ID. Check IDs are bare identifiers; anything with a path
// separator, a glob metacharacter or an extension is a pattern.
func looksLikeGlob(s string) bool {
	return strings.ContainsAny(s, "/*?[.")
}

// addSecretsAllowlistEntry appends {path: <path>} to
// checks.secrets.allowlist in preflight.yml. It does not set a
// fingerprint; users can edit the file to pin one (recommended; see
// README). Intermediate maps and lists are created as needed.
func addSecretsAllowlistEntry(configPath string, root *yaml.Node, path string) error {
	secrets := ensureMapping(ensureMapping(root, "checks"), "secrets")
	if mappingValue(secrets, "enabled") == nil {
		secrets.Content = append(secrets.Content, scalarNode("enabled"), &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	}
	allowlist := ensureSequence(secrets, "allowlist")

	for _, entry := range allowlist.Content {
		if p := mappingValue(entry, "path"); p != nil && p.Value == path {
			fmt.Printf("'%s' is already in the secrets allowlist\n", path)
			return nil
		}
	}
	allowlist.Content = append(allowlist.Content, &yaml.Node{
		Kind:    yaml.MappingNode,
		Content: []*yaml.Node{scalarNode("path"), scalarNode(path)},
	})

	if err := writeConfigDocument(configPath, root); err != nil {
		return err
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

	configPath, root, err := loadConfigDocument()
	if err != nil {
		return err
	}

	ignoreList := mappingValue(root, "ignore")
	found := false
	if ignoreList != nil && ignoreList.Kind == yaml.SequenceNode {
		kept := ignoreList.Content[:0]
		for _, item := range ignoreList.Content {
			if item.Value == checkID {
				found = true
				continue
			}
			kept = append(kept, item)
		}
		ignoreList.Content = kept
	}

	if !found {
		fmt.Printf("'%s' is not in the ignore list\n", checkID)
		return nil
	}

	if len(ignoreList.Content) == 0 {
		removeMappingKey(root, "ignore")
	}

	if err := writeConfigDocument(configPath, root); err != nil {
		return err
	}
	fmt.Printf("Removed '%s' from ignore list\n", checkID)
	return nil
}

// The ignore commands edit preflight.yml as a yaml.Node tree rather than
// decoding it into a map. A map round-trip drops every comment, sorts the
// keys alphabetically and re-indents the file, so a one-line change
// rewrote the user's whole config; the node tree keeps comments, key
// order and formatting, and only the edited entries move.

// loadConfigDocument reads ./preflight.yml and returns the root mapping
// node, creating an empty one for an empty file.
func loadConfigDocument() (string, *yaml.Node, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", nil, fmt.Errorf("failed to get current directory: %w", err)
	}
	configPath := filepath.Join(cwd, "preflight.yml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil, &ExitError{Code: ExitUsage, Err: fmt.Errorf("preflight.yml not found. Run 'preflight init' first")}
		}
		return "", nil, &ExitError{Code: ExitUsage, Err: fmt.Errorf("failed to read config: %w", err)}
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", nil, &ExitError{Code: ExitUsage, Err: fmt.Errorf("failed to parse preflight.yml: %w", err)}
	}
	root := documentRoot(&doc)
	if root.Kind != yaml.MappingNode {
		return "", nil, &ExitError{Code: ExitUsage, Err: fmt.Errorf("preflight.yml is not a mapping")}
	}
	return configPath, root, nil
}

// documentRoot returns the top-level mapping of a parsed document, wiring
// an empty mapping into an empty document so callers can append to it.
func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == 0 {
		doc.Kind = yaml.DocumentNode
	}
	if len(doc.Content) == 0 {
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	return doc.Content[0]
}

func writeConfigDocument(configPath string, root *yaml.Node) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}
	if err := os.WriteFile(configPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	return nil
}

// mappingValue returns the value node for key in a mapping, or nil.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func removeMappingKey(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

// ensureMapping returns the mapping under key, creating it (appended at
// the end, so existing keys keep their order) when absent.
func ensureMapping(m *yaml.Node, key string) *yaml.Node {
	if v := mappingValue(m, key); v != nil && v.Kind == yaml.MappingNode {
		return v
	}
	removeMappingKey(m, key) // a scalar or null under this key is replaced
	v := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, scalarNode(key), v)
	return v
}

// ensureSequence is ensureMapping for a list-valued key.
func ensureSequence(m *yaml.Node, key string) *yaml.Node {
	if v := mappingValue(m, key); v != nil && v.Kind == yaml.SequenceNode {
		return v
	}
	removeMappingKey(m, key)
	v := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	m.Content = append(m.Content, scalarNode(key), v)
	return v
}

func scalarNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
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
