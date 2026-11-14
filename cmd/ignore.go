package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/preflightsh/preflight/internal/catalog"
	"github.com/preflightsh/preflight/internal/checks"
	"github.com/preflightsh/preflight/internal/config"
	"github.com/preflightsh/preflight/internal/fsutil"
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
  preflight ignore llms_txt
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
	if err := catalog.RenamedError(checkID); err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}

	doc, err := loadConfigDocument()
	if err != nil {
		return err
	}
	root := doc.root

	// Two-arg form: `preflight ignore secrets <path>` appends an allowlist
	// entry instead of silencing the whole check.
	if len(args) == 2 {
		if checkID != "secrets" {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("per-path ignore is only supported for 'secrets' (got %q)", checkID)}
		}
		return addSecretsAllowlistEntry(doc, args[1]) //nolint:gosec // G602: guarded by len(args) == 2 above
	}

	// A typo used to be accepted and written to the file, so `preflight
	// ignore sitemapp` reported success and silenced nothing. The list
	// also holds file globs for the debug-statements scan, which are let
	// through by shape.
	if !checks.KnownID(checkID) && !config.LooksLikeGlob(checkID) {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("unknown check ID %q (run 'preflight checks' to list IDs)", checkID)}
	}

	// Entries are compared by the check they select, so indexnow, indexNow
	// and index_now are one entry. A pre-1.0 spelling is rewritten in
	// place, so `preflight ignore seo_meta` is also how an old seoMeta
	// line, which scan now rejects, gets fixed; further spellings of the
	// same check are dropped.
	checkID = catalog.Canonical(checkID)
	hadList := mappingValue(root, "ignore") != nil
	ignoreList := ensureSequence(root, "ignore")
	edit := &listEdit{list: ignoreList, items: append([]*yaml.Node(nil), ignoreList.Content...)}
	var kept []*yaml.Node
	var first *yaml.Node
	var renamedFrom string
	dropped := 0
	for _, item := range ignoreList.Content {
		if ignoreEntryCheck(item.Value) != checkID {
			kept = append(kept, item)
			continue
		}
		if first != nil {
			dropped++
			edit.remove = append(edit.remove, item)
			continue
		}
		first = item
		if item.Value != checkID {
			if _, renamed := catalog.Renamed(item.Value); renamed {
				renamedFrom = item.Value
				edit.rename(item, checkID)
				item.Value = checkID
			}
		}
		kept = append(kept, item)
	}
	if first != nil {
		if renamedFrom == "" && dropped == 0 {
			fmt.Printf("'%s' is already in the ignore list\n", first.Value)
			return nil
		}
		ignoreList.Content = kept
		if err := doc.writeEdit(edit); err != nil {
			return err
		}
		if renamedFrom != "" {
			fmt.Printf("Renamed '%s' to '%s' in the ignore list\n", renamedFrom, checkID)
		}
		if dropped > 0 {
			fmt.Printf("Removed %d duplicate spelling(s) of '%s' from the ignore list\n", dropped, checkID)
		}
		return nil
	}
	ignoreList.Content = append(ignoreList.Content, scalarNode(checkID))
	edit.add = checkID
	edit.newList = !hadList

	if err := doc.writeEdit(edit); err != nil {
		return err
	}
	fmt.Printf("Added '%s' to ignore list\n", checkID)
	return nil
}

// ignoreEntryCheck returns the check an ignore entry selects, following a
// pre-1.0 rename and a service ID that a core check verifies.
func ignoreEntryCheck(entry string) string {
	if current, renamed := catalog.Renamed(entry); renamed {
		entry = current
	}
	return catalog.Canonical(entry)
}

// addSecretsAllowlistEntry appends {path: <path>} to
// checks.secrets.allowlist in preflight.yml. It does not set a
// fingerprint; users can edit the file to pin one (recommended; see
// README). Intermediate maps and lists are created as needed.
func addSecretsAllowlistEntry(doc *configDocument, path string) error {
	secrets := ensureMapping(ensureMapping(doc.root, "checks"), "secrets")
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

	if err := doc.write(); err != nil {
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
	checkID := ignoreEntryCheck(args[0])

	doc, err := loadConfigDocument()
	if err != nil {
		return err
	}
	root := doc.root

	ignoreList := mappingValue(root, "ignore")
	found := false
	var edit *listEdit
	if ignoreList != nil && ignoreList.Kind == yaml.SequenceNode {
		edit = &listEdit{list: ignoreList, items: append([]*yaml.Node(nil), ignoreList.Content...)}
		var kept []*yaml.Node
		for _, item := range ignoreList.Content {
			// Match the entry however it was spelled, so `unignore llms_txt`
			// also removes a pre-1.0 `llmsTxt` line, which scan rejects.
			if ignoreEntryCheck(item.Value) == checkID {
				found = true
				edit.remove = append(edit.remove, item)
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
		edit.dropKey = mappingKey(root, "ignore")
		removeMappingKey(root, "ignore")
	}

	if err := doc.writeEdit(edit); err != nil {
		return err
	}
	fmt.Printf("Removed '%s' from ignore list\n", checkID)
	return nil
}

// The ignore commands edit preflight.yml as a yaml.Node tree rather than
// decoding it into a map. A map round-trip drops every comment and sorts
// the keys alphabetically; the node tree keeps comments and key order.
// Re-encoding the tree still normalizes the layout (2-space indent, blank
// lines between sections dropped, CRLF to LF), so an edit to the ignore
// list is first tried as a change to just its own lines (see writeEdit),
// which leaves the rest of the file byte for byte as the user wrote it.
// The re-encoded tree is the fallback whenever that is not safe.

// configDocument is a parsed preflight.yml: the document node, its
// top-level mapping (which is what the edits touch), and, for a file the
// parser returned nothing for, the raw text. yaml.v3 yields no node at all
// for a file that holds only comments, so the comment has no node to live
// on and is kept as a preamble instead.
type configDocument struct {
	path     string
	preamble string
	raw      []byte
	doc      yaml.Node
	root     *yaml.Node
}

// loadConfigDocument reads ./preflight.yml, wiring an empty mapping into an
// empty document so callers can append to it.
func loadConfigDocument() (*configDocument, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, couldNotRun(fmt.Errorf("failed to get current directory: %w", err))
	}
	d := &configDocument{path: filepath.Join(cwd, "preflight.yml")}

	data, err := fsutil.ReadFile(d.path, 8<<20)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &ExitError{Code: ExitUsage, Err: fmt.Errorf("preflight.yml not found. Run 'preflight init' first")}
		}
		return nil, &ExitError{Code: ExitUsage, Err: fmt.Errorf("failed to read config: %w", err)}
	}

	d.raw = data
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&d.doc); err != nil && !errors.Is(err, io.EOF) {
		return nil, &ExitError{Code: ExitUsage, Err: fmt.Errorf("failed to parse preflight.yml: %w", err)}
	}
	// Preflight reads only the first YAML document. Writing the file back
	// would silently delete everything after a "---" separator.
	var second yaml.Node
	if err := dec.Decode(&second); err == nil || !errors.Is(err, io.EOF) {
		return nil, &ExitError{Code: ExitUsage, Err: fmt.Errorf("preflight.yml holds more than one YAML document (a \"---\" separator); Preflight reads only the first, so edit the file by hand or remove the extra documents")}
	}
	if d.doc.Kind == 0 {
		d.doc.Kind = yaml.DocumentNode
		if text := strings.TrimSpace(string(data)); text != "" {
			d.preamble = text + "\n"
		}
	}
	if len(d.doc.Content) == 0 {
		d.doc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	d.root = d.doc.Content[0]
	if d.root.Kind != yaml.MappingNode {
		return nil, &ExitError{Code: ExitUsage, Err: fmt.Errorf("preflight.yml is not a mapping")}
	}
	return d, nil
}

// write serializes the whole document back, so comments attached at the
// document level survive along with those on the keys.
func (d *configDocument) write() error {
	data, err := d.encode()
	if err != nil {
		return couldNotRun(fmt.Errorf("failed to serialize config: %w", err))
	}
	return d.save(data)
}

func (d *configDocument) save(data []byte) error {
	if err := fsutil.WriteFile(d.path, data, 0644); err != nil {
		return couldNotRun(fmt.Errorf("failed to write config: %w", err))
	}
	return nil
}

// encode serializes the node tree the way write does.
func (d *configDocument) encode() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(d.preamble)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&d.doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// listEdit describes a change to a block-style list of plain scalars in
// terms of the lines of the original file: items to delete, an item to
// respell, and one value to append. items is the list as it was parsed,
// whose nodes still carry their original line and column.
type listEdit struct {
	list    *yaml.Node
	items   []*yaml.Node
	remove  []*yaml.Node
	renamed *yaml.Node
	renameT string
	add     string
	newList bool       // the list did not exist; add creates it at the end
	dropKey *yaml.Node // the key to delete along with a now-empty list
}

func (e *listEdit) rename(item *yaml.Node, to string) {
	// Copy the position: the caller changes item.Value next.
	old := *item
	e.renamed = &old
	e.renameT = to
}

// writeEdit writes the document after an ignore-list change. It applies
// the change to the original text line by line and keeps that only when
// it parses to exactly what the re-encoded node tree parses to; anything
// the line edit cannot express (a flow-style list, quoted entries,
// comments attached to a removed entry) falls back to re-encoding.
func (d *configDocument) writeEdit(e *listEdit) error {
	encoded, err := d.encode()
	if err != nil {
		return couldNotRun(fmt.Errorf("failed to serialize config: %w", err))
	}
	if e != nil && d.preamble == "" {
		if spliced, ok := e.apply(d.raw); ok && sameYAML(spliced, encoded) {
			return d.save(spliced)
		}
	}
	return d.save(encoded)
}

// apply performs the edit on the original text. ok is false when any part
// of it cannot be done as a plain line change.
func (e *listEdit) apply(raw []byte) ([]byte, bool) {
	lines := strings.SplitAfter(string(raw), "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	ending := "\n"
	if len(lines) > 0 && strings.HasSuffix(lines[0], "\r\n") {
		ending = "\r\n"
	}
	// itemLine returns the 0-based index of the line holding item when
	// that line is exactly "<indent>- <value>".
	itemLine := func(item *yaml.Node) (int, bool) {
		i := item.Line - 1
		if item.Kind != yaml.ScalarNode || item.HeadComment != "" || item.LineComment != "" || item.FootComment != "" || i < 0 || i >= len(lines) {
			return 0, false
		}
		text := strings.TrimRight(lines[i], "\r\n")
		col := item.Column - 1
		if col < 2 || col > len(text) || strings.TrimSpace(text[:col]) != "-" || strings.TrimRight(text[col:], " \t") != item.Value {
			return 0, false
		}
		return i, true
	}
	drop := map[int]bool{}
	for _, item := range e.remove {
		i, ok := itemLine(item)
		if !ok {
			return nil, false
		}
		drop[i] = true
	}
	if e.renamed != nil {
		i, ok := itemLine(e.renamed)
		if !ok {
			return nil, false
		}
		text := lines[i]
		lines[i] = text[:e.renamed.Column-1] + e.renameT + text[len(strings.TrimRight(text, " \t\r\n")):]
	}
	if e.dropKey != nil {
		i := e.dropKey.Line - 1
		if i < 0 || i >= len(lines) || strings.TrimSpace(lines[i]) != e.dropKey.Value+":" || e.dropKey.HeadComment != "" {
			return nil, false
		}
		drop[i] = true
	}
	insertAfter, newLines := -1, ""
	switch {
	case e.add == "":
	case e.newList:
		if len(lines) > 0 && !strings.HasSuffix(lines[len(lines)-1], "\n") {
			lines[len(lines)-1] += ending
		}
		insertAfter = len(lines) - 1
		newLines = "ignore:" + ending + "  - " + e.add + ending
	default:
		if len(e.items) == 0 {
			return nil, false
		}
		last := e.items[len(e.items)-1]
		i, ok := itemLine(last)
		if !ok {
			return nil, false
		}
		if !strings.HasSuffix(lines[i], "\n") {
			lines[i] += ending
		}
		insertAfter = i
		newLines = lines[i][:last.Column-1] + e.add + ending
	}
	var out strings.Builder
	if insertAfter == -1 && newLines != "" {
		out.WriteString(newLines)
	}
	for i, line := range lines {
		if !drop[i] {
			out.WriteString(line)
		}
		if i == insertAfter {
			out.WriteString(newLines)
		}
	}
	return []byte(out.String()), true
}

// sameYAML reports whether a and b are each a single YAML document with
// the same content.
func sameYAML(a, b []byte) bool {
	decode := func(data []byte) (any, bool) {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		var v, extra any
		if err := dec.Decode(&v); err != nil && !errors.Is(err, io.EOF) {
			return nil, false
		}
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, false
		}
		return v, true
	}
	va, okA := decode(a)
	vb, okB := decode(b)
	return okA && okB && reflect.DeepEqual(va, vb)
}

// mappingKey returns the key node for key in a mapping, or nil.
func mappingKey(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i]
		}
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
	Args:  cobra.NoArgs,
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
