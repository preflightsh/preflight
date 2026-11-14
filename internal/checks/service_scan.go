package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// SearchMatch contains details about a pattern match
type SearchMatch struct {
	FilePath string
	Pattern  string
}

// codeGroup is one search of the project's source: the patterns that show an
// integration is wired up.
type codeGroup struct {
	// patterns are matched against dependency manifests (dependency names
	// only), the stack's layout files, and every source file.
	patterns []*regexp.Regexp
	// deps are matched against dependency manifests only. A dependency name
	// is a looser signal than anything accepted in source, where the same
	// word turns up in prose.
	deps []*regexp.Regexp
	// sourceOnly leaves the manifests and layout files out: the caller reads
	// manifests itself, with patterns of its own.
	sourceOnly bool
	// hashByExt strips "#" line comments only in Ruby and Python files. The
	// default strips them everywhere, which suits template and script-tag
	// patterns; an SDK call can sit on a line that starts with "#" in other
	// languages (a private class field).
	hashByExt bool
}

// sourceExtensions are the file types a source search looks inside.
var sourceExtensions = map[string]bool{
	// JavaScript/TypeScript
	".tsx": true, ".jsx": true, ".js": true, ".ts": true, ".mjs": true, ".cjs": true,
	// PHP
	".php": true,
	// Template engines
	".twig": true, ".erb": true, ".haml": true, ".slim": true,
	".ejs": true, ".pug": true, ".hbs": true, ".handlebars": true, ".mustache": true,
	".njk": true, ".liquid": true,
	// HTML
	".html": true, ".htm": true,
	// Frontend frameworks
	".vue": true, ".svelte": true, ".astro": true,
	// Python
	".py": true,
	// Ruby
	".rb": true,
	// Go
	".go": true, ".tmpl": true, ".gohtml": true,
	".rs": true, ".java": true, ".kt": true, ".kts": true, ".cs": true, ".ex": true, ".exs": true,
}

// reSameLineBlockComment matches a /* ... */ comment that opens and closes
// on one line. The space after the opener keeps the "/**/" of a glob
// ('src/**/*.ts') out.
var reSameLineBlockComment = regexp.MustCompile(`/\*\s[^\n]*?\*/`)

// stripSourceComments removes comments from source before it is matched.
// Unlike stripCodeComments it does not treat every "/*" as a comment opener:
// in `route('/api/*')` that blanked the file up to the next "*/", and the
// SDK call a check was looking for went with it. A block comment counts
// when it opens a line or closes on the line it opened.
func stripSourceComments(content string, hash bool) string {
	content = protectURLSlashes(content)
	content = reLeadingBlockComment.ReplaceAllString(content, "")
	content = reSameLineBlockComment.ReplaceAllString(content, "")
	content = reSingleLineComment.ReplaceAllString(content, "")
	content = reHTMLComment.ReplaceAllString(content, "")
	content = reTwigComment.ReplaceAllString(content, "")
	content = reERBComment.ReplaceAllString(content, "")
	content = restoreURLSlashes(content)
	if hash {
		content = reHashLineComment.ReplaceAllString(content, "")
	}
	return content
}

// sourceText hands out one file's content with comments stripped, computing
// each form at most once however many groups ask.
type sourceText struct {
	raw        string
	hashByExt  bool // this file's language comments with "#"
	full, code *string
}

func (t *sourceText) get(g codeGroup) string {
	if !g.hashByExt || t.hashByExt {
		if t.full == nil {
			s := stripSourceComments(t.raw, true)
			t.full = &s
		}
		return *t.full
	}
	if t.code == nil {
		s := stripSourceComments(t.raw, false)
		t.code = &s
	}
	return *t.code
}

var patternLiterals sync.Map // *regexp.Regexp -> []string

// mayMatch reports whether p could match text, given text lowercased. It is
// a cheap necessary condition: every match of p contains one of the
// literals requiredLiterals finds, so a text with none of them cannot match.
// A pattern with no such literals always may.
func mayMatch(p *regexp.Regexp, lower string) bool {
	cached, ok := patternLiterals.Load(p)
	if !ok {
		var lits []string
		if parsed, err := syntax.Parse(p.String(), syntax.Perl); err == nil {
			if found, ok := requiredLiterals(parsed); ok {
				lits = found
			}
		}
		cached, _ = patternLiterals.LoadOrStore(p, lits)
	}
	lits := cached.([]string)
	if len(lits) == 0 {
		return true
	}
	for _, lit := range lits {
		if strings.Contains(lower, lit) {
			return true
		}
	}
	return false
}

// requiredLiterals returns lowercased literals of which every match of re
// must contain at least one. ok is false when no such set is found.
func requiredLiterals(re *syntax.Regexp) (lits []string, ok bool) {
	switch re.Op {
	case syntax.OpLiteral:
		lit := strings.ToLower(string(re.Rune))
		// Lowercasing can change a non-ASCII literal's bytes in ways that
		// differ from lowercasing the text around it; only ASCII is used.
		for _, r := range lit {
			if r > 127 {
				return nil, false
			}
		}
		return []string{lit}, len(lit) >= 2
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiterals(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLiterals(re.Sub[0])
		}
	case syntax.OpConcat:
		// Any one part's literals will do; take the most selective (the
		// longest shortest literal).
		best := 0
		for _, sub := range re.Sub {
			if found, ok := requiredLiterals(sub); ok {
				if n := shortest(found); n > best {
					lits, best = found, n
				}
			}
		}
		return lits, best > 0
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			found, ok := requiredLiterals(sub)
			if !ok {
				return nil, false
			}
			lits = append(lits, found...)
		}
		return lits, len(lits) > 0
	}
	return nil, false
}

func shortest(lits []string) int {
	n := len(lits[0])
	for _, l := range lits[1:] {
		n = min(n, len(l))
	}
	return n
}

func firstMatch(patterns []*regexp.Regexp, text string) (string, bool) {
	for _, p := range patterns {
		if p.MatchString(text) {
			return p.String(), true
		}
	}
	return "", false
}

// scanSource runs every group over the project in one pass and returns the
// first match for each group that has one. One pass matters: each declared
// service used to walk the whole tree on its own, and a project declaring
// twenty of them read every file twenty times.
func scanSource(ctx context.Context, rootDir, stack string, groups map[string]codeGroup) map[string]*SearchMatch {
	found := map[string]*SearchMatch{}
	if len(groups) == 0 {
		return found
	}
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	// A declared dependency in a package manifest counts as the integration
	// being present, since credentials are often managed outside the repo.
	for _, name := range dependencyManifests {
		content, err := readSourceFile(filepath.Join(rootDir, name))
		if err != nil {
			continue
		}
		deps := manifestDependencies(name, content)
		for _, id := range ids {
			g := groups[id]
			if found[id] != nil || g.sourceOnly {
				continue
			}
			if _, ok := firstMatch(g.patterns, deps); ok {
				found[id] = &SearchMatch{FilePath: name, Pattern: "dependency manifest"}
			} else if _, ok := firstMatch(g.deps, deps); ok {
				found[id] = &SearchMatch{FilePath: name, Pattern: "dependency manifest"}
			}
		}
	}

	match := func(path string, content []byte, layout bool) {
		ext := filepath.Ext(path)
		text := &sourceText{raw: string(content), hashByExt: ext == ".rb" || ext == ".py"}
		lower := strings.ToLower(text.raw)
		for _, id := range ids {
			g := groups[id]
			if found[id] != nil || (layout && g.sourceOnly) {
				continue
			}
			for _, p := range g.patterns {
				// Most files mention no service at all. A substring test
				// for the literal a pattern needs is far cheaper than the
				// pattern, and spares stripping the file's comments.
				if !mayMatch(p, lower) {
					continue
				}
				if p.MatchString(text.get(g)) {
					found[id] = &SearchMatch{FilePath: relPath(rootDir, path), Pattern: p.String()}
					break
				}
			}
		}
	}

	// The stack's layout files first: they are where a script tag lives, and
	// some sit in directories the walk stays out of (dist/index.html).
	for _, file := range stackLayoutFiles(stack) {
		if len(found) == len(groups) {
			return found
		}
		path := filepath.Join(rootDir, file)
		if content, err := readSourceFile(path); err == nil {
			match(path, content, true)
		}
	}

	policy := walkPolicy{root: rootDir, tracked: loadTrackedFiles(ctx, rootDir)}
	walkSource(ctx, policy, func(path string, content []byte) bool {
		match(path, content, false)
		return len(found) == len(groups)
	})
	return found
}

// sourceWalks counts walks of a project's source, so a test can hold the
// service checks to one walk per scan.
var sourceWalks atomic.Int64

// walkSource calls visit with the content of every source file the policy
// allows, until visit returns true or ctx is cancelled.
func walkSource(ctx context.Context, policy walkPolicy, visit func(path string, content []byte) bool) bool {
	sourceWalks.Add(1)
	done := false
	_ = filepath.WalkDir(policy.root, func(path string, d os.DirEntry, err error) error {
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil {
			return nil
		}
		// Never skip the root itself (a project can live in a directory
		// named build or deps).
		if d.IsDir() {
			if path != policy.root && policy.skipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !sourceExtensions[filepath.Ext(path)] || policy.skipFile(path) {
			return nil
		}
		content, err := readSourceFile(path)
		if err != nil {
			return nil
		}
		if visit(path, content) {
			done = true
			return filepath.SkipAll
		}
		return nil
	})
	return done
}

// walkSourceFiles calls visit with the content of every source file in the
// project, skipping dependency trees and build output, until visit returns
// true. It reports whether visit did.
func walkSourceFiles(rootDir string, visit func(path string, content []byte) bool) bool {
	ctx := context.Background()
	return walkSource(ctx, walkPolicy{root: rootDir, tracked: loadTrackedFiles(ctx, rootDir)}, visit)
}

// searchForPatternsWithDetails searches the project for patterns and returns
// details about the first match, or nil.
func searchForPatternsWithDetails(rootDir, stack string, patterns []*regexp.Regexp) *SearchMatch {
	return scanSource(context.Background(), rootDir, stack, map[string]codeGroup{"": {patterns: patterns}})[""]
}

func searchForPatterns(rootDir, stack string, patterns []*regexp.Regexp) bool {
	return searchForPatternsWithDetails(rootDir, stack, patterns) != nil
}

// dependencyManifests are the package manifests scanned for an integration's
// library name. A declared dependency (craft-amazon-ses in composer.json,
// @sendgrid/mail in package.json) means the integration is installed even
// when its credentials live outside the repo (a CMS control panel, a
// platform's environment), so a service check shouldn't report it as
// unconfigured.
var dependencyManifests = []string{
	"composer.json", "package.json", "Gemfile",
	"requirements.txt", "pyproject.toml", "Pipfile", "go.mod",
}

// reManifestProse matches the pyproject.toml fields that describe the
// project in words.
var reManifestProse = regexp.MustCompile(`(?m)^\s*(?:description|keywords|name|authors|maintainers|readme|classifiers)\s*=.*$`)

// manifestDependencies returns the part of a package manifest that names
// dependencies. A manifest also describes the project in prose, and
// `"description": "take payments with stripe"` is not Stripe being
// installed.
//
// JSON manifests come back as one `"name": "version"` line per dependency,
// followed by the package.json scripts (`wrangler deploy` is how some
// tooling shows up). The rest come back with comments stripped.
func manifestDependencies(name string, content []byte) string {
	sections := map[string][]string{
		"package.json":  {"dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "scripts"},
		"composer.json": {"require", "require-dev"},
	}[name]
	if sections == nil {
		text := stripComments(string(content))
		if name == "pyproject.toml" {
			text = reManifestProse.ReplaceAllString(text, "")
		}
		return text
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(content, &doc) != nil {
		return ""
	}
	var b strings.Builder
	for _, section := range sections {
		var entries map[string]any
		if json.Unmarshal(doc[section], &entries) != nil {
			continue
		}
		names := make([]string, 0, len(entries))
		for k := range entries {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			value, _ := entries[k].(string)
			if section == "scripts" {
				b.WriteString(value + "\n")
				continue
			}
			b.WriteString(`"` + k + `": "` + value + "\"\n")
		}
	}
	return b.String()
}

// sourceScan is one scan's shared search: every declared service's group,
// run once.
type sourceScan struct {
	once    sync.Once
	results map[string]*SearchMatch
}

type sourceScanKey struct {
	ctx  context.Context
	root string
}

var sourceScans sync.Map // sourceScanKey -> *sourceScan

// serviceCodeMatch returns where the project's code or manifests show the
// service id wired up, or nil.
//
// During a scan the answer for every declared service is computed together,
// by the first check that asks, and shared through the scan's context.
// Without a cancellable scan context (tests, init) only this service is
// searched for, and nothing is kept.
func (c Context) serviceCodeMatch(id string) *SearchMatch {
	groups := serviceCodeGroups()
	group, ok := groups[id]
	if !ok {
		return nil
	}
	stack := ""
	if c.Config != nil {
		stack = c.Config.Stack
	}
	if c.Ctx == nil || c.Ctx.Done() == nil || c.Config == nil || !reflect.TypeOf(c.Ctx).Comparable() {
		return scanSource(c.reqContext(), c.RootDir, stack, map[string]codeGroup{id: group})[id]
	}

	key := sourceScanKey{ctx: c.Ctx, root: c.RootDir}
	entry, loaded := sourceScans.LoadOrStore(key, &sourceScan{})
	scan := entry.(*sourceScan)
	if !loaded {
		context.AfterFunc(c.Ctx, func() { sourceScans.Delete(key) })
	}
	scan.once.Do(func() {
		declared := map[string]codeGroup{id: group}
		for sid, svc := range c.Config.Services {
			if g, ok := groups[sid]; ok && svc.Declared {
				declared[sid] = g
			}
		}
		scan.results = scanSource(c.Ctx, c.RootDir, stack, declared)
	})
	if m, ok := scan.results[id]; ok || c.Config.Services[id].Declared {
		return m
	}
	// The shared pass covers the declared services. One that is not
	// declared (no check asks about those in a scan) is searched on its own.
	return scanSource(c.Ctx, c.RootDir, stack, map[string]codeGroup{id: group})[id]
}
