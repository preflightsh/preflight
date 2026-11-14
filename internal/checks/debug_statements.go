package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

type DebugStatementsCheck struct{}

func (c DebugStatementsCheck) ID() string {
	return "debug_statements"
}

func (c DebugStatementsCheck) Title() string {
	return "Debug statements"
}

func (c DebugStatementsCheck) Run(ctx Context) (CheckResult, error) {
	findings := scanForDebugStatementsCtx(ctx.reqContext(), ctx.RootDir, ctx.Config.Ignore)

	if len(findings) == 0 {
		return CheckResult{
			ID:       c.ID(),
			Title:    c.Title(),
			Severity: SeverityInfo,
			Passed:   true,
			Message:  "No debug statements found",
		}, nil
	}

	// Limit findings shown
	maxFindings := 5
	message := fmt.Sprintf("Found %d debug statement(s)", len(findings))

	var suggestions []string
	for i, finding := range findings {
		if i >= maxFindings {
			suggestions = append(suggestions, fmt.Sprintf("... and %d more", len(findings)-maxFindings))
			break
		}
		suggestions = append(suggestions, finding)
	}

	return CheckResult{
		ID:          c.ID(),
		Title:       c.Title(),
		Severity:    SeverityWarn,
		Passed:      false,
		Message:     message,
		Suggestions: suggestions,
	}, nil
}

type debugPattern struct {
	pattern     *regexp.Regexp
	exclude     *regexp.Regexp // a match on the same line cancels the finding
	description string
	extensions  []string // file extensions to check (empty = all supported)
}

// reDebuggerStatement matches `debugger` used as a statement: alone on its
// line or between statement separators (`if (x) { debugger }`), with an
// optional semicolon, or as a Ruby modifier (`debugger if ENV["X"]`).
var reDebuggerStatement = regexp.MustCompile(`(?:^|[;{}])\s*debugger\s*(?:;|\}|$|\s+(?:if|unless)\b)`)

// reInlineCodeSpan matches a <code> or <pre> element opened and closed on
// the same line: documentation that names a debug call.
var reInlineCodeSpan = regexp.MustCompile(`(?i)<(code|pre)\b[^>]*>.*?</(?:code|pre)>`)

// phpExts are the files PHP debug helpers are looked for in. Drupal keeps
// PHP in .module, .inc, .theme, .install, and .profile files.
var phpExts = []string{".php", ".blade.php", ".module", ".inc", ".theme", ".install", ".profile"}

// debugPatterns are the debug statements looked for, by language.
var debugPatterns = []debugPattern{
	// JavaScript/TypeScript (including templates with inline scripts)
	{
		pattern:     regexp.MustCompile(`\bconsole\.(log|debug|info|trace|dir|table)\s*\(`),
		description: "console.log",
		extensions:  []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".htm", ".twig", ".blade.php", ".erb", ".ejs", ".hbs", ".njk", ".astro"},
	},
	{
		// The statement, not the word: "og-debugger" in a string or
		// <code>debugger</code> in docs is not a breakpoint.
		pattern:     reDebuggerStatement,
		description: "debugger",
		extensions:  []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".htm", ".twig", ".blade.php", ".erb", ".ejs", ".hbs", ".njk", ".astro"},
	},

	// Ruby
	{
		pattern:     regexp.MustCompile(`\bbinding\.pry\b`),
		description: "binding.pry",
		extensions:  []string{".rb", ".erb", ".rake"},
	},
	{
		pattern:     regexp.MustCompile(`\bbyebug\b`),
		description: "byebug",
		extensions:  []string{".rb", ".erb", ".rake"},
	},
	{
		pattern:     regexp.MustCompile(`\bbinding\.irb\b`),
		description: "binding.irb",
		extensions:  []string{".rb", ".erb", ".rake"},
	},
	{
		pattern:     reDebuggerStatement,
		description: "debugger",
		extensions:  []string{".rb", ".erb", ".rake"},
	},
	{
		// Kernel#pp called on a value. `pp = Struct.new`, `pp .new`, and
		// `pp: true` use the name for something else.
		pattern:     regexp.MustCompile(`(?:^|[^\w.@$:])pp[ \t]+[^\s=.,|&?:)\]}+\-*/%<>]`),
		description: "pp (pretty print)",
		extensions:  []string{".rb", ".erb", ".rake"},
	},

	// PHP
	{
		// The global helpers only: Yaml::dump($config), $dumper->dump()
		// and $collection->dd() are ordinary method calls.
		pattern:     regexp.MustCompile(`(?:^|[^\w:>.$])dd\s*\(`),
		description: "dd()",
		extensions:  phpExts,
	},
	{
		pattern:     regexp.MustCompile(`(?:^|[^\w:>.$])dump\s*\(`),
		description: "dump()",
		extensions:  phpExts,
	},
	{
		pattern:     regexp.MustCompile(`\bvar_dump\s*\(`),
		description: "var_dump()",
		extensions:  phpExts,
	},
	{
		// print_r($x, true) returns the string instead of printing it.
		pattern:     regexp.MustCompile(`\bprint_r\s*\(`),
		exclude:     regexp.MustCompile(`(?i)\bprint_r\s*\([^;]*,\s*true\s*\)`),
		description: "print_r()",
		extensions:  phpExts,
	},
	{
		// Drupal's Devel module.
		pattern:     regexp.MustCompile(`(?:^|[^\w:>.$])d(?:pm|sm|vm|pr)\s*\(`),
		description: "dpm()",
		extensions:  phpExts,
	},
	{
		pattern:     regexp.MustCompile(`(?:^|[^\w:>.$])k(?:int|sm)\s*\(`),
		description: "kint()",
		extensions:  phpExts,
	},
	{
		pattern:     regexp.MustCompile(`\bray\s*\(`),
		description: "ray() - Spatie Ray debugger",
		extensions:  phpExts,
	},

	// Python
	{
		pattern:     regexp.MustCompile(`\bbreakpoint\s*\(\s*\)`),
		description: "breakpoint()",
		extensions:  []string{".py"},
	},
	{
		pattern:     regexp.MustCompile(`\bpdb\.set_trace\s*\(`),
		description: "pdb.set_trace()",
		extensions:  []string{".py"},
	},
	{
		pattern:     regexp.MustCompile(`\bipdb\.set_trace\s*\(`),
		description: "ipdb.set_trace()",
		extensions:  []string{".py"},
	},
	{
		pattern:     regexp.MustCompile(`\bimport\s+pdb\b`),
		description: "import pdb",
		extensions:  []string{".py"},
	},
	{
		pattern:     regexp.MustCompile(`\bimport\s+ipdb\b`),
		description: "import ipdb",
		extensions:  []string{".py"},
	},

	// Go
	{
		pattern:     regexp.MustCompile(`\bfmt\.Print(ln|f)?\s*\([^)]*"DEBUG`),
		description: "fmt.Print with DEBUG",
		extensions:  []string{".go"},
	},
	{
		pattern:     regexp.MustCompile(`\bspew\.Dump\s*\(`),
		description: "spew.Dump()",
		extensions:  []string{".go"},
	},

	// Rust
	{
		pattern:     regexp.MustCompile(`\bdbg!\s*\(`),
		description: "dbg!()",
		extensions:  []string{".rs"},
	},
	{
		pattern:     regexp.MustCompile(`\btodo!\s*\(`),
		description: "todo!()",
		extensions:  []string{".rs"},
	},
	{
		pattern:     regexp.MustCompile(`\bunimplemented!\s*\(`),
		description: "unimplemented!()",
		extensions:  []string{".rs"},
	},

	// Java/Kotlin
	{
		pattern:     regexp.MustCompile(`\bSystem\.out\.print(ln)?\s*\(`),
		description: "System.out.println()",
		extensions:  []string{".java", ".kt"},
	},

	// Elixir
	{
		// With or without parentheses: `x |> IO.inspect` is the usual form.
		pattern:     regexp.MustCompile(`\bIO\.inspect\b`),
		description: "IO.inspect()",
		extensions:  []string{".ex", ".exs"},
	},
	{
		pattern:     regexp.MustCompile(`(?:^|[^\w.!])dbg\s*\(|\|>\s*dbg\b`),
		description: "dbg()",
		extensions:  []string{".ex", ".exs"},
	},
	{
		pattern:     regexp.MustCompile(`\bIEx\.pry\b`),
		description: "IEx.pry",
		extensions:  []string{".ex", ".exs"},
	},

	// Twig (Craft CMS, Symfony)
	{
		pattern:     regexp.MustCompile(`\{\{\s*(?:dump|kint)\s*\(`),
		description: "{{ dump() }}",
		extensions:  []string{".twig"},
	},
	{
		pattern:     regexp.MustCompile(`\{%\s*dump\s*`),
		description: "{% dump %}",
		extensions:  []string{".twig"},
	},
}

// debugPatternsByExt maps a file extension to the patterns that apply to
// it. Every pattern is scoped to extensions, so a file whose extension is
// not a key here is never read.
var debugPatternsByExt = func() map[string][]debugPattern {
	byExt := map[string][]debugPattern{}
	for _, p := range debugPatterns {
		for _, e := range p.extensions {
			byExt[e] = append(byExt[e], p)
		}
	}
	return byExt
}()

// Bundles, tests, and configs, matched anywhere in the file name.
var debugSkipInfixes = []string{
	".min.js",
	".bundle.js",
	".config.js",
	".config.ts",
	".test.",
	".spec.",
	".stories.",
	"_test.go",
	"_test.rb",
	"_spec.rb",
	"_test.py",
	"_test.exs",
}

// Build tooling and vendored libraries, matched as the start of the file
// name only: a bare substring hid members.ts ("ember"), moments.ts
// ("moment"), and piechart.tsx ("chart.") from the scan.
var debugSkipPrefixes = []string{
	"webpack.config",
	"vite.config",
	// Build scripts log to the terminal by design and never ship.
	"gulpfile",
	"gruntfile",
	"jest.config",
	"vitest.config",
	"tailwind.config",
	"postcss.config",
	"eslint",
	"eslintrc",
	"prettier",
	"prettierrc",
	"test_",
	"conftest.py",
	"alpine",
	"jquery",
	"lodash",
	"underscore",
	"react.",
	"react-dom",
	"vue.",
	"angular",
	"ember",
	"backbone",
	"moment",
	"axios",
	"d3.",
	"chart.",
	"three.",
	"gsap",
	"anime.",
	"htmx",
	"hyperscript",
	"turbo",
	"stimulus",
}

// debugSkipFile reports whether a lowercased file name is tooling, a test,
// or a vendored library.
func debugSkipFile(name string) bool {
	for _, s := range debugSkipInfixes {
		if strings.Contains(name, s) {
			return true
		}
	}
	name = strings.TrimLeft(name, ".") // .eslintrc.js, .prettierrc.cjs
	for _, p := range debugSkipPrefixes {
		if !strings.HasPrefix(name, p) {
			continue
		}
		// "jquery.js", "jquery-3.7.js", and "htmx_ext.js" are the library;
		// "moments.ts" and "turbocharge.ts" are the project's own code.
		rest := name[len(p):]
		if strings.HasSuffix(p, ".") || strings.HasSuffix(p, "_") || rest == "" || strings.ContainsRune(".-_", rune(rest[0])) {
			return true
		}
	}
	return false
}

// debugFileExt returns the extension debug patterns are keyed by.
func debugFileExt(path string) string {
	if strings.HasSuffix(path, ".blade.php") {
		return ".blade.php"
	}
	return strings.ToLower(filepath.Ext(path))
}

// hashCommentExts are the languages whose line comments start with "#".
var hashCommentExts = map[string]bool{".rb": true, ".rake": true, ".py": true, ".ex": true, ".exs": true}

// heredocExts are the languages with heredocs (see isInCodeExample).
var heredocExts = map[string]bool{
	".rb": true, ".rake": true, ".erb": true,
	".php": true, ".blade.php": true, ".module": true, ".inc": true, ".theme": true, ".install": true, ".profile": true,
}

// bundleExts are the files a bundler writes.
var bundleExts = map[string]bool{".js": true, ".mjs": true, ".cjs": true}

// hashCommentStart returns where a trailing "#" comment starts in a line
// whose string contents are already masked, or -1.
func hashCommentStart(masked string) int {
	for i := 0; i < len(masked); i++ {
		if masked[i] == '#' && (i == 0 || masked[i-1] == ' ' || masked[i-1] == '\t') {
			return i
		}
	}
	return -1
}

func scanForDebugStatements(rootDir string, ignore []string) []string {
	return scanForDebugStatementsCtx(context.Background(), rootDir, ignore)
}

// scanForDebugStatementsCtx walks the project's shipped source for debug
// statements. It stops, returning what it has, once ctx is cancelled.
func scanForDebugStatementsCtx(ctx context.Context, rootDir string, ignore []string) []string {
	var findings []string
	policy := walkPolicy{root: rootDir, tracked: loadTrackedFiles(ctx, rootDir), shipped: true}

	_ = filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if ctx.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if path != rootDir && policy.skipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip symlinks, devices, and pipes: the same path-traversal and
		// DoS concern as the secrets walker (a symlink to /dev/zero would
		// get past the size cap below).
		if !d.Type().IsRegular() {
			return nil
		}

		ext := debugFileExt(path)
		patterns := debugPatternsByExt[ext]
		if len(patterns) == 0 || debugSkipFile(strings.ToLower(d.Name())) || policy.skipFile(path) {
			return nil
		}

		// Honor user-configured ignore globs (the top-level `ignore` list in
		// preflight.yml), so build tooling, vendored code, or files that only
		// mention debug calls in strings or docs can be excluded.
		rel := policy.rel(path)
		for _, g := range ignore {
			if ok, _ := doublestar.Match(filepath.ToSlash(g), rel); ok {
				return nil
			}
		}

		// Skip files larger than 500KB
		info, err := d.Info()
		if err != nil || info.Size() > 500*1024 {
			return nil
		}

		content, err := readSourceFile(path)
		if err != nil {
			return nil
		}
		if bundleExts[ext] && looksBundled(content) {
			return nil
		}

		findings = append(findings, debugFindingsInFile(rel, ext, string(content), patterns)...)
		return nil
	})

	return findings
}

// debugFindingsInFile returns the unguarded debug statements in one file.
func debugFindingsInFile(rel, ext, content string, patterns []debugPattern) []string {
	var findings []string

	// Multi-line block comments are blanked first (newlines kept, so line
	// numbers hold): a console.log inside a /* ... */ or <!-- ... -->
	// spanning several lines is commented out, and no per-line test can
	// tell.
	lines := strings.Split(blankBlockComments(content), "\n")

	// One guard scanner per file, advanced to each statement as it is
	// found. Replaying the file from the top for every statement made a
	// file of N statements cost N*N lines.
	var guard devGuardScanner
	replayed := 0

	for lineNum, line := range lines {
		// Skip commented lines (basic check). This only catches whole-line
		// comments; hash-style ones in particular have to be handled here,
		// because stripCodeComments deliberately leaves "#" alone (it is a
		// CSS selector and a YAML key as often as it is a comment).
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" ||
			strings.HasPrefix(trimmedLine, "//") ||
			strings.HasPrefix(trimmedLine, "#") ||
			strings.HasPrefix(trimmedLine, "*") ||
			strings.HasPrefix(trimmedLine, "/*") ||
			strings.HasPrefix(trimmedLine, "{#") ||
			strings.HasPrefix(trimmedLine, "<!--") {
			continue
		}

		// A debug statement named in a trailing comment is not a debug
		// statement: `doWork(); // console.log(x) if this breaks` is real
		// code plus a note. The prefix check above can't see those, so
		// strip inline comments before matching. stripCodeComments leaves
		// URLs intact, so a logged https:// link keeps its line.
		line = stripCodeComments(line)
		// <code>console.log()</code> on one line is documentation.
		line = reInlineCodeSpan.ReplaceAllString(line, "")
		codeLine := maskCodeStrings(line)
		// A trailing "#" comment, in the languages that have them.
		if hashCommentExts[ext] {
			if i := hashCommentStart(codeLine); i >= 0 {
				line, codeLine = line[:i], codeLine[:i]
			}
		}

		for _, p := range patterns {
			matchLine := codeLine
			if strings.HasPrefix(p.description, "fmt.Print") && strings.Contains(codeLine, "fmt.Print") {
				matchLine = line
			}
			loc := p.pattern.FindStringIndex(matchLine)
			if loc == nil || (p.exclude != nil && p.exclude.MatchString(line)) {
				continue
			}
			for ; replayed < lineNum; replayed++ {
				guard.line(lines[replayed], -1)
			}
			// The statement's own line is replayed on a copy: the scanner
			// stops at the statement there, and the whole line still has to
			// be replayed for whatever follows.
			statement := guard.clone()
			if statement.line(lines[lineNum], loc[0]) || isInCodeExample(lines, lineNum, heredocExts[ext]) {
				continue
			}
			findings = append(findings, fmt.Sprintf("%s:%d - %s", rel, lineNum+1, p.description))
		}
	}

	return findings
}

// A devGuardScanner answers whether a debug statement only runs in
// development. It is fed the file's lines in order and tracks the blocks
// that are open: braces, template blocks ({% if %}, <% if %>, @if,
// {{ if }}, {#if}), and keyword blocks closed by indentation (Python, Ruby,
// a braceless if). A block guards when the condition that opened it selects
// development (devPolarity); its else branch does not. On the statement's
// own line an inline if, `cond && stmt`, `cond ? stmt :`, and a trailing
// `stmt if cond` guard too.

type guardFrame struct {
	kind string // "{" for a brace, "<family>:<block>" for a template block
	dev  bool
}

type indentFrame struct {
	indent int
	dev    bool
}

type devGuardScanner struct {
	frames  []guardFrame
	indents []indentFrame
	// pending: the last line was a development condition still waiting for
	// its body (a braceless if, an Allman brace), or a
	// #[cfg(debug_assertions)] attribute, which is sticky: it holds until
	// the item's brace or semicolon.
	pending, sticky bool
}

// clone returns a copy that can be advanced without touching g.
func (g *devGuardScanner) clone() *devGuardScanner {
	c := *g
	c.frames = append([]guardFrame(nil), g.frames...)
	c.indents = append([]indentFrame(nil), g.indents...)
	return &c
}

var (
	reGuardKeyword = regexp.MustCompile(`^(else\s*if|elseif|elif|elsif|if|unless|else)\b`)
	// Python's `if x:` (but not Elixir's `== :dev` or Rust's `a::b`).
	rePythonColon = regexp.MustCompile(`^(.*?[^\s:]):(?:\s|$)`)
	reCfgAttr     = regexp.MustCompile(`^#\[cfg\(`)
	// `stmt if cond` / `stmt unless cond` (Ruby, Python's conditional expression).
	reTrailingGuard = regexp.MustCompile(`\s(if|unless)\s+(.+)$`)

	// Twig, Django, Jinja, Liquid, Nunjucks.
	reTwigTag = regexp.MustCompile(`^\{%-?\s*(if|elseif|elif|else|endif|unless|endunless)\b(.*?)-?%\}`)
	// ERB. A brace in the tag means EJS, whose JavaScript blocks the brace
	// tracking handles.
	reERBTag = regexp.MustCompile(`^<%[-=]?\s*(if|unless|elsif|else|end)\b([^{}%]*?)-?%>`)
	reERBDo  = regexp.MustCompile(`^<%[-=]?[^{}%]*\bdo\b\s*(?:\|[^|%]*\|)?\s*-?%>`)
	// Go templates and Hugo ({{ if }}...{{ end }}), Handlebars ({{#if}}...{{/if}}).
	reMustacheTag = regexp.MustCompile(`^\{\{[-~]?\s*(#if|#unless|/if|/unless|if|else\s+if|else|end|range|with|define|block)\b(.*?)[-~]?\}\}`)
	reSvelteTag   = regexp.MustCompile(`^\{(#if|:else\s+if|:else|/if)\b(.*?)\}`)
	reBladeTag    = regexp.MustCompile(`^@(if|elseif|unless|env|production|else|endif|endunless|endenv|endproduction)\b`)
)

// line replays one line. With position >= 0 it is the statement's own line,
// and line reports whether the statement at position is guarded.
func (g *devGuardScanner) line(rawLine string, position int) bool {
	raw := stripCodeComments(rawLine)
	code := maskCodeStrings(raw)
	target := position >= 0
	if strings.TrimSpace(code) == "" && !target {
		return false
	}
	indent := len(code) - len(strings.TrimLeft(code, " \t"))
	for len(g.indents) > 0 && g.indents[len(g.indents)-1].indent >= indent {
		g.indents = g.indents[:len(g.indents)-1]
	}
	limit := len(code)
	if target {
		limit = min(position, limit)
	}

	var (
		condFound, condDev, condAtStart bool
		braceCond                       bool // a condition not yet given to a brace
		inline                          bool // an inline condition still applies
		setPending                      bool
		condEnd                         = -1
	)
	for j := 0; j < limit; {
		c := code[j]
		if c == '{' || c == '<' || c == '@' {
			if n := g.templateTag(raw, code, j, limit); n > 0 {
				j += n
				continue
			}
		}
		if c == '#' && reCfgAttr.MatchString(code[j:]) {
			open := j + len("#[cfg")
			end := matchingParen(code, open)
			if end < 0 {
				end = len(code) - 1
			}
			if devPolarity(raw[open+1:end]) > 0 {
				g.pending, g.sticky, setPending = true, true, true
			}
			j = end + 1
			continue
		}
		if isWordStart(code, j) {
			if m := reGuardKeyword.FindStringSubmatch(code[j:]); m != nil {
				kw := m[1]
				if kw == "else" {
					braceCond, inline, g.pending = false, false, false
					j += len(kw)
					continue
				}
				cond, end := guardCondition(raw, code, j+len(kw))
				p := devPolarity(cond)
				if kw == "unless" {
					p = -p
				}
				condFound, condDev, braceCond, inline, condEnd = true, p > 0, true, true, end
				condAtStart = j == indent
				j = max(end, j+len(kw))
				continue
			}
		}
		switch c {
		case '{':
			dev := false
			if braceCond {
				dev, braceCond = condDev, false
			} else if g.pending {
				dev, g.pending, g.sticky = true, false, false
			}
			g.frames = append(g.frames, guardFrame{kind: "{", dev: dev})
			inline = false
		case '}':
			g.pop(func(k string) bool { return k == "{" })
			inline = false
		case ';':
			braceCond, inline, g.pending = false, false, false
		}
		j++
	}

	if target {
		if g.pending || (inline && condDev) || guardedOperand(raw, code, limit) || trailingGuard(raw, code, limit) {
			return true
		}
		for _, f := range g.frames {
			if f.dev {
				return true
			}
		}
		for _, f := range g.indents {
			if f.dev {
				return true
			}
		}
		return false
	}

	if braceCond && condDev && condEnd >= 0 && condEnd <= len(code) && strings.TrimSpace(code[condEnd:]) == "" {
		g.pending, g.sticky, setPending = true, false, true
	}
	if !setPending && !g.sticky {
		g.pending = false
	}
	if condFound && condAtStart && !strings.Contains(code, "{") {
		g.indents = append(g.indents, indentFrame{indent: indent, dev: condDev})
	}
	return false
}

// pop removes the innermost frame whose kind matches.
func (g *devGuardScanner) pop(match func(string) bool) {
	for i := len(g.frames) - 1; i >= 0; i-- {
		if match(g.frames[i].kind) {
			g.frames = append(g.frames[:i], g.frames[i+1:]...)
			return
		}
	}
}

// innermost returns the innermost frame of a template family, or nil.
func (g *devGuardScanner) innermost(family string) *guardFrame {
	for i := len(g.frames) - 1; i >= 0; i-- {
		if strings.HasPrefix(g.frames[i].kind, family+":") {
			return &g.frames[i]
		}
	}
	return nil
}

// templateTag consumes a template control tag at code[j:] and returns its
// length, or 0 when there is none.
func (g *devGuardScanner) templateTag(raw, code string, j, limit int) int {
	s := code[j:limit]
	family, kw, cond, n := "", "", "", 0
	submatch := func(re *regexp.Regexp) bool {
		m := re.FindStringSubmatchIndex(s)
		if m == nil {
			return false
		}
		n = m[1]
		if len(m) > 2 && m[2] >= 0 {
			kw = s[m[2]:m[3]]
		}
		if len(m) > 4 && m[4] >= 0 {
			cond = raw[j+m[4] : j+m[5]]
		}
		return true
	}
	switch {
	case submatch(reTwigTag):
		family = "twig"
	case submatch(reERBTag):
		family = "erb"
	case submatch(reERBDo):
		family, kw = "erb", "do"
	case submatch(reMustacheTag):
		family = "mustache"
	case submatch(reSvelteTag):
		family = "svelte"
	case (j == 0 || !isIdentByte(code[j-1])) && submatch(reBladeTag):
		family = "blade"
		if kw == "if" || kw == "elseif" || kw == "unless" || kw == "env" {
			open := j + n
			for open < len(code) && code[open] == ' ' {
				open++
			}
			if open < limit && code[open] == '(' {
				if end := matchingParen(code, open); end >= 0 && end < limit {
					cond, n = raw[open+1:end], end+1-j
				}
			}
		}
	default:
		return 0
	}

	closing := strings.HasPrefix(kw, "/")
	kw = strings.Join(strings.Fields(strings.TrimLeft(kw, "#/:")), " ")
	switch {
	case closing:
		g.pop(func(k string) bool { return k == family+":"+kw })
	case kw == "if" || kw == "env":
		if kw == "env" {
			cond = "environment(" + cond + ")"
		}
		g.frames = append(g.frames, guardFrame{kind: family + ":" + kw, dev: devPolarity(cond) > 0})
	case kw == "unless":
		g.frames = append(g.frames, guardFrame{kind: family + ":unless", dev: devPolarity(cond) < 0})
	case kw == "production" || kw == "do" || kw == "range" || kw == "with" || kw == "define" || kw == "block":
		g.frames = append(g.frames, guardFrame{kind: family + ":" + kw})
	case kw == "elseif" || kw == "elif" || kw == "elsif" || kw == "else if":
		if f := g.innermost(family); f != nil {
			f.dev = devPolarity(cond) > 0
		}
	case kw == "else":
		if f := g.innermost(family); f != nil {
			f.dev = false
		}
	case kw == "end":
		g.pop(func(k string) bool { return strings.HasPrefix(k, family+":") })
	case strings.HasPrefix(kw, "end"):
		g.pop(func(k string) bool { return k == family+":"+strings.TrimPrefix(kw, "end") })
	}
	return n
}

// guardCondition returns the condition that follows a keyword ending at k,
// and where it ends: a parenthesized one (JavaScript, PHP), or one running
// to the block's brace or the line's end (Go, Rust, Python, Ruby).
func guardCondition(raw, code string, k int) (string, int) {
	for k < len(code) && (code[k] == ' ' || code[k] == '\t') {
		k++
	}
	if k < len(code) && code[k] == '(' {
		if end := matchingParen(code, k); end >= 0 {
			return raw[k+1 : end], end + 1
		}
		return raw[k:], len(code)
	}
	end := len(code)
	if i := strings.IndexAny(code[k:], "{;"); i >= 0 {
		end = k + i
	}
	if m := rePythonColon.FindStringSubmatchIndex(code[k:end]); m != nil {
		return raw[k : k+m[3]], k + m[1]
	}
	return raw[k:end], end
}

// guardedOperand reports whether the code before limit ends in `cond &&`,
// `cond and`, or `cond ?` with a development cond.
func guardedOperand(raw, code string, limit int) bool {
	head := strings.TrimRight(code[:limit], " \t")
	var op int
	switch {
	case strings.HasSuffix(head, "&&"):
		op = len(head) - 2
	case strings.HasSuffix(head, "?") && !strings.HasSuffix(head, "??"):
		op = len(head) - 1
	case strings.HasSuffix(head, " and"):
		op = len(head) - 4
	default:
		return false
	}
	return devPolarity(raw[operandStart(code, op):op]) > 0
}

// operandStart walks back from end to the start of the expression ending
// there: the nearest unmatched paren, or a statement, argument, assignment,
// ternary, or || boundary.
func operandStart(code string, end int) int {
	depth := 0
	for i := end - 1; i >= 0; i-- {
		switch code[i] {
		case ')', ']':
			depth++
		case '(', '[':
			if depth == 0 {
				return i + 1
			}
			depth--
		case ';', '{', '}', ',', '?':
			if depth == 0 {
				return i + 1
			}
		case ':':
			if depth == 0 && i+1 < len(code) && code[i+1] == ' ' {
				return i + 1
			}
		case '|':
			if depth == 0 && i > 0 && code[i-1] == '|' {
				return i + 1
			}
		case '=':
			var prev, next byte
			if i > 0 {
				prev = code[i-1]
			}
			if i+1 < len(code) {
				next = code[i+1]
			}
			if depth == 0 && next != '=' && prev != '=' && prev != '!' && prev != '<' && prev != '>' {
				return i + 1
			}
		}
	}
	return 0
}

// trailingGuard reports a Ruby-style `stmt if cond` after the statement.
func trailingGuard(raw, code string, position int) bool {
	if position >= len(code) {
		return false
	}
	rest := code[position:]
	m := reTrailingGuard.FindStringSubmatchIndex(rest)
	if m == nil || strings.ContainsAny(rest[:m[0]], ";{") {
		return false
	}
	p := devPolarity(raw[position+m[4] : position+m[5]])
	if rest[m[2]:m[3]] == "unless" {
		p = -p
	}
	return p > 0
}

// matchingParen returns the index of the paren closing the one at open, or -1.
func matchingParen(code string, open int) int {
	depth := 0
	for i := open; i < len(code); i++ {
		switch code[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isWordStart(code string, j int) bool {
	if c := code[j]; c < 'a' || c > 'z' {
		return false
	}
	return j == 0 || !isIdentByte(code[j-1]) && code[j-1] != '.' && code[j-1] != '$' && code[j-1] != '@'
}

func isIdentByte(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b >= 'A' && b <= 'Z'
}

var (
	reEnvComparison = regexp.MustCompile(`(?i)(===?|!==?|<>|\beq\b|\bne\b)\s*(?:['"]|:)(development|dev|local|debug|testing|test|production|prod|staging|live)\b`)
	reEnvCall       = regexp.MustCompile(`(?i)\b(?:environment|env)\s*\(\s*\[?\s*['"](development|dev|local|testing|test|production|prod|staging|live)\b`)
	reRailsEnv      = regexp.MustCompile(`(?i)\brails\.env\.(development|local|test|production|staging)\?`)
	reHugoServer    = regexp.MustCompile(`(?:\.Site|\bhugo)\.IsServer\b`)
	// Development flags: isDev, __DEV__, import.meta.env.DEV, devMode,
	// settings.DEBUG, app.debug, APP_DEBUG, debug_assertions, isLocal.
	reDevIdent = regexp.MustCompile(`(?i)\b(?:is_?dev(?:elopment)?(?:_?mode)?|is_?debug(?:_?mode)?|is_?local|in_?development|dev_?mode|debug_?mode|dev|debug|__dev__|\w+_debug|debug_\w+)\b`)
	// Production flags: isProduction, import.meta.env.PROD, production.
	reProdIdent    = regexp.MustCompile(`(?i)\b(?:is_?prod(?:uction)?|in_?production|prod|production|__prod__)\b`)
	reDisjunction  = regexp.MustCompile(`(?i)\|\||\bor\b`)
	reDevEnvValues = regexp.MustCompile(`(?i)^(?:development|dev|local|debug|testing|test)$`)
)

// devPolarity classifies a condition: 1 when it selects development, -1
// when it selects production, 0 when it is neither or mixed. A disjunction
// is development only when every alternative is (`isDev || isAdmin` runs
// for admins in production); in a conjunction one development term is
// enough.
func devPolarity(cond string) int {
	masked := maskCodeStrings(cond)
	result, prev := 0, 0
	bounds := append(reDisjunction.FindAllStringIndex(masked, -1), []int{len(cond), len(cond)})
	for k, loc := range bounds {
		p := conjunctPolarity(cond[prev:loc[0]])
		prev = loc[1]
		if k == 0 {
			result = p
		} else if p != result {
			return 0
		}
	}
	return result
}

func conjunctPolarity(cond string) int {
	work := []byte(cond)
	dev, prod := false, false
	scan := func(re *regexp.Regexp, polarity func(m []int) int, negatable bool) {
		for _, m := range re.FindAllSubmatchIndex(work, -1) {
			p := polarity(m)
			if negatable && negatedAt(cond, m[0]) {
				p = -p
			}
			dev, prod = dev || p > 0, prod || p < 0
			for i := m[0]; i < m[1]; i++ {
				work[i] = ' '
			}
		}
	}
	value := func(m []int, group int) int {
		if reDevEnvValues.MatchString(cond[m[2*group]:m[2*group+1]]) {
			return 1
		}
		return -1
	}
	scan(reEnvComparison, func(m []int) int {
		p := value(m, 2)
		if op := strings.ToLower(cond[m[2]:m[3]]); op[0] == '!' || op == "<>" || op == "ne" {
			p = -p
		}
		return p
	}, false)
	scan(reEnvCall, func(m []int) int { return value(m, 1) }, true)
	scan(reRailsEnv, func(m []int) int { return value(m, 1) }, true)
	scan(reHugoServer, func([]int) int { return 1 }, true)
	scan(reDevIdent, func([]int) int { return 1 }, true)
	scan(reProdIdent, func([]int) int { return -1 }, true)
	switch {
	case dev:
		return 1
	case prod:
		return -1
	}
	return 0
}

// negatedAt reports whether the term starting at i is negated: `!isDev`,
// `!import.meta.env.PROD`, `!app()->isLocal()`, `not settings.DEBUG`,
// `not(debug_assertions)`. A macro bang (`cfg!(...)`) is not a negation.
func negatedAt(s string, i int) bool {
	// Back over the receiver chain to the start of the expression.
	for {
		if i > 0 && s[i-1] == '.' {
			i--
		} else if i > 1 && (s[i-2:i] == "->" || s[i-2:i] == "::") {
			i -= 2
		} else {
			break
		}
		if i > 1 && s[i-2:i] == "()" {
			i -= 2
		}
		for i > 0 && (isIdentByte(s[i-1]) || s[i-1] == '$') {
			i--
		}
	}
	for i > 0 && (s[i-1] == ' ' || s[i-1] == '\t' || s[i-1] == '(') {
		i--
	}
	bangs := 0
	for i > 0 && s[i-1] == '!' {
		bangs++
		i--
	}
	if bangs > 0 {
		return bangs%2 == 1 && (i == 0 || !isIdentByte(s[i-1]))
	}
	w := i
	for w > 0 && isIdentByte(s[w-1]) {
		w--
	}
	return strings.EqualFold(s[w:i], "not")
}

var (
	// reHeredocStart matches a heredoc opener: Ruby's <<~WORD, <<-WORD, and
	// <<WORD, PHP's <<<WORD, each with an optionally quoted marker.
	reHeredocStart = regexp.MustCompile(`<<[<~-]?['"]?([A-Z_][A-Z0-9_]*)`)
	// reHTMLCodeOpen and reHTMLCodeClose match the <pre> and <code> elements
	// themselves. A substring test for "<pre" and "<code" also matched
	// Array<Preference>, <PreviewCard>, and <CodeBlock>.
	reHTMLCodeOpen  = regexp.MustCompile(`<(?:pre|code|PRE|CODE)(?:\s[^>]*)?>`)
	reHTMLCodeClose = regexp.MustCompile(`</(?:pre|code|PRE|CODE)>`)
)

// isInCodeExample reports whether a line sits inside a documentation code
// block: a heredoc (in the languages that have them), a Markdown fence, or
// an HTML <pre> or <code> element opened within the last 30 lines.
func isInCodeExample(lines []string, lineNum int, heredocs bool) bool {
	start := max(lineNum-30, 0)

	heredocMarker := ""
	inMarkdownCode := false
	inHTMLCode := false

	for i := start; i <= lineNum; i++ {
		line := lines[i]

		if heredocs {
			if heredocMarker == "" {
				if m := reHeredocStart.FindStringSubmatch(line); m != nil {
					heredocMarker = m[1]
				}
			} else if closesHeredoc(strings.TrimSpace(line), heredocMarker) {
				heredocMarker = ""
			}
		}

		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inMarkdownCode = !inMarkdownCode
		}

		if reHTMLCodeOpen.MatchString(line) {
			inHTMLCode = true
		}
		if reHTMLCodeClose.MatchString(line) {
			inHTMLCode = false
		}
	}

	if heredocMarker != "" || inMarkdownCode || inHTMLCode {
		return true
	}

	// A line that is itself labelled as an example in a comment.
	lineLower := strings.ToLower(lines[lineNum])
	for _, marker := range []string{"// example", "# example", "/* example", "<!-- example", "{# example"} {
		if strings.Contains(lineLower, marker) {
			return true
		}
	}
	return false
}

// closesHeredoc reports whether a trimmed line ends the heredoc opened with
// marker: the marker alone (Ruby), or followed by punctuation (PHP's "EOT;").
func closesHeredoc(trimmed, marker string) bool {
	if !strings.HasPrefix(trimmed, marker) {
		return false
	}
	rest := trimmed[len(marker):]
	return rest == "" || !isIdentByte(rest[0])
}
