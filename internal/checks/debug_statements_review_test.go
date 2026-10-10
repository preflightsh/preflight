package checks

import (
	"slices"
	"strings"
	"testing"
)

func findingFiles(findings []string) []string {
	var files []string
	for _, f := range findings {
		file, _, _ := strings.Cut(f, ":")
		if !slices.Contains(files, file) {
			files = append(files, file)
		}
	}
	slices.Sort(files)
	return files
}

// TestDebugStatementsFalsePositives: the word "debugger" in a string or in
// documentation, Symfony's Yaml::dump(), print_r($x, true) (which returns a
// string), and console.log inside a multi-line comment are not debug
// statements left behind.
func TestDebugStatementsFalsePositives(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "src/tools.ts", "export const tools = [{ slug: \"og-debugger\", title: \"OG Debugger\" }]\n")
	writeFixture(t, root, "templates/home.html", "<li><code>debugger</code> left behind</li>\n<p><code>console.log(x)</code> too</p>\n")
	writeFixture(t, root, "src/Config.php", "<?php\nuse Symfony\\Component\\Yaml\\Yaml;\n$out = Yaml::dump($config, 4);\n$d->dump($x);\n$s = print_r($x, true);\n")
	writeFixture(t, root, "src/a.js", "function f() {\n  /*\n  console.log('old debugging');\n  debugger;\n  */\n  return 1\n}\n")
	writeFixture(t, root, "src/b.html", "<!--\n<script>console.log('x')</script>\n-->\n<p>hi</p>\n")
	// A glob in a string must not open a "comment" that hides real code.
	writeFixture(t, root, "src/routes.js", "const r = \"/api/*\"\nconsole.log('real one')\n/* note */\n")

	got := scanForDebugStatements(root, nil)
	if len(got) != 1 || !strings.HasPrefix(got[0], "src/routes.js:2") {
		t.Fatalf("findings = %v, want only src/routes.js:2", got)
	}
}

// TestDebugStatementsRealOnesStillFound: the statement forms still match.
func TestDebugStatementsRealOnesStillFound(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "src/a.js", "function f(x) {\n  debugger\n  if (x) { debugger; }\n}\n")
	writeFixture(t, root, "app/x.rb", "def f\n  debugger if ENV['X']\nend\n")
	writeFixture(t, root, "src/p.php", "<?php\ndump($user);\ndd($request);\nprint_r($rows);\n")
	got := scanForDebugStatements(root, nil)
	if len(got) != 6 {
		t.Fatalf("findings = %v, want 6", got)
	}
}

// TestDebugStatementsSkipFilesByName: vendored-library names are matched as
// the start of the file name; a substring match hid the project's own
// members.ts, RememberMe.tsx, contest_entry.js, piechart.tsx and moments.ts.
func TestDebugStatementsSkipFilesByName(t *testing.T) {
	root := t.TempDir()
	for _, n := range []string{"members.ts", "RememberMe.tsx", "contest_entry.js", "piechart.tsx", "moments.ts", "control.ts", "jquery-3.7.1.js", "moment.js", "test_utils.py", ".eslintrc.js"} {
		body := "export function f(x){ console.log(x) }\n"
		if strings.HasSuffix(n, ".py") {
			body = "breakpoint()\n"
		}
		writeFixture(t, root, "src/"+n, body)
	}
	got := findingFiles(scanForDebugStatements(root, nil))
	want := []string{"src/RememberMe.tsx", "src/contest_entry.js", "src/control.ts", "src/members.ts", "src/moments.ts", "src/piechart.tsx"}
	if !slices.Equal(got, want) {
		t.Fatalf("files = %v, want %v", got, want)
	}
}

// TestDebugStatementsGuardNeedsCondition: isDeviceMobile is not isDev, and
// reading an env value is not a guard. A real conditional still is.
func TestDebugStatementsGuardNeedsCondition(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "src/a.ts", "const isDeviceMobile = window.innerWidth < 600\nconsole.log('leaked', user)\n")
	writeFixture(t, root, "src/b.ts", "const api = import.meta.env.VITE_API_URL\nconsole.log('token', token)\n")
	writeFixture(t, root, "src/c.ts", "if (import.meta.env.DEV) {\n  console.log('dev only')\n}\n")
	writeFixture(t, root, "src/d.ts", "if (isDev) console.log('dev only')\n")
	got := findingFiles(scanForDebugStatements(root, nil))
	if want := []string{"src/a.ts", "src/b.ts"}; !slices.Equal(got, want) {
		t.Fatalf("files = %v, want %v", got, want)
	}
}
