package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func writeSrc(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return dir
}

// A debug statement named inside a trailing comment is a note about code,
// not code. The whole-line comment skip could not see those, so the raw
// line matched and reported a console.log that does not exist.
func TestScanForDebugStatements(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		body    string
		wantAny bool
	}{
		{
			name:    "trailing comment mentioning a debug call",
			file:    "app.js",
			body:    "doSomethingReal(); // debug: console.log(response) if this breaks\n",
			wantAny: false,
		},
		{
			name:    "whole-line comment",
			file:    "app.js",
			body:    "// console.log('left over')\nreal();\n",
			wantAny: false,
		},
		{
			name:    "real debug statement",
			file:    "app.js",
			body:    "console.log('left over');\n",
			wantAny: true,
		},
		{
			name:    "real debug statement with a trailing comment",
			file:    "app.js",
			body:    "console.log(x); // TODO remove before launch\n",
			wantAny: true,
		},
		{
			// The comment stripper must not truncate the line at the URL and
			// lose the debug call that follows it.
			name:    "debug statement after a URL on the same line",
			file:    "app.js",
			body:    "const u = \"https://api.example.com/v1\"; console.log(u);\n",
			wantAny: true,
		},
		{
			name:    "clean file",
			file:    "app.js",
			body:    "export function add(a, b) { return a + b }\n",
			wantAny: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanForDebugStatements(writeSrc(t, tc.file, tc.body), nil)
			if gotAny := len(got) > 0; gotAny != tc.wantAny {
				t.Errorf("scanForDebugStatements found %v, want any=%v", got, tc.wantAny)
			}
		})
	}
}
