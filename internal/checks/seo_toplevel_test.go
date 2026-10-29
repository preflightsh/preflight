package checks

import "testing"

// Next.js metadata keys are found at the top level of the object however it
// is laid out; the demo's one-line metadata export used to report a missing
// description. Keys nested in openGraph do not count as top-level ones.
func TestNextMetadataTopLevelKeys(t *testing.T) {
	cases := []struct {
		name, src   string
		title, desc bool
	}{
		{"one line", `export const metadata = { title: "Acme Store", description: "Things worth buying." };`, true, true},
		{"multi line", "export const metadata: Metadata = {\n  title: 'Acme',\n  description: site.description,\n};", true, true},
		{"title template", "export const metadata = {\n  title: { default: 'Acme', template: '%s | Acme' },\n};", true, false},
		{"only in openGraph", `export const metadata = { openGraph: { title: "Acme", description: "x" } };`, false, false},
		{"quoted keys", `export const metadata = { "title": "Acme", "description": "x" };`, true, true},
		{"brace in string", `export const metadata = { title: "a { b", description: "c" };`, true, true},
		{"no description value", `export const metadata = { title: "Acme", description: , };`, true, false},
	}
	for _, tc := range cases {
		if got := hasNextJSMetadata(tc.src, "title"); got != tc.title {
			t.Errorf("%s: title = %v, want %v", tc.name, got, tc.title)
		}
		if got := hasNextJSMetadata(tc.src, "description"); got != tc.desc {
			t.Errorf("%s: description = %v, want %v", tc.name, got, tc.desc)
		}
	}
}
