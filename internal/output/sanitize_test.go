package output

import "testing"

func TestSanitize(t *testing.T) {
	cases := []struct{ in, line, lines string }{
		{"plain text", "plain text", "plain text"},
		{"tab\tkept", "tab\tkept", "tab\tkept"},
		{"a\nb", "ab", "a\nb"},
		{"title\x1b]0;spoof\x07 rest", "title]0;spoof rest", "title]0;spoof rest"},
		{"erase\x1b[2K\rline", "erase[2Kline", "erase[2Kline"},
		{"c1 \u009b31m csi", "c1 31m csi", "c1 31m csi"},
		{"lone \x9b byte", "lone  byte", "lone  byte"},
		{"del\x7f", "del", "del"},
		{"unicode ✓ café", "unicode ✓ café", "unicode ✓ café"},
	}
	for _, tc := range cases {
		if got := Sanitize(tc.in); got != tc.line {
			t.Errorf("Sanitize(%q) = %q, want %q", tc.in, got, tc.line)
		}
		if got := SanitizeLines(tc.in); got != tc.lines {
			t.Errorf("SanitizeLines(%q) = %q, want %q", tc.in, got, tc.lines)
		}
	}
}

// License names are matched as words. Lowercased substring matching made
// "MPL" match "example", "MIT" match "limit", and "ISC" match "misc", so
// almost every passing message was printed.
func TestHasUsefulPassedMessage(t *testing.T) {
	useful := []string{
		"MIT license found",
		"Apache-2.0 license found (at ../LICENSE)",
		"Licensed under the ISC terms",
		"prod: ✓; staging: ✓",
		"Skipped for local URL",
		"Stripe not declared",
	}
	for _, msg := range useful {
		if !hasUsefulPassedMessage(msg) {
			t.Errorf("%q should be shown", msg)
		}
	}
	plain := []string{
		"robots.txt served at https://example.com/robots.txt",
		"Sitemap template found",
		"All icons complete",
		"No rate limit or commit hooks found",
		"Checked misc files",
		"No debug statements found",
	}
	for _, msg := range plain {
		if hasUsefulPassedMessage(msg) {
			t.Errorf("%q should not be shown", msg)
		}
	}
}
