package output

import (
	"strings"
	"unicode/utf8"
)

// Sanitize strips the control characters a terminal would interpret, for
// text printed on one line. Titles are ours, but messages and suggestions
// carry file names and content harvested from the scanned project, config
// notes quote the config file, and history and auth output repeat what the
// dashboard sent; a string holding an escape sequence would otherwise reach
// the terminal verbatim (the JSON output is safe because encoding/json
// escapes them). Tabs are kept; C0 controls (newlines included), DEL and
// the C1 range (U+0080 to U+009F, which some terminals treat as 8-bit
// escape introducers) are dropped.
func Sanitize(s string) string {
	return stripControls(s, false)
}

// SanitizeLines is Sanitize for text that is meant to span lines: it keeps
// newlines and drops everything else Sanitize drops.
func SanitizeLines(s string) string {
	return stripControls(s, true)
}

func stripControls(s string, keepNewlines bool) string {
	drop := func(r rune, size int) bool {
		if r == '\n' && keepNewlines {
			return false
		}
		// A lone invalid byte is dropped too: 0x9b on its own is not valid
		// UTF-8, but a terminal in 8-bit mode still reads it as CSI.
		return isTerminalControl(r) || (r == utf8.RuneError && size == 1)
	}
	clean := true
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if drop(r, size) {
			clean = false
			break
		}
		i += size
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !drop(r, size) {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func isTerminalControl(r rune) bool {
	if r == '\t' {
		return false
	}
	return r < 0x20 || (r >= 0x7f && r <= 0x9f)
}
