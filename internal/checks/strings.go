package checks

// maskCodeStrings blanks quoted contents without shifting positions. Debug
// call syntax inside a string or regular-expression literal is documentation.
func maskCodeStrings(code string) string {
	out := []byte(code)
	var quote byte
	escaped := false
	for i, c := range out {
		if quote != 0 {
			if c != '\n' {
				out[i] = ' '
			}
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
		} else if c == '\'' || c == '"' || c == '`' {
			quote = c
			out[i] = ' '
		}
	}
	return string(out)
}
