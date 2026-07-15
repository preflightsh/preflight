package checks

import "testing"

// A canonical URL is required to be absolute, so "https://" appears in
// essentially every real canonical tag. The comment stripper used to cut
// the line at the "//", which left the tag without its closing ">" and
// made detection depend on whether some later tag happened to supply one:
// pretty-printed HTML matched by accident, minified HTML did not match at
// all and reported a canonical tag as missing.
func TestHasCanonicalURL(t *testing.T) {
	cases := []struct {
		name string
		html string
		want bool
	}{
		{
			name: "absolute https, rel before href",
			html: `<link rel="canonical" href="https://example.com/page">`,
			want: true,
		},
		{
			name: "absolute https, href before rel",
			html: `<link href="https://example.com/page" rel="canonical">`,
			want: true,
		},
		{
			name: "absolute http",
			html: `<link rel="canonical" href="http://example.com/page">`,
			want: true,
		},
		{
			name: "protocol-relative",
			html: `<link rel="canonical" href="//example.com/page">`,
			want: true,
		},
		{
			name: "relative path",
			html: `<link rel="canonical" href="/page">`,
			want: true,
		},
		{
			name: "minified head",
			html: `<head><title>x</title><link rel="canonical" href="https://example.com/"><meta charset="utf-8"></head>`,
			want: true,
		},
		{
			name: "pretty-printed head",
			html: "<head>\n  <link rel=\"canonical\" href=\"https://example.com/\">\n  <meta charset=\"utf-8\">\n</head>",
			want: true,
		},
		{
			name: "single quotes",
			html: `<link rel='canonical' href='https://example.com/page'>`,
			want: true,
		},
		{
			name: "no canonical tag at all",
			html: `<head><title>x</title><meta charset="utf-8"></head>`,
			want: false,
		},
		{
			name: "commented-out canonical does not count",
			html: `<head><!-- <link rel="canonical" href="https://example.com/"> --></head>`,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasCanonicalURL(tc.html, "static"); got != tc.want {
				t.Errorf("hasCanonicalURL(%q) = %v, want %v", tc.html, got, tc.want)
			}
		})
	}
}
