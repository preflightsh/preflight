package checks

import "testing"

func TestIsLocalURL(t *testing.T) {
	cases := []struct {
		in   string
		want bool
		why  string
	}{
		// Real local URLs — must still be detected.
		{"http://localhost", true, "bare localhost"},
		{"http://localhost:3000", true, "localhost with port"},
		{"localhost:3000", true, "no scheme + port"},
		{"http://127.0.0.1", true, "loopback IPv4"},
		{"http://127.0.0.5:8080", true, "loopback IPv4 (not .1)"},
		{"http://0.0.0.0", true, "unspecified IPv4"},
		{"http://[::1]", true, "loopback IPv6"},
		{"https://myapp.local", true, "mDNS suffix"},
		{"https://x.y.test", true, ".test suffix"},
		{"https://example.ddev.site", true, "ddev"},
		{"https://yow.lndo.site", true, "lando"},
		{"https://app.localhost", true, ".localhost TLD"},

		// SSRF-bypass attempts via the new local TLDs — must NOT match.
		{"https://attacker.com/?h=yow.lndo.site", false, ".lndo.site in query"},
		{"https://example.lndo.site.evil.com", false, "'.lndo.site' is not the suffix"},

		// SSRF-bypass attempts via substring — must NOT match.
		{"https://localhost.attacker.com/", false, "substring 'localhost' in hostname"},
		{"https://attacker.com/?h=localhost", false, "substring in query"},
		{"https://attacker.com#127.0.0.1", false, "substring in fragment"},
		{"https://attacker-127.0.0.1.example.com/", false, "substring in hostname"},
		{"https://localproject.com", false, "starts with 'local' but not local"},
		{"https://my.local.com", false, "'.local' is not the suffix"},
		{"https://example.test.evil.com", false, "'.test' is not the suffix"},

		// Non-local public.
		{"https://example.com", false, "public domain"},
		{"https://8.8.8.8", false, "public IP"},
	}
	for _, tc := range cases {
		got := IsLocalURL(tc.in)
		if got != tc.want {
			t.Errorf("IsLocalURL(%q) = %v, want %v (%s)", tc.in, got, tc.want, tc.why)
		}
	}
}
