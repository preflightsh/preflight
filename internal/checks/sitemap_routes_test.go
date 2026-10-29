package checks

import "testing"

// Framework sitemap endpoints that live outside the App Router paths the
// check knew about.
func TestSitemapFrameworkEndpoints(t *testing.T) {
	cases := []struct {
		name  string
		stack string
		file  string
		pass  bool
	}{
		{"next pages router getServerSideProps", "next", "pages/sitemap.xml.js", true},
		{"next pages router under src", "next", "src/pages/sitemap.xml.tsx", true},
		{"astro endpoint", "astro", "src/pages/sitemap.xml.ts", true},
		{"astro sitemap index endpoint", "astro", "src/pages/sitemap-index.xml.js", true},
		{"sveltekit +server", "svelte", "src/routes/sitemap.xml/+server.js", true},
		{"sveltekit +server inside a route group", "svelte", "src/routes/(marketing)/sitemap.xml/+server.ts", true},
		{"remix escaped dot route nested", "remix", "app/routes/(seo)/sitemap[.]xml.tsx", true},
		{"unrelated page is not a sitemap", "next", "pages/about.js", false},
		{"a sitemap component is not an endpoint", "next", "src/pages/components/SitemapLink.tsx", false},
		{"a +server outside sitemap.xml", "svelte", "src/routes/api/+server.ts", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := SitemapCheck{}.Run(sitemapProject(t, tc.stack, map[string]string{tc.file: "export {}\n"}))
			if err != nil {
				t.Fatal(err)
			}
			if res.Passed != tc.pass {
				t.Errorf("passed=%v, want %v (%s)", res.Passed, tc.pass, res.Message)
			}
		})
	}
}
