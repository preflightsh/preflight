package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

func writeFixture(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestNextMetadataOnlyCountsRootRoute: a root layout with no metadata plus a
// commented-out export on a nested page used to pass both SEO and OG with
// "configured via Next.js Metadata API". Neither file declares anything.
func TestNextMetadataOnlyCountsRootRoute(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "app/layout.tsx", "export default function RootLayout({children}){ return <html><body>{children}</body></html> }\n")
	writeFixture(t, root, "app/blog/page.tsx", "// export const metadata = { title: 'old' }\nexport const metadata = { title: 'Blog only' }\nexport default function P(){ return null }\n")
	ctx := Context{RootDir: root, Config: &config.PreflightConfig{Stack: "next"}}

	if res, _ := (SEOMetadataCheck{}).Run(ctx); res.Passed {
		t.Errorf("seo_meta passed on a nested-page export: %q", res.Message)
	}
	if res, _ := (OGTwitterCheck{}).Run(ctx); res.Passed {
		t.Errorf("og_twitter passed on a nested-page export: %q", res.Message)
	}
}

// TestNextMetadataRootPageAndRouteGroup: the root page and a top-level route
// group layout are real places for the site's metadata, and values may be
// identifiers rather than string literals.
func TestNextMetadataRootPageAndRouteGroup(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "app/layout.tsx", "export default function RootLayout({children}){ return <html><body>{children}</body></html> }\n")
	writeFixture(t, root, "app/(marketing)/layout.tsx", `import { site } from "@/site"
export const metadata: Metadata = {
  title: { default: site.name, template: "%s | Site" },
  description: site.description,
  openGraph: { title: site.name, description: site.description, images: [site.og], url: site.url, type: "website" },
  twitter: { card: "summary_large_image", images: [site.og] },
}
export default function L({children}){ return children }
`)
	ctx := Context{RootDir: root, Config: &config.PreflightConfig{Stack: "next"}}

	if res, _ := (SEOMetadataCheck{}).Run(ctx); !res.Passed {
		t.Errorf("seo_meta: %q", res.Message)
	}
	if res, _ := (OGTwitterCheck{}).Run(ctx); !res.Passed {
		t.Errorf("og_twitter: %q", res.Message)
	}
}

// TestSEOTitleAttributeIsNotATitle: a tooltip title= on an HTML element is not
// the page title, while a title prop on a component still counts.
func TestSEOTitleAttributeIsNotATitle(t *testing.T) {
	if checkAlternatePatterns(`<a href="/" title="Home">x</a>`, "title") {
		t.Error(`<a title="Home"> counted as a page title`)
	}
	if !checkAlternatePatterns(`<Seo title="Pricing" />`, "title") {
		t.Error(`<Seo title=...> not counted as a page title`)
	}
	if !checkAlternatePatterns(`useHead({ title: "Docs" })`, "title") {
		t.Error(`title: in a JS object not counted`)
	}
}
