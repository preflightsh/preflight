package checks

import "testing"

// TestLangIgnoresHreflang: an alternate link's hreflang="en" is not the
// document language on <html>.
func TestLangIgnoresHreflang(t *testing.T) {
	if hasLangAttribute(`<html><head><link rel="alternate" hreflang="en" href="/en"></head></html>`, "static") {
		t.Error("hreflang counted as <html lang>")
	}
	if !hasLangAttribute(`export default function RootLayout({children}){ return <html lang="en">{children}</html> }`, "next") {
		t.Error("<html lang=\"en\"> not found")
	}
}

// TestCanonicalNeedsACanonical: Next.js metadataBase emits no canonical
// tag, and Astro.url is used for nav highlighting. Neither is a canonical.
func TestCanonicalNeedsACanonical(t *testing.T) {
	if hasCanonicalURL("export const metadata = { metadataBase: new URL('https://x.com'), title: 'x' }", "next") {
		t.Error("metadataBase counted as a canonical")
	}
	if hasCanonicalURL("---\nconst path = Astro.url.pathname\n---\n<html><head><title>x</title></head></html>", "astro") {
		t.Error("Astro.url nav use counted as a canonical")
	}
	if !hasCanonicalURL("export const metadata = { alternates: { canonical: '/' } }", "next") {
		t.Error("alternates.canonical not found")
	}
	if !hasCanonicalURL("---\nconst canonicalURL = new URL(Astro.url.pathname, Astro.site)\n---\n<link rel=\"canonical\" href={canonicalURL} />", "astro") {
		t.Error("Astro canonical not found")
	}
}
