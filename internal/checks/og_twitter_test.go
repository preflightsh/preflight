package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// WebP is the reason golang.org/x/image is a dependency, and it is decoded
// from whatever the scanned site serves. Decoding is delegated to x/image,
// so these lock in that the webp decoder stays registered: dropping the
// blank import would silently downgrade every og:image to "unknown format"
// rather than fail the build.
func TestFetchImageDimensionsWebP(t *testing.T) {
	img, err := os.ReadFile(filepath.Join("testdata", "og-image.webp"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/webp")
		_, _ = w.Write(img)
	}))
	defer srv.Close()

	ctx := Context{Ctx: context.Background(), Client: srv.Client()}
	width, height, err := fetchImageDimensions(ctx, srv.URL)
	if err != nil {
		t.Fatalf("fetchImageDimensions returned error: %v", err)
	}
	if width != 1200 || height != 630 {
		t.Errorf("fetchImageDimensions = %dx%d, want 1200x630", width, height)
	}
}

func TestGetLocalImageDimensionsWebP(t *testing.T) {
	width, height, err := getLocalImageDimensions(filepath.Join("testdata", "og-image.webp"))
	if err != nil {
		t.Fatalf("getLocalImageDimensions returned error: %v", err)
	}
	if width != 1200 || height != 630 {
		t.Errorf("getLocalImageDimensions = %dx%d, want 1200x630", width, height)
	}
}

// A malformed webp must surface as a decode error, not a panic. x/image has
// shipped several panic-on-malformed-webp advisories (GO-2026-5061,
// GO-2026-4961) and these bytes come off the network from the site being
// scanned, so a panic would take down the whole scan.
//
// Only the header is corrupted here: DecodeConfig reads dimensions out of the
// header and never touches the pixel data, so truncating the tail of a valid
// webp still decodes fine and would not test anything.
func TestFetchImageDimensionsMalformedWebP(t *testing.T) {
	img, err := os.ReadFile(filepath.Join("testdata", "og-image.webp"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	corruptSize := append([]byte{}, img...)
	corruptSize[16], corruptSize[17], corruptSize[18] = 0xFF, 0xFF, 0xFF

	tests := []struct {
		name string
		data []byte
	}{
		// Declares a VP8 chunk far larger than the bytes that follow: the
		// shape of the "small image claims to hold huge data" advisories.
		{"vp8 chunk size overstated", corruptSize},
		// Header cut mid-chunk.
		{"truncated in riff header", img[:16]},
		{"truncated after riff header", img[:20]},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "image/webp")
				_, _ = w.Write(tc.data)
			}))
			defer srv.Close()

			ctx := Context{Ctx: context.Background(), Client: srv.Client()}
			// A panic here fails the test rather than unwinding the scan.
			if _, _, err := fetchImageDimensions(ctx, srv.URL); err == nil {
				t.Error("fetchImageDimensions = nil error, want decode error")
			}
		})
	}
}

// og:image and twitter:image are almost always absolute (crawlers have to
// be able to fetch them without a base), and the "//" in the scheme used
// to be eaten by the comment stripper before this value was read. The tag
// still looked present, so the check reported a clean pass while the
// dimension validation below it silently never ran.
func TestExtractMetaContentAbsoluteURL(t *testing.T) {
	cases := []struct {
		name string
		html string
		attr string
		want string
	}{
		{
			name: "og:image https",
			html: `<meta property="og:image" content="https://cdn.example.com/og.png">`,
			attr: `property=["']og:image["']`,
			want: "https://cdn.example.com/og.png",
		},
		{
			name: "og:image http",
			html: `<meta property="og:image" content="http://cdn.example.com/og.png">`,
			attr: `property=["']og:image["']`,
			want: "http://cdn.example.com/og.png",
		},
		{
			name: "twitter:image protocol-relative",
			html: `<meta name="twitter:image" content="//cdn.example.com/t.png">`,
			attr: `name=["']twitter:image["']`,
			want: "//cdn.example.com/t.png",
		},
		{
			name: "og:image relative path",
			html: `<meta property="og:image" content="/og.png">`,
			attr: `property=["']og:image["']`,
			want: "/og.png",
		},
		{
			name: "og:image in a multi-tag head",
			html: "<head>\n  <meta property=\"og:image\" content=\"https://x.com/o.png\">\n  <meta name=\"twitter:card\" content=\"summary\">\n</head>",
			attr: `property=["']og:image["']`,
			want: "https://x.com/o.png",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractMetaContent(stripComments(tc.html), tc.attr)
			if got != tc.want {
				t.Errorf("extractMetaContent = %q, want %q", got, tc.want)
			}
		})
	}
}

// resolveImageURL keys off the "http://" prefix to decide absolute vs
// relative, so a truncated scheme silently turned an absolute URL into a
// relative one and appended it to the site's base URL.
func TestResolveImageURLKeepsAbsoluteAfterStrip(t *testing.T) {
	html := `<meta property="og:image" content="https://cdn.example.com/og.png">`
	raw := extractMetaContent(stripComments(html), `property=["']og:image["']`)
	got := resolveImageURL(raw, "https://example.com")
	want := "https://cdn.example.com/og.png"
	if got != want {
		t.Errorf("resolveImageURL = %q, want %q (absolute URL must not be rebased)", got, want)
	}
}
