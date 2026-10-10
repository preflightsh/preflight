package checks

import "testing"

// TestDetectIndexNowInSourceNeedsKey: preflightsh-website's check catalog
// ({Name: "IndexNow", ID: "index_now"}) was reported as "IndexNow served
// dynamically". Only code that carries the configured key counts, and a
// commented-out route does not.
func TestDetectIndexNowInSourceNeedsKey(t *testing.T) {
	const key = "23a74777e94982ce283db6a0ee3ad917"

	root := t.TempDir()
	writeFixture(t, root, "internal/web/catalog.go", "package web\nvar checks = []string{\"IndexNow\"}\n")
	writeFixture(t, root, "internal/web/old.go", "package web\n// mux.HandleFunc(\"GET /"+key+".txt\", h)\n")
	if path, ok := detectIndexNowInSource(Context{RootDir: root}, key); ok {
		t.Fatalf("matched %s without the key in live code", path)
	}

	writeFixture(t, root, "internal/web/handlers.go", "package web\nconst indexNowKey = \""+key+"\"\n")
	if path, ok := detectIndexNowInSource(Context{RootDir: root}, key); !ok || path != "internal/web/handlers.go" {
		t.Fatalf("path=%q ok=%v", path, ok)
	}
}
