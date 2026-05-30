package config

import (
	"os"
	"path/filepath"
	"testing"
)

const testKey = "23a74777e94982ce283db6a0ee3ad917"

// writeProject materializes a map of relative path -> content under a temp dir.
func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

// TestDetectIndexNowDynamicAcrossStacks verifies the dynamic IndexNow detector
// fires for a route-served key on every supported stack, not just Go, and stays
// quiet when nothing wires up IndexNow.
func TestDetectIndexNowDynamicAcrossStacks(t *testing.T) {
	cases := []struct {
		name      string
		files     map[string]string
		wantFound bool
		wantKey   string // "" means "don't assert a specific key"
	}{
		{
			name: "go net/http route",
			files: map[string]string{
				"internal/web/handlers.go": "const indexNowKey = \"" + testKey + "\"\n" +
					"// mux.HandleFunc(\"GET /\"+indexNowKey+\".txt\", s.indexNowVerify)\n",
			},
			wantFound: true,
			wantKey:   testKey,
		},
		{
			name: "deploy script pinging the api",
			files: map[string]string{
				"bin/deploy": "#!/usr/bin/env bash\nINDEXNOW_KEY=\"" + testKey + "\"\n" +
					"curl \"https://api.indexnow.org/indexnow?key=$INDEXNOW_KEY\"\n",
			},
			wantFound: true,
			wantKey:   testKey,
		},
		{
			name: "rails service object",
			files: map[string]string{
				"app/services/index_now_service.rb": "class IndexNowService\n" +
					"  API = \"https://api.indexnow.org/indexnow\"\n  KEY = \"" + testKey + "\"\nend\n",
			},
			wantFound: true,
			wantKey:   testKey,
		},
		{
			name: "laravel controller",
			files: map[string]string{
				"app/Http/Controllers/IndexNowController.php": "<?php\nclass IndexNowController {\n" +
					"  public function key() { return \"" + testKey + "\"; }\n}\n",
			},
			wantFound: true,
			wantKey:   testKey,
		},
		{
			name: "next.js app router catch route",
			files: map[string]string{
				"src/app/[key].txt/route.ts": "// serves the indexnow verification key\n" +
					"export const KEY = \"" + testKey + "\"\n",
			},
			wantFound: true,
			wantKey:   testKey,
		},
		{
			name: "django module",
			files: map[string]string{
				"indexnow.py": "INDEXNOW_KEY = \"" + testKey + "\"\n" +
					"API = \"https://api.indexnow.org/indexnow\"\n",
			},
			wantFound: true,
			wantKey:   testKey,
		},
		{
			name: "key referenced only as served filename",
			files: map[string]string{
				"server/routes.go": "// route serves " + testKey + ".txt for IndexNow\n",
			},
			wantFound: true,
			wantKey:   testKey,
		},
		{
			name: "dependency and build dirs are skipped",
			files: map[string]string{
				"node_modules/some-pkg/indexnow.js": "const KEY = \"" + testKey + "\"\n",
				"vendor/foo/index_now.go":           "const k = \"" + testKey + "\"\n",
				"src/index.ts":                      "console.log('hello')\n",
			},
			wantFound: false,
		},
		{
			name: "unrelated project",
			files: map[string]string{
				"main.go":      "package main\nfunc main() {}\n",
				"package.json": "{\"name\":\"x\"}\n",
			},
			wantFound: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeProject(t, tc.files)

			found, key := detectIndexNowDynamic(root)
			if found != tc.wantFound {
				t.Fatalf("detectIndexNowDynamic found = %v, want %v (key=%q)", found, tc.wantFound, key)
			}
			if tc.wantKey != "" && key != tc.wantKey {
				t.Fatalf("extracted key = %q, want %q", key, tc.wantKey)
			}

			// DetectServices must agree that IndexNow is present.
			if got := DetectServices(root)["indexnow"]; got != tc.wantFound {
				t.Fatalf("DetectServices[indexnow] = %v, want %v", got, tc.wantFound)
			}
		})
	}
}

// TestDetectIndexNowStaticKeyFile confirms a static hex key file in a web root is
// still detected (the pre-existing path), independent of the dynamic walk.
func TestDetectIndexNowStaticKeyFile(t *testing.T) {
	root := writeProject(t, map[string]string{
		"public/" + testKey + ".txt": testKey + "\n",
	})
	if !DetectServices(root)["indexnow"] {
		t.Fatal("expected static IndexNow key file to be detected")
	}
}
