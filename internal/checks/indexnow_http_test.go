package checks

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

const indexNowTestKey = "0123456789abcdef0123456789abcdef"

func indexNowCtx(t *testing.T, files map[string]string, url string, client *http.Client) Context {
	t.Helper()
	ctx := sitemapProject(t, "rails", files)
	ctx.Config.Checks.IndexNow = &config.IndexNowConfig{Enabled: true, Key: indexNowTestKey}
	ctx.Config.URLs = config.URLConfig{Production: url}
	ctx.Client = client
	return ctx
}

// TestIndexNowHTTPProbeDecides: with a reachable URL and a key, the
// deployed /{key}.txt decides; a job file named index_now_job.rb is not
// evidence the key is served.
func TestIndexNowHTTPProbeDecides(t *testing.T) {
	notFound := httptest.NewServer(http.NotFoundHandler())
	defer notFound.Close()
	serving := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+indexNowTestKey+".txt" {
			fmt.Fprint(w, indexNowTestKey)
			return
		}
		http.NotFound(w, r)
	}))
	defer serving.Close()
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer blocked.Close()

	job := map[string]string{"app/jobs/index_now_job.rb": "class IndexNowJob; end\n"}

	t.Run("heuristic file but host 404s", func(t *testing.T) {
		res, _ := IndexNowCheck{}.Run(indexNowCtx(t, job, notFound.URL, notFound.Client()))
		if res.Passed {
			t.Fatalf("host 404s on the key file but check passed: %q", res.Message)
		}
	})
	t.Run("key file on disk but host 404s", func(t *testing.T) {
		files := map[string]string{"public/" + indexNowTestKey + ".txt": indexNowTestKey}
		res, _ := IndexNowCheck{}.Run(indexNowCtx(t, files, notFound.URL, notFound.Client()))
		if res.Passed {
			t.Fatalf("host 404s on the key file but check passed: %q", res.Message)
		}
	})
	t.Run("host serves the key", func(t *testing.T) {
		res, _ := IndexNowCheck{}.Run(indexNowCtx(t, nil, serving.URL, serving.Client()))
		if !res.Passed {
			t.Fatalf("expected pass: %q", res.Message)
		}
	})
	t.Run("blocked host falls back to source", func(t *testing.T) {
		res, _ := IndexNowCheck{}.Run(indexNowCtx(t, job, blocked.URL, blocked.Client()))
		if !res.Passed {
			t.Fatalf("a 403 is not a verdict; source heuristics should decide: %q", res.Message)
		}
	})
	t.Run("offline scan uses heuristics", func(t *testing.T) {
		res, _ := IndexNowCheck{}.Run(indexNowCtx(t, job, "", nil))
		if !res.Passed {
			t.Fatalf("expected heuristic pass offline: %q", res.Message)
		}
	})
}

// TestIndexNowEnvNeedsValue: a placeholder INDEXNOW_KEY= in .env.example
// configures nothing.
func TestIndexNowEnvNeedsValue(t *testing.T) {
	cases := []struct {
		body string
		pass bool
	}{
		{"INDEXNOW_KEY=\n", false},
		{"INDEXNOW_KEY=\"\"\nOTHER=1\n", false},
		{"# INDEXNOW_KEY=abc\n", false},
		{"INDEXNOW_KEY=" + indexNowTestKey + "\n", true},
		{"export INDEXNOW_KEY='" + indexNowTestKey + "'\n", true},
	}
	for _, tc := range cases {
		ctx := indexNowCtx(t, map[string]string{".env.example": tc.body}, "", nil)
		res, _ := IndexNowCheck{}.Run(ctx)
		if res.Passed != tc.pass {
			t.Errorf("%q: passed=%v want %v (%s)", tc.body, res.Passed, tc.pass, res.Message)
		}
	}
}
