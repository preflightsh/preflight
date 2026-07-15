package checks

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// ServiceCheck backs roughly a third of the registry, so a bug in its
// step ordering shows up across dozens of integration checks at once.
// These pin the documented order: declared -> env -> live -> code -> warn.

type svcOpts struct {
	declared bool
	envFile  string // contents of .env, if any
	codeFile string // contents of an index.html at the project root, if any
	prodURL  string
	client   *http.Client
}

func newServiceCheck() ServiceCheck {
	return ServiceCheck{
		CheckID:        "acme",
		CheckTitle:     "Acme",
		EnvPrefixes:    []string{"ACME_"},
		LivePatterns:   []*regexp.Regexp{regexp.MustCompile(`acme\.js`)},
		CodePatterns:   []*regexp.Regexp{regexp.MustCompile(`acme-sdk`)},
		EnvFoundMsg:    "env-found",
		LiveFoundMsg:   "live-found",
		CodeFoundMsg:   "code-found",
		LiveMissingMsg: "live-missing",
		NotFoundMsg:    "not-found",
	}
}

func runServiceCheck(t *testing.T, o svcOpts) CheckResult {
	t.Helper()
	dir := t.TempDir()
	if o.envFile != "" {
		if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(o.envFile), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if o.codeFile != "" {
		if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(o.codeFile), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	services := map[string]config.ServiceConfig{}
	if o.declared {
		services["acme"] = config.ServiceConfig{Declared: true}
	}
	res, err := newServiceCheck().Run(Context{
		RootDir: dir,
		Client:  o.client,
		Config: &config.PreflightConfig{
			Stack:    "static",
			Services: services,
			URLs:     config.URLConfig{Production: o.prodURL},
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

func TestServiceCheckPriority(t *testing.T) {
	t.Run("not declared skips", func(t *testing.T) {
		res := runServiceCheck(t, svcOpts{declared: false})
		if !res.Passed || res.Message != "Acme not declared, skipping" {
			t.Errorf("got passed=%v msg=%q, want the skip message", res.Passed, res.Message)
		}
	})

	t.Run("env var wins over everything", func(t *testing.T) {
		res := runServiceCheck(t, svcOpts{declared: true, envFile: "ACME_KEY=x\n"})
		if !res.Passed || res.Message != "env-found" {
			t.Errorf("got passed=%v msg=%q, want env-found", res.Passed, res.Message)
		}
	})

	t.Run("live match beats code match", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`<script src="/acme.js"></script>`))
		}))
		defer srv.Close()
		res := runServiceCheck(t, svcOpts{
			declared: true, prodURL: srv.URL, client: srv.Client(),
			codeFile: "acme-sdk",
		})
		if !res.Passed || res.Message != "live-found" {
			t.Errorf("got passed=%v msg=%q, want live-found", res.Passed, res.Message)
		}
	})

	t.Run("code match with no URL configured passes", func(t *testing.T) {
		res := runServiceCheck(t, svcOpts{declared: true, codeFile: "acme-sdk"})
		if !res.Passed || res.Message != "code-found" {
			t.Errorf("got passed=%v msg=%q, want code-found", res.Passed, res.Message)
		}
	})

	t.Run("code match but live page lacks it warns", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`<html>nothing here</html>`))
		}))
		defer srv.Close()
		res := runServiceCheck(t, svcOpts{
			declared: true, prodURL: srv.URL, client: srv.Client(),
			codeFile: "acme-sdk",
		})
		if res.Passed || res.Message != "live-missing" {
			t.Errorf("got passed=%v msg=%q, want live-missing", res.Passed, res.Message)
		}
	})

	t.Run("nothing found warns", func(t *testing.T) {
		res := runServiceCheck(t, svcOpts{declared: true})
		if res.Passed || res.Message != "not-found" {
			t.Errorf("got passed=%v msg=%q, want not-found", res.Passed, res.Message)
		}
	})

	t.Run("live match alone passes without code", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`acme.js`))
		}))
		defer srv.Close()
		res := runServiceCheck(t, svcOpts{declared: true, prodURL: srv.URL, client: srv.Client()})
		if !res.Passed || res.Message != "live-found" {
			t.Errorf("got passed=%v msg=%q, want live-found", res.Passed, res.Message)
		}
	})
}

// An unreachable site is not evidence that the integration is missing from
// it. checkLiveSiteForPatterns returns the same (false, url) for "fetched
// and did not match" as for "could not fetch at all", so a site that is
// down, or a CI runner with no egress, turns a passing code-found result
// into a "not live" warning about a page nobody ever looked at.
func TestServiceCheckUnreachableLiveSite(t *testing.T) {
	// Bind then immediately close, so the port is dead but well-formed.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	res := runServiceCheck(t, svcOpts{
		declared: true, prodURL: deadURL, client: &http.Client{},
		codeFile: "acme-sdk",
	})

	if !res.Passed || res.Message != "code-found" {
		t.Errorf("unreachable prod + code present: got passed=%v msg=%q, want code-found. "+
			"An unreachable page is not evidence the integration is missing from it.",
			res.Passed, res.Message)
	}
}

// checkLiveSiteForPatterns is called directly by the cookie-consent checks
// as well as through ServiceCheck, and they use the same "did we inspect a
// page" idiom, so pin its contract at the source.
func TestCheckLiveSiteForPatterns(t *testing.T) {
	patterns := []*regexp.Regexp{regexp.MustCompile(`acme\.js`)}

	newCtx := func(prod string, client *http.Client) Context {
		return Context{
			Client: client,
			Config: &config.PreflightConfig{URLs: config.URLConfig{Production: prod}},
		}
	}

	t.Run("no URL configured inspects nothing", func(t *testing.T) {
		found, url := checkLiveSiteForPatterns(newCtx("", &http.Client{}), patterns)
		if found || url != "" {
			t.Errorf("got (%v, %q), want (false, \"\")", found, url)
		}
	})

	t.Run("nil client inspects nothing", func(t *testing.T) {
		found, url := checkLiveSiteForPatterns(newCtx("https://example.com", nil), patterns)
		if found || url != "" {
			t.Errorf("got (%v, %q), want (false, \"\")", found, url)
		}
	})

	t.Run("unreachable URL inspects nothing", func(t *testing.T) {
		dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		deadURL := dead.URL
		dead.Close()

		found, url := checkLiveSiteForPatterns(newCtx(deadURL, &http.Client{}), patterns)
		if found || url != "" {
			t.Errorf("got (%v, %q), want (false, \"\"): a failed fetch inspected no page", found, url)
		}
	})

	t.Run("reachable page without the pattern is inspected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<html>nothing</html>"))
		}))
		defer srv.Close()

		found, url := checkLiveSiteForPatterns(newCtx(srv.URL, srv.Client()), patterns)
		if found {
			t.Error("found = true, want false")
		}
		if url == "" {
			t.Error("url is empty, want the inspected URL: the page was fetched and read")
		}
	})

	t.Run("reachable page with the pattern", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`<script src="/ACME.JS"></script>`))
		}))
		defer srv.Close()

		found, _ := checkLiveSiteForPatterns(newCtx(srv.URL, srv.Client()), patterns)
		if !found {
			t.Error("found = false, want true (body is lowercased before matching)")
		}
	})

	t.Run("falls back to staging when production is unset", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("acme.js"))
		}))
		defer srv.Close()

		ctx := Context{
			Client: srv.Client(),
			Config: &config.PreflightConfig{URLs: config.URLConfig{Staging: srv.URL}},
		}
		if found, _ := checkLiveSiteForPatterns(ctx, patterns); !found {
			t.Error("found = false, want true from the staging URL")
		}
	})
}
