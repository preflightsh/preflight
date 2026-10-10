package checks

import (
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

func sentryCtx(root string) Context {
	return Context{RootDir: root, Config: &config.PreflightConfig{
		Services: map[string]config.ServiceConfig{"sentry": {Declared: true}},
	}}
}

// TestSentryDetection: Go's sentry.Init under cmd/, Django settings, and a
// declared SDK all count; the old search was case-sensitive, skipped .go, and
// only looked in src, app, lib and config.
func TestSentryDetection(t *testing.T) {
	cases := map[string]map[string]string{
		"go init under cmd": {"cmd/server/main.go": "package main\nfunc main(){ sentry.Init(sentry.ClientOptions{}) }\n"},
		"django settings":   {"mysite/settings.py": "import sentry_sdk\nsentry_sdk.init(dsn=DSN)\n"},
		"go.mod dependency": {"go.mod": "module x\nrequire github.com/getsentry/sentry-go v0.30.0\n"},
		"python dependency": {"requirements.txt": "sentry-sdk[django]==2.0\n"},
		"node import":       {"src/instrument.ts": "import * as Sentry from \"@sentry/node\"\n"},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for rel, body := range files {
				writeFixture(t, root, rel, body)
			}
			if res, _ := (SentryCheck{}).Run(sentryCtx(root)); !res.Passed {
				t.Fatalf("not found: %q", res.Message)
			}
		})
	}
}

func TestSentryCommentedOutDoesNotCount(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "app/main.py", "# sentry_sdk.init(dsn=DSN)\n")
	writeFixture(t, root, "src/index.js", "// Sentry.init({ dsn })\n")
	if res, _ := (SentryCheck{}).Run(sentryCtx(root)); res.Passed {
		t.Fatalf("commented-out init counted: %q", res.Message)
	}
}
