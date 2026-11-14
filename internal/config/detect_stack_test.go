package config

import (
	"strings"
	"testing"
)

// Substring matches on package.json used to make "sanity" and "contentful"
// win over the real framework, and any file named "craft" meant Craft CMS.
func TestDetectStackDependencyMatching(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"sanity-check script is not Sanity", map[string]string{
			"package.json":   `{"scripts":{"sanity-check":"node x.js"},"dependencies":{"react":"^18"}}`,
			"vite.config.ts": "export default {}",
		}, "vite"},
		{"react app using the contentful SDK", map[string]string{
			"package.json":   `{"dependencies":{"react":"^18","contentful":"^10"}}`,
			"vite.config.ts": "export default {}",
		}, "vite"},
		{"sanity studio", map[string]string{
			"package.json":     `{"dependencies":{"sanity":"^3","react":"^18"}}`,
			"sanity.config.ts": "export default {}",
		}, "sanity"},
		{"bare contentful project", map[string]string{
			"package.json": `{"dependencies":{"contentful":"^10"}}`,
		}, "contentful"},
		{"craft directory is not Craft CMS", map[string]string{
			"craft/notes.txt": "hello",
			"index.php":       "<?php echo 1;",
		}, "php"},
		{"craft console script", map[string]string{
			"craft":     "#!/usr/bin/env php\n<?php\n// Craft console application\n",
			"index.php": "<?php echo 1;",
		}, "craft"},
		// Vite-based meta-frameworks ship a vite.config.*, which used to win
		// and turn off the layout-based SEO checks.
		{"sveltekit with vite config", map[string]string{
			"package.json":     `{"devDependencies":{"@sveltejs/kit":"^2","svelte":"^5","vite":"^5"}}`,
			"vite.config.ts":   "export default {}",
			"svelte.config.js": "export default {}",
		}, "svelte"},
		{"remix with vite config", map[string]string{
			"package.json":   `{"dependencies":{"@remix-run/react":"^2","react":"^18"}}`,
			"vite.config.ts": "export default {}",
		}, "remix"},
		{"remix classic compiler", map[string]string{
			"package.json":    `{"dependencies":{"@remix-run/node":"^2","react":"^18"}}`,
			"remix.config.js": "module.exports = {}",
			"app/root.tsx":    "export default function App() {}",
		}, "remix"},
		{"nuxt with vite config", map[string]string{
			"package.json":   `{"dependencies":{"nuxt":"^3","vue":"^3"}}`,
			"vite.config.ts": "export default {}",
		}, "nuxt"},
		{"nuxt config only", map[string]string{
			"package.json":   `{"scripts":{"dev":"nuxi dev"}}`,
			"nuxt.config.ts": "export default defineNuxtConfig({})",
		}, "nuxt"},
		{"plain vite react app", map[string]string{
			"package.json":   `{"dependencies":{"react":"^18"},"devDependencies":{"vite":"^5"}}`,
			"vite.config.ts": "export default {}",
		}, "vite"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectStack(writeProject(t, tc.files)); got != tc.want {
				t.Errorf("DetectStack = %q, want %q", got, tc.want)
			}
		})
	}
}

// A requirements.txt beside a frontend app used to make the project
// "python", and a Next app with no next.config.* was "react".
func TestDetectStackOrdering(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"vite react app with python scripts", map[string]string{
			"package.json":     `{"dependencies":{"react":"^18"},"devDependencies":{"vite":"^5"}}`,
			"vite.config.ts":   "export default {}",
			"requirements.txt": "requests\n",
		}, "vite"},
		{"flask app that bundles assets with vite", map[string]string{
			"package.json":     `{"devDependencies":{"vite":"^5"}}`,
			"vite.config.ts":   "export default {}",
			"requirements.txt": "flask\n",
		}, "python"},
		{"django with a react frontend stays django", map[string]string{
			"package.json":     `{"dependencies":{"react":"^18"}}`,
			"requirements.txt": "django\n",
			"manage.py":        "#!/usr/bin/env python\n",
		}, "django"},
		{"plain python project", map[string]string{
			"requirements.txt": "flask\n",
		}, "python"},
		{"next without a config file", map[string]string{
			"package.json": `{"dependencies":{"next":"^15","react":"^19"}}`,
		}, "next"},
		{"next with python scripts", map[string]string{
			"package.json":     `{"dependencies":{"next":"^15","react":"^19"}}`,
			"requirements.txt": "requests\n",
		}, "next"},
		{"plain react app", map[string]string{
			"package.json": `{"dependencies":{"react":"^19"}}`,
		}, "react"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectStack(writeProject(t, tc.files)); got != tc.want {
				t.Errorf("DetectStack = %q, want %q", got, tc.want)
			}
		})
	}
}

// A virtualenv's installed packages are not the project's code, and
// apps/web is the web app of a monorepo, not a compiled web root.
func TestDetectServicesSkipDirs(t *testing.T) {
	dir := writeProject(t, map[string]string{
		".venv/lib/python3.12/site-packages/foo/a.py": "from openai import OpenAI\nimport redis\nr = 'redis://localhost'\n",
		"venv/lib/b.py":                  "import sentry_sdk\nsentry_sdk.init(dsn='https://x@sentry.io/1')\n",
		".svelte-kit/output/server/x.js": "posthog.init('k')\n",
		"web/assets/bundle.js":           "mixpanel.init('k')\n",
		"public/build/app.js":            "LogRocket.init('k')\n",
	})
	got := DetectServices(dir)
	for _, svc := range []string{"openai", "redis", "sentry", "posthog", "mixpanel", "logrocket"} {
		if got[svc] {
			t.Errorf("%s detected from a skipped directory", svc)
		}
	}

	dir = writeProject(t, map[string]string{
		"apps/web/src/layout.tsx":      "Sentry.init({})\n",
		"apps/api/public/widget.js":    "mixpanel.init('k')\n",
		"packages/ui/storage/index.ts": "posthog.init('k')\n",
	})
	got = DetectServices(dir)
	for _, svc := range []string{"sentry", "mixpanel", "posthog"} {
		if !got[svc] {
			t.Errorf("%s not detected below the project root", svc)
		}
	}
}

// Only what a manifest depends on counts: not its description, keywords,
// script names, or a commented-out gem.
func TestDetectServicesReadsDependenciesOnly(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"package.json":  `{"name":"mixpanel-exporter","description":"take payments with stripe, report to bugsnag","keywords":["twilio"],"scripts":{"firebase":"echo"},"dependencies":{"left-pad":"^1"},"devDependencies":{"@sentry/cli":"^2"}}`,
		"composer.json": `{"description":"a mailgun and cloudinary bridge","require":{"php":"^8.2"},"require-dev":{"algolia/algoliasearch-client-php":"^4"}}`,
		"Gemfile":       "source 'https://rubygems.org'\n# gem 'rollbar'\ngem 'rails' # replaces honeybadger\ngem 'sidekiq'\n",
	})
	got := DetectServices(dir)
	for _, svc := range []string{"mixpanel", "stripe", "bugsnag", "twilio", "firebase", "mailgun", "cloudinary", "rollbar", "honeybadger"} {
		if got[svc] {
			t.Errorf("%s detected from text that is not a dependency", svc)
		}
	}
	for _, svc := range []string{"sentry", "algolia", "sidekiq"} {
		if !got[svc] {
			t.Errorf("%s is a dependency and was not detected", svc)
		}
	}
	// A manifest that is not valid JSON is still read, as before.
	dir = writeProject(t, map[string]string{"package.json": `{"dependencies":{"stripe":"^1",}}`})
	if !DetectServices(dir)["stripe"] {
		t.Error("stripe not detected in a malformed package.json")
	}
}

func TestScanEnvFileHandlesExportAndIndent(t *testing.T) {
	dir := writeProject(t, map[string]string{
		".env": "\xef\xbb\xbfexport STRIPE_SECRET_KEY=x\n  SENTRY_DSN=y\n\texport\tPOSTHOG_KEY=z\n# MAILGUN_API_KEY=commented\nexported_TWILIO_SID=no\n",
	})
	got := DetectServices(dir)
	for _, svc := range []string{"stripe", "sentry", "posthog"} {
		if !got[svc] {
			t.Errorf("%s not detected", svc)
		}
	}
	for _, svc := range []string{"mailgun", "twilio"} {
		if got[svc] {
			t.Errorf("%s detected from a comment or a different variable", svc)
		}
	}
}

// Every caller lowercases content first, so mixed-case patterns never matched.
func TestDetectServicesBraintreeAndBunny(t *testing.T) {
	cases := []struct {
		name    string
		content string
		svc     string
		want    bool
	}{
		{"braintree npm dependency", `{"dependencies":{"braintree":"^3"}}`, "braintree", true},
		{"braintree gem", "gem 'braintree'\n", "braintree", true},
		{"braintree env key", "BRAINTREE_MERCHANT_ID=abc\n", "braintree", true},
		{"bunny gem", "gem \"bunny\"\n", "rabbitmq", true},
		{"bunnycdn package is not rabbitmq", `{"dependencies":{"bunnycdn-storage":"^1"}}`, "rabbitmq", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			services := map[string]bool{}
			detectServicesFromContent(strings.ToLower(tc.content), services, "node")
			if services[tc.svc] != tc.want {
				t.Errorf("%s detected = %v, want %v", tc.svc, services[tc.svc], tc.want)
			}
		})
	}
}
