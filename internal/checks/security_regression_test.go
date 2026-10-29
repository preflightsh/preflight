package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

func regressionContext(root string) Context {
	return Context{RootDir: root, Config: &config.PreflightConfig{Stack: "static", Services: map[string]config.ServiceConfig{}}}
}

func TestSecretsCoverExamplesAndLargeFiles(t *testing.T) {
	for _, tc := range []struct{ name, pad string }{{"settings.example.js", ""}, {".env.example", ""}, {"large.js", strings.Repeat(" ", 2<<20)}} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, tc.name, tc.pad+"\nTOKEN="+fakeGHPATa)
			r, _ := (SecretScanCheck{}).Run(regressionContext(root))
			if r.Passed || r.Severity != SeverityError {
				t.Fatalf("result=%+v", r)
			}
		})
	}
	t.Run("oversized input is inconclusive", func(t *testing.T) {
		root := t.TempDir()
		p := filepath.Join(root, "large.js")
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(33 << 20); err != nil {
			t.Fatal(err)
		}
		f.Close()
		r, _ := (SecretScanCheck{}).Run(regressionContext(root))
		if r.Passed || !r.Inconclusive {
			t.Fatalf("result=%+v", r)
		}
	})
}

func TestPublicIdentifiersAndPrivateKeyRegex(t *testing.T) {
	root := t.TempDir()
	body := `Sentry.init({dsn:"https://` + strings.Repeat("a", 32) + `@o123.ingest.sentry.io/123"}); posthog.init('phc_` + strings.Repeat("b", 40) + `');`
	writeFixture(t, root, "client.js", body)
	writeFixture(t, root, "patterns.go", "package patterns\nvar pattern = `-----BEGIN PGP PRIVATE KEY BLOCK`\n")
	if r, _ := (SecretScanCheck{}).Run(regressionContext(root)); !r.Passed {
		t.Fatalf("public identifiers reported: %+v", r)
	}
	writeFixture(t, root, "secret.pem", "-----BEGIN PRIVATE KEY-----\nprivate key data\n-----END PRIVATE KEY-----")
	// Extensionless/private-key files are also in scope.
	writeFixture(t, root, "secret", "-----BEGIN PRIVATE KEY-----\nprivate key data\n-----END PRIVATE KEY-----")
	if r, _ := (SecretScanCheck{}).Run(regressionContext(root)); r.Passed {
		t.Fatal("actual private-key header missed")
	}
}

func TestEnvParityReadErrorsAreNotPasses(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, ".env.example", "REQUIRED=\n")
	writeFixture(t, root, ".env", "LONG="+strings.Repeat("x", 3<<20))
	r, _ := EnvParityCheck{}.Run(envParityCtx(root))
	if r.Passed || !r.Inconclusive {
		t.Fatalf("result=%+v", r)
	}
}

func TestDebugGuardPolarityScopeAndStrings(t *testing.T) {
	cases := []struct {
		name, body string
		found      bool
	}{
		{"production", "if(process.env.NODE_ENV === 'production') { debugger; }", true},
		{"prod flag", "if(import.meta.env.PROD) { console.log('debug'); }", true},
		{"closed block", "if(isDev) { work(); }\nconsole.log('unguarded');", true},
		{"same line closed block", "if(isDev) { work(); } console.log('unguarded');", true},
		{"negated development", "if(!isDev) { console.log('production'); }", true},
		{"development block", "if(import.meta.env.DEV) {\nconsole.log('development');\n}", false},
		{"development inline", "if(isDev) console.log('development');", false},
		{"literal", "const hint = 'console.log(x)';", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "app.js", tc.body)
			if got := len(scanForDebugStatements(root, nil)) > 0; got != tc.found {
				t.Fatalf("found=%v want=%v", got, tc.found)
			}
		})
	}
}

func TestDynamicEmptyMetadataCannotPass(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "app/layout.tsx", "export async function generateMetadata(){return {}}\nexport default function Layout(){return <html><body/></html>}")
	ctx := regressionContext(root)
	ctx.Config.Stack = "next"
	for _, c := range []Check{SEOMetadataCheck{}, OGTwitterCheck{}} {
		r, _ := c.Run(ctx)
		if r.Passed {
			t.Fatalf("%s passed empty generator", c.ID())
		}
	}
}

func TestDeployedMetadataOverridesStaticHints(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "index.html", `<title>Test</title><meta name="description" content="d"><meta property="og:title" content="t"><meta property="og:description" content="d"><link rel="canonical" href="https://example.com/"><html lang="en"><meta name="viewport" content="width=device-width"><script type="application/ld+json">{}</script>`)
	ctx := regressionContext(root)
	ctx.Config.URLs.Production = "https://example.com"
	ctx.PageFetchProduction = PageFetch{URL: ctx.Config.URLs.Production, Status: 200}
	ctx.PageHTMLProduction = "<html><body>Missing metadata</body></html>"
	for _, c := range []Check{SEOMetadataCheck{}, CanonicalURLCheck{}, LangAttributeCheck{}, ViewportCheck{}, StructuredDataCheck{}, OGTwitterCheck{}} {
		t.Run(c.ID(), func(t *testing.T) {
			r, _ := c.Run(ctx)
			if r.Passed {
				t.Fatalf("static hints masked deployed absence: %+v", r)
			}
		})
	}
}

func TestSecurityHeaderValues(t *testing.T) {
	cases := []struct {
		name, value string
		valid       bool
	}{
		{"Strict-Transport-Security", "max-age=0", false}, {"Strict-Transport-Security", "max-age=31536000; includeSubDomains", true},
		{"X-Content-Type-Options", "invalid", false}, {"X-Content-Type-Options", "nosniff", true},
		{"Referrer-Policy", "invalid", false}, {"Referrer-Policy", "strict-origin-when-cross-origin", true},
		{"Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'", false}, {"Content-Security-Policy", "default-src 'self'", true},
		{"Content-Security-Policy", "style-src 'self'", false}, {"Content-Security-Policy", "script-src 'nonce-a' 'unsafe-inline'", true},
	}
	for _, tc := range cases {
		t.Run(tc.name+" "+tc.value, func(t *testing.T) {
			if got := validSecurityHeader(tc.name, tc.value); got != tc.valid {
				t.Fatalf("valid=%v", got)
			}
		})
	}
}

func TestEnvConfigurationRequiresMeaningfulAssignments(t *testing.T) {
	cases := []struct {
		name, file, body string
		pass             bool
	}{
		{"wrong field", ".env", "OPENAI_NOT_A_KEY=anything", false}, {"empty", ".env", "OPENAI_API_KEY=", false}, {"placeholder", ".env", "OPENAI_API_KEY=your_key_here", false}, {"sample", ".env.example", "OPENAI_API_KEY=value", false}, {"comment", ".env", "# OPENAI_API_KEY=value", false}, {"actual", ".env", "export OPENAI_API_KEY=value", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, tc.file, tc.body)
			ctx := regressionContext(root)
			ctx.Config.Services["openai"] = config.ServiceConfig{Declared: true}
			r, _ := OpenAICheck.Run(ctx)
			if r.Passed != tc.pass {
				t.Fatalf("result=%+v", r)
			}
		})
	}
}

func TestLegalEvidenceCannotBeDirectoryOrExternalRedirect(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"privacy", "terms"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if r, _ := (LegalPagesCheck{}).Run(regressionContext(root)); r.Passed {
		t.Fatal("directories counted as pages")
	}
	for _, location := range []string{"//attacker.invalid/privacy", "https://attacker.invalid/privacy", "http://example.com/privacy", "https://example.com:8443/privacy"} {
		if isSameDomainRedirect("https://example.com", location) {
			t.Fatalf("accepted %q", location)
		}
	}
	if !isSameDomainRedirect("https://example.com", "/privacy-policy") {
		t.Fatal("local redirect rejected")
	}
}

func TestServiceLanguageCoverage(t *testing.T) {
	for _, ext := range []string{".rs", ".java", ".kt", ".cs", ".ex", ".exs"} {
		t.Run(ext, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, "src/app"+ext, `client = "https://api.openai.com"`)
			ctx := regressionContext(root)
			ctx.Config.Services["openai"] = config.ServiceConfig{Declared: true}
			if r, _ := OpenAICheck.Run(ctx); !r.Passed {
				t.Fatalf("language missed: %+v", r)
			}
		})
	}
}

func TestDependencyDiscoveryAndUnavailableTools(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"go.mod", "package-lock.json", "apps/shop/yarn.lock", "services/api/Cargo.lock", "node_modules/vendor/package-lock.json"} {
		writeFixture(t, root, name, "fixture")
	}
	tasks, err := discoverAudits(regressionContext(root))
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 4 {
		t.Fatalf("targets=%+v", tasks)
	}
	t.Setenv("PATH", t.TempDir())
	r, _ := VulnerabilityCheck{}.Run(regressionContext(root))
	if r.Passed || !r.Inconclusive || !strings.Contains(r.Message, "4 project/ecosystem") {
		t.Fatalf("result=%+v", r)
	}
	empty := t.TempDir()
	r, _ = VulnerabilityCheck{}.Run(regressionContext(empty))
	if r.Passed || !r.Skipped {
		t.Fatalf("no manifests result=%+v", r)
	}
	for _, manifest := range []string{"pyproject.toml", "Pipfile", "poetry.lock", "uv.lock", "pnpm-lock.yaml", "bun.lock", "pom.xml", "build.gradle.kts", "mix.exs"} {
		unsupported := t.TempDir()
		writeFixture(t, unsupported, manifest, "fixture")
		r, _ = VulnerabilityCheck{}.Run(regressionContext(unsupported))
		if r.Passed || !r.Inconclusive || r.Skipped {
			t.Fatalf("%s result=%+v", manifest, r)
		}
	}
}

func TestStripeRequiresActualNonemptyEnvValues(t *testing.T) {
	for _, tc := range []struct{ file, content string }{
		{".env.example", "STRIPE_SECRET_KEY=sk_test_fixture\n"},
		{".env", "STRIPE_SECRET_KEY=\n"},
		{".env", "STRIPE_SECRET_KEY=\"\"\n"},
		{".env", "STRIPE_SECRET_KEY=your_key\n"},
		{".env", "UNRELATED_STRIPE_SECRET_KEY=sk_test_fixture\n"},
	} {
		root := t.TempDir()
		writeFixture(t, root, "src/payments.go", "package payments\nfunc charge(){ stripe.Key = k }\n")
		writeFixture(t, root, tc.file, tc.content)
		if r, _ := (StripeWebhookCheck{}).Run(stripeCtx(root)); r.Passed {
			t.Fatalf("accepted %s %q", tc.file, tc.content)
		}
	}
}

func TestMailRecordsValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []string
		valid   bool
	}{
		{"valid", []string{"v=spf1 include:example.com -all"}, true}, {"wrong version", []string{"v=spf10 -all"}, false}, {"duplicates", []string{"v=spf1 -all", "v=spf1 ~all"}, false}, {"invalid syntax", []string{"v=spf1 include:"}, false},
	} {
		t.Run("spf "+tc.name, func(t *testing.T) {
			ok, _, _ := evaluateSPF(tc.records, nil)
			if ok != tc.valid {
				t.Fatalf("valid=%v", ok)
			}
		})
	}
	for _, tc := range []struct {
		name    string
		records []string
		valid   bool
	}{
		{"valid", []string{"v=DMARC1; p=reject"}, true}, {"missing policy", []string{"v=DMARC1"}, false}, {"duplicates", []string{"v=DMARC1; p=none", "v=DMARC1; p=reject"}, false}, {"invalid policy", []string{"v=DMARC1; p=bad"}, false},
	} {
		t.Run("dmarc "+tc.name, func(t *testing.T) {
			ok, _, _ := evaluateDMARC(tc.records, nil)
			if ok != tc.valid {
				t.Fatalf("valid=%v", ok)
			}
		})
	}
	ctx := regressionContext(t.TempDir())
	ctx.Config.Checks.EmailAuth = &config.EmailAuthConfig{Enabled: true}
	if r, _ := (EmailAuthCheck{}).Run(ctx); r.Passed || !r.Skipped {
		t.Fatal("missing mail domain passed")
	}
}

func TestFetchCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body, fetch := FetchPage(ctx, srv.Client(), srv.URL)
	if body != "" || fetch.Status != 0 {
		t.Fatal("cancelled fetch succeeded")
	}
}

func FuzzRenderedHTML(f *testing.F) {
	for _, seed := range []string{"<html lang='en'><title>T</title></html>", "<meta name=description content=''>", "<script type=application/ld+json>{}</script>"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			t.Skip()
		}
		d := parseRenderedHTML(s)
		_ = d.hasMeta("og:image")
		_ = d.hasLinkRel("canonical")
		_ = maskCodeStrings(s)
		_ = stripComments(s)
	})
}
