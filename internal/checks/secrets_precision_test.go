package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic values shaped like real tokens. None of them is a credential.
const (
	fakeBody24 = "a1B2c3D4e5F6g7H8i9J0k1L2"
	fakeBody32 = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
	fakeBody48 = fakeBody24 + "Z9y8X7w6V5u4T3s2R1q0P9o8"
	fakeHex32  = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	fakeHex64  = fakeHex32 + "1a2b3c4d5e6f708192a3b4c5d6e7f809"
	fakeUpper  = "Q7W2E9R4T1Y8U3I6"
)

// secretsResult runs the secrets check over one file outside a git repo.
func secretsResult(t *testing.T, name, body string) CheckResult {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, name, body)
	r, err := (SecretScanCheck{}).Run(regressionContext(root))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestSecretsIgnoreLookalikes: text that merely resembles a key must not be
// an error. Each of these was reported, or would be by an unanchored
// pattern, and an error here is exit 2 on a project with nothing wrong.
func TestSecretsIgnoreLookalikes(t *testing.T) {
	cases := []struct{ name, file, body string }{
		{"env var name starting GOOGLE_", "src/config.js", "const bucket = process.env.GOOGLE_CLOUD_STORAGE_BUCKET_NAME;\n"},
		{"longer GOOGLE_ name", "src/config.js", "const k = process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON_BASE64;\n"},
		{"GOOG run without digits", "src/a.js", "const GOOGLEANALYTICSMEASUREMENTID = 1;\n"},
		{"AWS docs example key", ".env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"},
		{"x filler token", ".env", "GITHUB_TOKEN=ghp_" + strings.Repeat("x", 36) + "\n"},
		{"x filler stripe key in an example file", ".env.example", "STRIPE_SECRET_KEY=sk_test_" + strings.Repeat("x", 24) + "\n"},
		{"zero filler", "config.yml", "token: ghp_" + strings.Repeat("0", 36) + "\n"},
		{"placeholder words", ".env.example", "STRIPE_SECRET_KEY=sk_live_" + "YourStripeSecretKeyGoesHere1\n"},
		{"two character body", "config.yml", "key: sk_live_" + strings.Repeat("ab", 14) + "\n"},
		{"cache key with an md5", "src/cache.js", "const id = 'cache-key-" + fakeHex32 + "'\n"},
		{"mailgun shape inside a longer hash", "src/a.js", "const id = 'key-" + fakeHex64 + "'\n"},
		{"identifier ending re_", "src/store.js", "const v = store_" + fakeBody32 + ";\n"},
		{"identifier ending sk-", "src/task.js", "const id = 'task-" + fakeBody48 + "'\n"},
		{"identifier ending npm_", "src/a.js", "const v = 'pnpm_" + fakeBody24 + "Z9y8X7w6V5u4'\n"},
		{"AKIA inside a longer run", "src/a.js", "const v = 'ZZAKIA" + fakeUpper + "'\n"},
		{"AKIA followed by more", "src/a.js", "const v = 'AKIA" + fakeUpper + "Q7W2'\n"},
		{"ASIA inside a word", "src/a.js", "const v = 'FANTASIA" + fakeUpper + "'\n"},
		{"AIza inside a base64 run", "package-lock.json", `{"integrity": "sha512-Qm9/AIza` + fakeBody24 + "Z9y8X7w6V5u" + `+x/3w=="}` + "\n"},
		{"discord shape inside a longer token", "src/a.js", "const jwt = 'eyJhbGciOiJIUzI1NiJ9.M" + fakeBody24 + ".a1B2c3." + fakeBody24 + "Z9y" + "'\n"},
		{"shopify shape with a prefix", "src/a.js", "const v = 'myshpat_" + fakeHex32 + "'\n"},
		{"restricted test key shape with a prefix", "src/a.js", "const v = 'mark_test_" + fakeBody24 + "'\n"},
		{"service account shape with a prefix", "src/a.js", "const v = 'task-svcacct-" + fakeBody48 + "'\n"},
		{"slack app shape with a prefix", "src/a.js", "const v = 'boxapp-1-A0B1C2D3-1234-" + fakeBody32 + "'\n"},
		{"digitalocean shape too short", "src/a.js", "const v = 'dop_v1_" + fakeHex32 + "'\n"},
		{"PEM header literal", "src/pem.js", "k.replace(\"-----BEGIN PRIVATE KEY-----\", \"\")\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if r := secretsResult(t, tc.file, tc.body); !r.Passed {
				t.Fatalf("reported: %+v", r)
			}
		})
	}
}

// TestSecretsStillCatchRealShapes: the same patterns, standing alone with a
// varied body, are still errors.
func TestSecretsStillCatchRealShapes(t *testing.T) {
	cases := []struct{ name, body, label string }{
		{"stripe live", "k = \"sk_live_" + fakeBody24 + "\"", "Stripe live key"},
		{"stripe restricted test", "k = \"rk_test_" + fakeBody24 + "\"", "Stripe restricted test key"},
		{"aws access key", "AWS_ACCESS_KEY_ID=AKIA" + fakeUpper, "AWS Access Key ID"},
		{"aws temporary key", "AWS_ACCESS_KEY_ID=ASIA" + fakeUpper, "AWS temporary Access Key ID"},
		{"gcs hmac id", "HMAC_ID=GOOG1E" + fakeUpper + fakeUpper, "Google Cloud HMAC access ID"},
		{"google api key", "key: AIza" + fakeBody24 + "Z9y8X7w6V5u", googleAPIKeyType},
		{"mailgun", "MAILGUN_KEY=key-" + fakeHex32, "Mailgun API key"},
		{"resend, one run", "RESEND=re_" + fakeBody32, "Resend API key"},
		{"resend, two runs", "RESEND=re_a1B2c3D4_" + fakeBody24, "Resend API key"},
		{"discord", "DISCORD=M" + fakeBody24 + ".a1B2c3." + fakeBody24 + "Z9y", "Discord bot token"},
		{"openai service account", "OPENAI=sk-svcacct-" + fakeBody48, "OpenAI service account key"},
		{"shopify", "SHOPIFY=shpat_" + fakeHex32, "Shopify access token"},
		{"slack app", "SLACK=xapp-1-A0B1C2D3-1234-" + fakeBody32, "Slack app-level token"},
		{"digitalocean", "DO=dop_v1_" + fakeHex64, "DigitalOcean access token"},
		{"two tokens one character apart", "a=ghp_" + fakeBody24 + "m3N4o5P6q7R8,ghp_" + fakeBody24 + "Z9y8X7w6V5u4", "found in 2 place(s)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := secretsResult(t, "config.yml", tc.body+"\n")
			if r.Passed || r.Severity != SeverityError {
				t.Fatalf("missed: %+v", r)
			}
			if !strings.Contains(r.Message+strings.Join(r.Suggestions, " "), tc.label) {
				t.Errorf("label %q not in %q %v", tc.label, r.Message, r.Suggestions)
			}
		})
	}
}

// TestSecretsURLCredentials: a real password in a connection URL is a leak;
// templates, interpolations, and local defaults are not.
func TestSecretsURLCredentials(t *testing.T) {
	cases := []struct {
		name, line string
		found      bool
	}{
		{"database url", "DATABASE_URL=postgres://app:" + fakeBody24 + "@db.prod.acme.io:5432/app", true},
		{"mongodb srv", "MONGO=mongodb+srv://svc:h7Gk2pQ9zL4x@cluster0.ab1cd.mongodb.net/app", true},
		{"basic auth in a registry url", `"url": "https://deploy:h7Gk2pQ9zL4x@git.acme.io/repo.git"`, true},
		{"placeholder password", "DATABASE_URL=postgres://app:password@db.prod.acme.io/app", false},
		{"your password here", "DATABASE_URL=mysql://user:your_password_here@db.prod.acme.io/app", false},
		{"shell interpolation", "DATABASE_URL=postgres://app:${DB_PASSWORD}@db.prod.acme.io/app", false},
		{"ruby interpolation", `url = "postgres://app:#{password}@db.prod.acme.io/app"`, false},
		{"format verb", `dsn := fmt.Sprintf("postgres://app:%s@db.prod.acme.io/app", pw)`, false},
		{"angle bracket template", "postgres://<user>:<password>@db.prod.acme.io/app", false},
		{"compose service host", "DATABASE_URL=postgres://app:h7Gk2pQ9zL4x@db:5432/app", false},
		{"localhost", "REDIS_URL=redis://default:h7Gk2pQ9zL4x@localhost:6379", false},
		{"loopback", "DATABASE_URL=mysql://root:h7Gk2pQ9zL4x@127.0.0.1/app", false},
		{"private address", "connect ECONNREFUSED postgres://app:h7Gk2pQ9zL4x@10.0.0.12:5432/db", false},
		{"private address, 172 range", "DATABASE_URL=postgres://app:h7Gk2pQ9zL4x@172.20.0.5/db", false},
		{"public address", "DATABASE_URL=postgres://app:h7Gk2pQ9zL4x@172.32.0.5/db", true},
		{"leet placeholder", `"https://jon:s3cr3t@github.com/acme/app.git"`, false},
		{"leet password word", "DATABASE_URL=postgres://app:P4ssw0rd!@db.prod.acme.io/app", false},
		{"documentation host", "https://deploy:h7Gk2pQ9zL4x@git.example.com/repo.git", false},
		{"password same as user", "DATABASE_URL=postgres://postgres:postgres@db.prod.acme.io/app", false},
		{"no password", "https://deploy@git.acme.io/repo.git", false},
		{"port, not a password", "proxy = http://proxy.acme.io:8080/path?x=a@b.co", false},
		{"email after a url", "see https://acme.io/docs: mail ops@acme.io", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := secretsResult(t, "settings.conf", tc.line+"\n")
			if r.Passed == tc.found {
				t.Fatalf("found=%v want %v: %+v", !r.Passed, tc.found, r)
			}
			if tc.found && !strings.Contains(strings.Join(r.Suggestions, " "), urlCredentialsType) {
				t.Errorf("label: %v", r.Suggestions)
			}
		})
	}
}

// TestSecretsScanDrupalAndInfraFiles: PHP in .module and .inc files, state
// files, SQL, and Dockerfile.prod were outside the scanned set.
func TestSecretsScanDrupalAndInfraFiles(t *testing.T) {
	for _, name := range []string{"web/modules/custom/pay/pay.module", "includes/keys.inc", "pay.theme", "pay.install", "terraform.tfstate", "seed.sql", "Dockerfile.prod", "Dockerfile"} {
		t.Run(name, func(t *testing.T) {
			if r := secretsResult(t, name, "KEY sk_live_"+fakeBody24+"\n"); r.Passed {
				t.Fatalf("not scanned: %+v", r)
			}
		})
	}
}

// TestSecretsTrackedFilesUnderSkippedDirs: git carries a tracked file
// whatever its directory is called. build/, vendor/, and the rest are only
// skipped for content git does not track.
func TestSecretsTrackedFilesUnderSkippedDirs(t *testing.T) {
	line := "KEY=\"sk_live_" + fakeBody24 + "\"\n"
	for _, dir := range []string{"build", "vendor", "tmp", "deps", "target", "dist", "coverage", "node_modules/pkg", "deploy/vendor"} {
		t.Run("tracked/"+dir, func(t *testing.T) {
			root := t.TempDir()
			initGitRepo(t, root)
			writeFixture(t, root, dir+"/release.sh", line)
			gitCommit(t, root, dir+"/release.sh")
			r, _ := (SecretScanCheck{}).Run(regressionContext(root))
			if r.Passed || r.Severity != SeverityError || !strings.Contains(strings.Join(r.Suggestions, " "), "[tracked by git]") {
				t.Fatalf("tracked secret under %s missed: %+v", dir, r)
			}
		})
	}
	t.Run("untracked content stays out", func(t *testing.T) {
		root := t.TempDir()
		initGitRepo(t, root)
		writeFixture(t, root, "src/app.js", "export {}\n")
		// A tracked file beside untracked build output: the directory is
		// walked, the untracked file in it is not scanned.
		writeFixture(t, root, "build/tracked.sh", "echo ok\n")
		gitCommit(t, root, "src/app.js", "build/tracked.sh")
		writeFixture(t, root, "build/bundle.js", line)
		writeFixture(t, root, "node_modules/pkg/index.js", line)
		writeFixture(t, root, "vendor/lib/a.php", line)
		if r, _ := (SecretScanCheck{}).Run(regressionContext(root)); !r.Passed {
			t.Fatalf("untracked build output reported: %+v", r)
		}
	})
	t.Run("ignored directory listed whole", func(t *testing.T) {
		root := t.TempDir()
		initGitRepo(t, root)
		writeFixture(t, root, ".gitignore", "secrets/\n")
		gitCommit(t, root, ".gitignore")
		writeFixture(t, root, "secrets/prod.env", line)
		st := loadGitStatus(root)
		if !st.inRepo || !st.ignoredDirs["secrets"] || len(st.ignored) != 0 {
			t.Fatalf("status=%+v", st)
		}
		if r, _ := (SecretScanCheck{}).Run(regressionContext(root)); !r.Passed {
			t.Fatalf("ignored directory reported: %+v", r)
		}
	})
}

// TestSecretsWithoutGit: outside a repository the root .gitignore says what
// is meant to stay out of version control. A project unpacked from an
// archive, or scanned from the Docker image, has no git to ask.
func TestSecretsWithoutGit(t *testing.T) {
	line := "STRIPE_SECRET_KEY=sk_live_" + fakeBody24 + "\n"
	t.Run("ignored env file", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, ".gitignore", "# local settings\n.env\n/config/local/\n*.secret.yml\n")
		writeFixture(t, root, ".env", line)
		writeFixture(t, root, "config/local/keys.yml", line)
		writeFixture(t, root, "deploy/prod.secret.yml", line)
		if r, _ := (SecretScanCheck{}).Run(regressionContext(root)); !r.Passed || r.Inconclusive {
			t.Fatalf("ignored files reported: %+v", r)
		}
	})
	t.Run("env file not ignored", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, ".gitignore", "node_modules/\n")
		writeFixture(t, root, ".env", line)
		if r, _ := (SecretScanCheck{}).Run(regressionContext(root)); r.Passed || r.Severity != SeverityError {
			t.Fatalf("missed: %+v", r)
		}
	})
	t.Run("negated rule", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, ".gitignore", ".env*\n!.env.production\n")
		writeFixture(t, root, ".env.production", line)
		if r, _ := (SecretScanCheck{}).Run(regressionContext(root)); r.Passed {
			t.Fatalf("re-included file skipped: %+v", r)
		}
	})
}

// TestSecretsGitFailureIsInconclusive: inside a repository git cannot read,
// the scan no longer knows which files are committed. It used to fall back
// silently and report every ignored .env as an error.
func TestSecretsGitFailureIsInconclusive(t *testing.T) {
	line := "STRIPE_SECRET_KEY=sk_live_" + fakeBody24 + "\n"
	t.Run("git missing", func(t *testing.T) {
		root := t.TempDir()
		initGitRepo(t, root)
		writeFixture(t, root, ".gitignore", ".env\n")
		writeFixture(t, root, ".env", line)
		writeFixture(t, root, "src/app.js", "export {}\n")
		t.Setenv("PATH", t.TempDir())
		r, _ := (SecretScanCheck{}).Run(regressionContext(root))
		if r.Passed || !r.Inconclusive || r.Severity != SeverityWarn || !strings.Contains(r.Message, "git is not installed") {
			t.Fatalf("result=%+v", r)
		}
		if strings.Contains(r.Message, "\n") || strings.Contains(r.Message, root) {
			t.Errorf("message must be one line without paths: %q", r.Message)
		}
	})
	t.Run("git missing and a secret git would have carried", func(t *testing.T) {
		root := t.TempDir()
		initGitRepo(t, root)
		writeFixture(t, root, "src/app.js", "const k = \"sk_live_"+fakeBody24+"\"\n")
		t.Setenv("PATH", t.TempDir())
		r, _ := (SecretScanCheck{}).Run(regressionContext(root))
		if r.Passed || !r.Inconclusive || r.Severity != SeverityError {
			t.Fatalf("result=%+v", r)
		}
	})
	t.Run("unreadable repository", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFixture(t, root, "src/app.js", "export {}\n")
		r, _ := (SecretScanCheck{}).Run(regressionContext(root))
		if r.Passed || !r.Inconclusive || !strings.Contains(r.Message, "git could not read this repository") {
			t.Fatalf("result=%+v", r)
		}
	})
	t.Run("no repository at all is not a failure", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, "src/app.js", "export {}\n")
		t.Setenv("PATH", t.TempDir())
		if r, _ := (SecretScanCheck{}).Run(regressionContext(root)); !r.Passed || r.Inconclusive {
			t.Fatalf("result=%+v", r)
		}
	})
}

// TestSecretsUnreadableIgnoredDir: a directory the scan would skip anyway
// is not a gap in it.
func TestSecretsUnreadableIgnoredDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	root := t.TempDir()
	initGitRepo(t, root)
	writeFixture(t, root, ".gitignore", "data/\n")
	writeFixture(t, root, "src/app.js", "export {}\n")
	gitCommit(t, root, ".gitignore", "src/app.js")
	locked := filepath.Join(root, "data")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if r, _ := (SecretScanCheck{}).Run(regressionContext(root)); !r.Passed || r.Inconclusive {
		t.Fatalf("result=%+v", r)
	}
}

// TestSecretsFileAtExactlyTheCap: a file of exactly the size cap with no
// final newline fits, and was reported as exceeding the read budget.
func TestSecretsFileAtExactlyTheCap(t *testing.T) {
	token := "TOKEN=" + fakeGHPATa
	for _, tc := range []struct {
		name, tail string
	}{{"no trailing newline", token}, {"trailing newline", token + "\n"}} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			body := strings.Repeat("a\n", (maxSecretFileSize-len(tc.tail))/2)
			body += strings.Repeat(" ", maxSecretFileSize-len(tc.tail)-len(body)) + tc.tail
			if len(body) != maxSecretFileSize {
				t.Fatalf("fixture is %d bytes", len(body))
			}
			writeFixture(t, root, "big.js", body)
			r, _ := (SecretScanCheck{}).Run(regressionContext(root))
			if r.Passed || r.Inconclusive || r.Severity != SeverityError {
				t.Fatalf("result=%+v", r)
			}
		})
	}
}

func TestGitignoreRules(t *testing.T) {
	root := t.TempDir()
	bom := string(rune(0xFEFF))
	writeFixture(t, root, ".gitignore", bom+"# comment\n.env\n*.log\nbuild/\n/config/local.yml\ndocs/**/draft.txt\n!keep.log\n")
	rules := loadRootGitignore(root)
	for _, tc := range []struct {
		rel     string
		dir     bool
		ignored bool
	}{
		{".env", false, true},
		{"apps/web/.env", false, true},
		{".env.production", false, false},
		{"debug.log", false, true},
		{"logs/keep.log", false, false},
		{"build", true, true},
		{"build", false, false},
		{"config/local.yml", false, true},
		{"apps/config/local.yml", false, false},
		{"docs/a/b/draft.txt", false, true},
		{"src/app.js", false, false},
	} {
		if got := rules.match(tc.rel, tc.dir); got != tc.ignored {
			t.Errorf("match(%q, dir=%v) = %v, want %v", tc.rel, tc.dir, got, tc.ignored)
		}
	}
}
