package checks

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

// A byte order mark on the first line was read as part of the first key, so
// APP_KEY was reported missing from both files at once.
func TestEnvParityIgnoresBOM(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, ".env", "\uFEFFAPP_KEY=1\r\nDB_URL=2\r\n")
	writeFixture(t, root, ".env.example", "APP_KEY=\nDB_URL=\n")
	if res, _ := (EnvParityCheck{}).Run(envParityCtx(root)); !res.Passed {
		t.Fatalf("msg=%q", res.Message)
	}
}

// The last line of a quoted multi-line value (a PEM key) ends in "=" and was
// reported as a missing variable, which put key material into Message and
// from there onto the dashboard.
func TestEnvParityMultilineValuesAreNotKeys(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, ".env", strings.Join([]string{
		`APP_KEY=base64:abc=`,
		`JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----`,
		`MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7`,
		`FAKElastlineOFtheKEYmaterial0123456789==`,
		`-----END PRIVATE KEY-----"`,
		`SINGLE='line one`,
		`OTHER_LOOKING=value`,
		`line three'`,
		`ESCAPED="a \" still open`,
		`NOT_A_KEY=1"`,
		`AFTER=1`,
		`some prose = not a variable`,
		`1BAD=1`,
	}, "\n")+"\n")
	writeFixture(t, root, ".env.example", "APP_KEY=\n")
	res, _ := (EnvParityCheck{}).Run(envParityCtx(root))
	want := "Missing in .env.example: AFTER, ESCAPED, JWT_PRIVATE_KEY, SINGLE"
	if res.Message != want {
		t.Fatalf("msg=%q\nwant %q", res.Message, want)
	}
	for _, s := range append(res.Suggestions, res.Message) {
		if strings.Contains(s, "FAKElastline") || strings.Contains(s, "MIIEv") {
			t.Errorf("key material in output: %q", s)
		}
	}
}

// "# SENTRY_DSN=" in the example documents an optional variable. Setting it
// in .env is not undocumented, and leaving it out is not a miss.
func TestEnvParityCommentedExampleKeysAreDocumented(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, ".env.example", "APP_KEY=\n# Optional, set to enable error tracking: see docs\n# SENTRY_DSN=\n#MAIL_HOST=smtp.example.com\n")
	writeFixture(t, root, ".env", "APP_KEY=1\nSENTRY_DSN=https://x\n")
	if res, _ := (EnvParityCheck{}).Run(envParityCtx(root)); !res.Passed {
		t.Fatalf("msg=%q", res.Message)
	}
	// A variable commented out in .env is still unset there.
	writeFixture(t, root, ".env", "# APP_KEY=1\n")
	if res, _ := (EnvParityCheck{}).Run(envParityCtx(root)); res.Passed || res.Message != "Missing in .env: APP_KEY" {
		t.Fatalf("commented in .env: passed=%v msg=%q", res.Passed, res.Message)
	}
}

// envFile and exampleFile come from the scanned repo's preflight.yml. A path
// that leaves the project used to be read, and the variable names in the
// file it pointed at ended up in Message.
func TestEnvParityFilesStayInsideTheProject(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "project")
	writeFixture(t, root, ".env.example", "APP_KEY=\n")
	writeFixture(t, root, ".env", "APP_KEY=1\n")
	writeFixture(t, base, "outside-secret.cfg", "SECRET_KEY=hunter2\n")
	writeFixture(t, base, "elsewhere/.env", "OTHER_PROJECT_TOKEN=1\n")

	cases := map[string]config.EnvParityConfig{
		"dot dot env file":     {EnvFile: "../outside-secret.cfg", ExampleFile: ".env.example"},
		"dot dot example file": {EnvFile: ".env", ExampleFile: "../outside-secret.cfg"},
		"absolute env file":    {EnvFile: filepath.Join(base, "outside-secret.cfg"), ExampleFile: ".env.example"},
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(base, "elsewhere"), filepath.Join(root, "apps")); err != nil {
			t.Fatal(err)
		}
		cases["symlinked directory"] = config.EnvParityConfig{EnvFile: "apps/.env", ExampleFile: ".env.example"}
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			cfg.Enabled = true
			ctx := Context{RootDir: root, Config: &config.PreflightConfig{Checks: config.ChecksConfig{EnvParity: &cfg}}}
			res, _ := (EnvParityCheck{}).Run(ctx)
			if res.Passed || !res.Inconclusive {
				t.Errorf("result=%+v", res)
			}
			if strings.Contains(res.Message, "SECRET_KEY") || strings.Contains(res.Message, "OTHER_PROJECT_TOKEN") {
				t.Errorf("a name from outside the project reached Message: %q", res.Message)
			}
		})
	}

	// A file in a subdirectory of the project is still fine.
	writeFixture(t, root, "config/.env", "APP_KEY=1\n")
	ctx := Context{RootDir: root, Config: &config.PreflightConfig{Checks: config.ChecksConfig{
		EnvParity: &config.EnvParityConfig{Enabled: true, EnvFile: "config/.env", ExampleFile: ".env.example"},
	}}}
	if res, _ := (EnvParityCheck{}).Run(ctx); !res.Passed {
		t.Errorf("subdirectory env file: %+v", res)
	}
	if data, err := readProjectFile(root, "config/.env"); err != nil || string(data) != "APP_KEY=1\n" {
		t.Errorf("readProjectFile inside the project: %q, %v", data, err)
	}
	if _, err := readProjectFile(root, "../outside-secret.cfg"); err == nil {
		t.Error("readProjectFile read a file outside the project")
	}
}
