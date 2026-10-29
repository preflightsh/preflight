package config

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValueValidation(t *testing.T) {
	cases := []struct {
		name, body string
		bad        bool
	}{
		{"unknown declared service", "services:\n  sentyr:\n    declared: true\n", true},
		{"unknown undeclared service", "services:\n  newthing:\n    declared: false\n", false},
		{"unknown ignore", "ignore: [security_headerz]\n", false},
		{"invalid glob", "ignore: ['web/[x']\n", true},
		{"pre-1.0 ID", "ignore: [seoMeta]\n", true},
		{"service ID", "ignore: [indexnow]\n", false},
		{"source glob", "ignore: ['web/**/*.js']\n", false},
		{"missing mail domain", "checks:\n  emailAuth:\n    enabled: true\n", false},
		{"malformed mail domain", "checks:\n  emailAuth:\n    enabled: true\n    domain: -mail.example.com\n", true},
		{"mail URL", "checks:\n  emailAuth:\n    enabled: true\n    domain: https://example.com\n", true},
		{"independent mail domain", "checks:\n  emailAuth:\n    enabled: true\n    domain: MAIL.example.com.\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, tc.body))
			if (err != nil) != tc.bad {
				t.Fatalf("err=%v", err)
			}
			if cfg != nil && cfg.Checks.EmailAuth != nil && cfg.Checks.EmailAuth.Enabled && cfg.Checks.EmailAuth.Domain != "" && cfg.Checks.EmailAuth.Domain != "mail.example.com" {
				t.Fatalf("domain=%q", cfg.Checks.EmailAuth.Domain)
			}
		})
	}
}

// init v0.2.1 through v0.3.0 wrote the xAI service as groq; it was renamed
// grok later, and v0.23 loaded the old name. It is read as grok with a note.
func TestGroqServiceIsReadAsGrok(t *testing.T) {
	cfg, err := Load(writeConfig(t, "services:\n  groq:\n    declared: true\n"))
	if err != nil {
		t.Fatalf("groq rejected: %v", err)
	}
	if !cfg.Services["grok"].Declared {
		t.Errorf("groq: declared true did not carry over to grok: %+v", cfg.Services)
	}
	if _, ok := cfg.Services["groq"]; ok {
		t.Error("groq should be replaced by grok")
	}
	if len(cfg.Notes) != 1 || !strings.Contains(cfg.Notes[0], `"grok"`) {
		t.Errorf("want one note naming grok, got %q", cfg.Notes)
	}

	cfg, err = Load(writeConfig(t, "services:\n  groq:\n    declared: false\n  grok:\n    declared: true\n"))
	if err != nil || !cfg.Services["grok"].Declared {
		t.Fatalf("groq and grok both present: err=%v services=%+v", err, cfg.Services)
	}
}

// v0.23 accepted any ignore entry. A bare word that is not a check ID is a
// file pattern to the source scans, which matches only a file of that name
// at the project root, so it warns instead of failing the load.
func TestBareIgnoreEntryWarns(t *testing.T) {
	cfg, err := Load(writeConfig(t, "ignore: [vendor, security_headerz]\n"))
	if err != nil {
		t.Fatalf("bare ignore entry rejected: %v", err)
	}
	if len(cfg.Notes) != 2 {
		t.Fatalf("want a note per entry, got %q", cfg.Notes)
	}
	if !strings.Contains(cfg.Notes[0], `"vendor/**"`) {
		t.Errorf("want the directory form suggested, got %q", cfg.Notes[0])
	}
	if !strings.Contains(cfg.Notes[1], `"security_headers"`) {
		t.Errorf("want the near check ID suggested, got %q", cfg.Notes[1])
	}
	if len(cfg.Ignore) != 2 {
		t.Errorf("entries must be kept for the source scans, got %q", cfg.Ignore)
	}
}

// A service ID Preflight does not know is a note when it is not declared
// (a newer init lists every service it knows) and an error when it is,
// since a misspelled declaration silently skips the check the user wanted.
func TestUnknownServiceIDs(t *testing.T) {
	cfg, err := Load(writeConfig(t, "services:\n  newthing:\n    declared: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Notes) != 1 || !strings.Contains(cfg.Notes[0], "newthing") {
		t.Errorf("want a note naming newthing, got %q", cfg.Notes)
	}
	_, err = Load(writeConfig(t, "services:\n  sentyr:\n    declared: true\n"))
	if err == nil || !strings.Contains(err.Error(), "sentyr") || !strings.Contains(err.Error(), "newer") {
		t.Errorf("want an error naming sentyr with the upgrade hint, got %v", err)
	}
}

func FuzzConfig(f *testing.F) {
	for _, seed := range []string{"projectName: demo\n", "ignore: [seoMeta]\n", "checks:\n  secrets:\n    allowlist: [{path: '**'}]\n"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		var cfg PreflightConfig
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
			return
		}
		applyDefaults(&cfg)
		_ = Validate(&cfg)
	})
}
