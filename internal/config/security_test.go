package config

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValueValidation(t *testing.T) {
	cases := []struct {
		name, body string
		bad        bool
	}{
		{"unknown service", "services:\n  sentyr:\n    declared: true\n", true},
		{"unknown ignore", "ignore: [security_headerz]\n", true},
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
