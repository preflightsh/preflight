package checks

import (
	"testing"

	"github.com/preflightsh/preflight/internal/config"
)

func envParityCtx(root string) Context {
	return Context{RootDir: root, Config: &config.PreflightConfig{Checks: config.ChecksConfig{
		EnvParity: &config.EnvParityConfig{Enabled: true, EnvFile: ".env", ExampleFile: ".env.example"},
	}}}
}

// TestEnvParityExportPrefix: `export KEY=` names KEY. It used to be read as
// the key "export KEY", reported missing from an example listing KEY.
func TestEnvParityExportPrefix(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, ".env", "export API_KEY=1\nexport DB_URL=2\n")
	writeFixture(t, root, ".env.example", "API_KEY=\nDB_URL=\n")
	if res, _ := (EnvParityCheck{}).Run(envParityCtx(root)); !res.Passed {
		t.Fatalf("msg=%q", res.Message)
	}
}

// TestEnvParityMessageIsStable: the missing keys were listed in map order,
// so the message changed between identical runs.
func TestEnvParityMessageIsStable(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, ".env", "ZED=1\nALPHA=1\nMIKE=1\nBRAVO=1\n")
	writeFixture(t, root, ".env.example", "\n")
	want := "Missing in .env.example: ALPHA, BRAVO, MIKE, ZED"
	for i := 0; i < 10; i++ {
		if res, _ := (EnvParityCheck{}).Run(envParityCtx(root)); res.Message != want {
			t.Fatalf("run %d: msg=%q, want %q", i, res.Message, want)
		}
	}
}
