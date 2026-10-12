//go:build unix

package checks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditCancellationKillsDescendantGroup(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "Cargo.lock", "fixture")
	bin := t.TempDir()
	writeFixture(t, bin, "cargo", "#!/bin/sh\nsleep 20 &\nwait\n")
	if err := os.Chmod(filepath.Join(bin, "cargo"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx := regressionContext(root)
	cancelCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx.Ctx = cancelCtx
	start := time.Now()
	r, _ := VulnerabilityCheck{}.Run(ctx)
	if time.Since(start) > 3*time.Second {
		t.Fatal("descendant retained output pipes after cancellation")
	}
	if r.Passed || !r.Inconclusive {
		t.Fatalf("result=%+v", r)
	}
}
