package checks

import (
	"context"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestDebugScanIsLinear: the dev-guard state used to be rebuilt from line 0
// for every match, so a file of N debug statements cost N*N line replays
// (13,000 console.log lines took 103 seconds). One scanner per file makes it
// linear; the budget here is generous for a slow CI runner and still far
// below what the quadratic version needed for this file.
func TestDebugScanIsLinear(t *testing.T) {
	root := t.TempDir()
	var b strings.Builder
	for i := 0; i < 12000; i++ {
		b.WriteString("  console.log('line', i)\n")
	}
	writeFixture(t, root, "src/big.js", b.String())

	start := time.Now()
	got := scanForDebugStatements(root, nil)
	elapsed := time.Since(start)
	if len(got) != 12000 {
		t.Fatalf("findings = %d, want 12000", len(got))
	}
	if elapsed > 15*time.Second {
		t.Fatalf("scan took %s, want well under 15s", elapsed)
	}
}

// TestDebugScanHonorsCancellation: a cancelled scan context stops the walk.
func TestDebugScanHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "src/a.js", "console.log(1)\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := scanForDebugStatementsCtx(ctx, root, nil); len(got) != 0 {
		t.Fatalf("findings after cancel = %v, want none", got)
	}
}

// TestDebugGuardStateMatchesReplay: the per-file scanner must give the same
// answers as replaying the file for each statement did.
func TestDebugGuardStateMatchesReplay(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "src/a.js", strings.Join([]string{
		"if (process.env.NODE_ENV === 'development') {",
		"  console.log('guarded'); console.log('guarded too')",
		"}",
		"console.log('bare')",
		"if (isDev) console.log('inline')",
		"function f() {",
		"  if (import.meta.env.DEV) {",
		"    console.debug('nested')",
		"  } else {",
		"    console.log('else branch')",
		"  }",
		"}",
		"",
	}, "\n"))
	got := scanForDebugStatements(root, nil)
	want := []string{"src/a.js:10 - console.log", "src/a.js:4 - console.log"}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
}

// TestDebugStatementsNotFlagged covers code that is not a debug statement
// left in shipped code.
func TestDebugStatementsNotFlagged(t *testing.T) {
	root := t.TempDir()
	// Drupal style writes the constant in capitals.
	writeFixture(t, root, "src/dump.php", "<?php\n$s = print_r($data, TRUE);\n$t = print_r($data, True);\n")
	// pp as an identifier, not Kernel#pp.
	writeFixture(t, root, "app/models/point.rb", "pp = Struct.new(:a)\nq = pp   .new(1)\nrender(pp: true)\n")
	// A trailing hash comment naming a debug call.
	writeFixture(t, root, "app/models/note.rb", "x = 1 # pp x while debugging\n")
	// Build and maintenance scripts log to the terminal by design.
	writeFixture(t, root, "scripts/seed.js", "console.log('seeding')\n")
	writeFixture(t, root, "bin/release.js", "console.log('releasing')\n")
	// Tests.
	writeFixture(t, root, "tests/unit/a.js", "console.log('t')\n")
	writeFixture(t, root, "src/__tests__/a.js", "console.log('t')\n")
	writeFixture(t, root, "spec/models/user_spec.rb", "binding.pry\n")
	writeFixture(t, root, "app/models/user_spec.rb", "binding.pry\n")
	// CMS core and third-party plugins.
	writeFixture(t, root, "wp-admin/js/common.js", "console.log('core')\n")
	writeFixture(t, root, "wp-includes/js/api.js", "console.log('core')\n")
	writeFixture(t, root, "wp-content/plugins/akismet/a.php", "<?php\nvar_dump($x);\n")
	writeFixture(t, root, "web/core/misc/drupal.js", "console.log('core')\n")
	writeFixture(t, root, "web/modules/contrib/devel/devel.module", "<?php\ndpm($x);\n")

	if got := scanForDebugStatements(root, nil); len(got) != 0 {
		t.Fatalf("findings = %v, want none", got)
	}
}

// TestDebugStatementsFound covers statements the scan used to miss.
func TestDebugStatementsFound(t *testing.T) {
	root := t.TempDir()
	// A TypeScript generic or a JSX component is not an HTML <pre>/<code> block.
	writeFixture(t, root, "src/prefs.ts", "const cache: Array<Preference> = []\n\n\nconsole.log(cache)\n")
	writeFixture(t, root, "src/card.tsx", "export const C = () => <PreviewCard>\n  {console.log('x')}\n</PreviewCard>\n")
	writeFixture(t, root, "src/block.tsx", "export const D = () => <CodeBlock lang=\"js\" />\nconsole.log('y')\n")
	// Route and source directories that share a name with an output directory.
	writeFixture(t, root, "app/logs/page.tsx", "console.log('route')\n")
	writeFixture(t, root, "assets/js/app.js", "console.log('phoenix')\n")
	writeFixture(t, root, "app/assets/javascripts/site.js", "console.log('sprockets')\n")
	writeFixture(t, root, "src/scripts/menu.js", "console.log('shipped')\n")
	// Drupal.
	writeFixture(t, root, "web/modules/custom/shop/shop.module", "<?php\ndpm($order);\nkint($order);\nvar_dump($x);\n")
	// Elixir.
	writeFixture(t, root, "lib/app/worker.ex", "x |> IO.inspect\ny |> IO.inspect(label: \"y\")\ndbg(z)\nw |> dbg()\n")
	// A key named example, usage, demo, or sample does not excuse the call.
	writeFixture(t, root, "src/doc.js", "const o = { example: console.log(1) }\n")
	// A PHP heredoc closes with its marker and a semicolon.
	writeFixture(t, root, "src/tpl.php", "<?php\n$s = <<<EOT\ntext\nEOT;\nvar_dump($s);\n")
	// A shift by a constant is not a heredoc.
	writeFixture(t, root, "src/bits.js", "const mask = 1 << FLAG_BITS\nconsole.log(mask)\n")

	got := scanForDebugStatements(root, nil)
	want := []string{
		"app/assets/javascripts/site.js:1 - console.log",
		"app/logs/page.tsx:1 - console.log",
		"assets/js/app.js:1 - console.log",
		"lib/app/worker.ex:1 - IO.inspect()",
		"lib/app/worker.ex:2 - IO.inspect()",
		"lib/app/worker.ex:3 - dbg()",
		"lib/app/worker.ex:4 - dbg()",
		"src/bits.js:2 - console.log",
		"src/block.tsx:2 - console.log",
		"src/card.tsx:2 - console.log",
		"src/doc.js:1 - console.log",
		"src/prefs.ts:4 - console.log",
		"src/scripts/menu.js:1 - console.log",
		"src/tpl.php:5 - var_dump()",
		"web/modules/custom/shop/shop.module:2 - dpm()",
		"web/modules/custom/shop/shop.module:3 - kint()",
		"web/modules/custom/shop/shop.module:4 - var_dump()",
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("findings:\n got %s\nwant %s", strings.Join(got, "\n     "), strings.Join(want, "\n     "))
	}
}

// TestDebugStatementsOutputDirs: public, static, storage, log, tmp, and out
// hold build output and runtime data. Without git they are skipped at the
// project root; inside a repository only what git tracks there is source.
func TestDebugStatementsOutputDirs(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "public/js/main.js", "console.log('hand written')\n")
	writeFixture(t, root, "public/build/app.js", "console.log('compiled')\n")
	writeFixture(t, root, "storage/framework/views/a.php", "<?php\nvar_dump($x);\n")
	writeFixture(t, root, "log/dev.js", "console.log('data')\n")

	if got := scanForDebugStatements(root, nil); len(got) != 0 {
		t.Fatalf("outside git: findings = %v, want none", got)
	}

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@example.invalid"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	writeFixture(t, root, ".gitignore", "public/build/\nstorage/\nlog/\n")
	git("add", "-A")
	git("commit", "-qm", "init")

	got := scanForDebugStatements(root, nil)
	if want := []string{"public/js/main.js:1 - console.log"}; !slices.Equal(got, want) {
		t.Fatalf("inside git: findings = %v, want %v", got, want)
	}

	// A committed bundle is still not source.
	writeFixture(t, root, filepath.Join("public", "js", "bundle.js"), "!function(){console.log(1)}();"+strings.Repeat("var a=1;", 400)+"\n")
	git("add", "-A")
	git("commit", "-qm", "bundle")
	got = scanForDebugStatements(root, nil)
	if want := []string{"public/js/main.js:1 - console.log"}; !slices.Equal(got, want) {
		t.Fatalf("with a committed bundle: findings = %v, want %v", got, want)
	}
}
