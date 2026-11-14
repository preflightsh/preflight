package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const mitText = "MIT License\n\nPermission is hereby granted, free of charge, to any person\n"

func licenseResult(t *testing.T, root string) CheckResult {
	t.Helper()
	r, err := (LicenseCheck{}).Run(regressionContext(root))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestLicenseFileNames: the conventional names beyond LICENSE and
// LICENSE.md, in any letter case. COPYING.LESSER reported "No LICENSE file
// found".
func TestLicenseFileNames(t *testing.T) {
	for _, name := range []string{"LICENSE", "License.md", "licence.txt", "LICENSE.rst", "LICENSE-MIT", "COPYING", "COPYING.LESSER", "UNLICENSE", "Unlicense.txt"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, name, mitText)
			if r := licenseResult(t, root); !r.Passed {
				t.Fatalf("%s not recognized: %+v", name, r)
			}
		})
	}
	for _, name := range []string{"LICENSES.md", "licensing-notes.txt", "copyingfiles.txt", "src/LICENSE"} {
		t.Run("not a license: "+name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, root, name, mitText)
			if r := licenseResult(t, root); r.Passed {
				t.Fatalf("%s counted as the project license: %+v", name, r)
			}
		})
	}
	t.Run("empty file", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, "LICENSE", "  \n")
		if r := licenseResult(t, root); r.Passed {
			t.Fatalf("empty LICENSE passed: %+v", r)
		}
	})
	t.Run("lesser gpl", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, "COPYING.LESSER", "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3\n")
		if r := licenseResult(t, root); !r.Passed || !strings.Contains(r.Message, "LGPL") {
			t.Fatalf("result=%+v", r)
		}
	})
}

// TestLicenseStaysInsideTheRepository: a project that is its own repository
// passed on the LICENSE of an unrelated parent directory ("MIT license found
// (at ../LICENSE)"), reading a file outside the project to do it.
func TestLicenseStaysInsideTheRepository(t *testing.T) {
	mkdir := func(t *testing.T, path string) {
		t.Helper()
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("own repository under a parent with a license", func(t *testing.T) {
		parent := t.TempDir()
		writeFixture(t, parent, "LICENSE", mitText)
		writeFixture(t, parent, "package.json", "{}\n")
		project := filepath.Join(parent, "project")
		mkdir(t, filepath.Join(project, ".git"))
		if r := licenseResult(t, project); r.Passed {
			t.Fatalf("passed on the parent's LICENSE: %+v", r)
		}
	})
	t.Run("no repository anywhere", func(t *testing.T) {
		parent := t.TempDir()
		writeFixture(t, parent, "LICENSE", mitText)
		writeFixture(t, parent, "package.json", "{}\n")
		project := filepath.Join(parent, "project")
		mkdir(t, project)
		if r := licenseResult(t, project); r.Passed {
			t.Fatalf("passed on a parent outside any repository: %+v", r)
		}
	})
	t.Run("app inside a monorepo", func(t *testing.T) {
		repo := t.TempDir()
		mkdir(t, filepath.Join(repo, ".git"))
		writeFixture(t, repo, "LICENSE", mitText)
		app := filepath.Join(repo, "apps", "web")
		mkdir(t, app)
		r := licenseResult(t, app)
		if !r.Passed || !strings.Contains(filepath.ToSlash(r.Message), "(at ../../LICENSE)") {
			t.Fatalf("repository root LICENSE not found: %+v", r)
		}
	})
	t.Run("stops at the repository root", func(t *testing.T) {
		outer := t.TempDir()
		writeFixture(t, outer, "LICENSE", mitText)
		repo := filepath.Join(outer, "repo")
		mkdir(t, filepath.Join(repo, ".git"))
		app := filepath.Join(repo, "apps", "web")
		mkdir(t, app)
		if r := licenseResult(t, app); r.Passed {
			t.Fatalf("walked past the repository root: %+v", r)
		}
	})
}

// bigImage writes an image-named file over the 500KB threshold.
func bigImage(t *testing.T, root, rel string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(full)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(600 * 1024); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func largeImagePaths(root string) []string {
	var paths []string
	for _, img := range findLargeImages(root, 500*1024) {
		paths = append(paths, filepath.ToSlash(img.path))
	}
	return paths
}

// TestImageOptimizationScope: the same image was listed once per copy
// (public/hero.png and dist/hero.png), and CMS uploads and git-ignored
// output were counted as the project's own images.
func TestImageOptimizationScope(t *testing.T) {
	t.Run("build output beside a source root", func(t *testing.T) {
		root := t.TempDir()
		for _, p := range []string{"public/hero.png", "dist/hero.png", "build/hero.png", "out/hero.png", "_site/hero.png"} {
			bigImage(t, root, p)
		}
		if got := largeImagePaths(root); len(got) != 1 || got[0] != "public/hero.png" {
			t.Fatalf("images=%v", got)
		}
	})
	t.Run("build output is all there is", func(t *testing.T) {
		root := t.TempDir()
		bigImage(t, root, "dist/hero.png")
		if got := largeImagePaths(root); len(got) != 1 || got[0] != "dist/hero.png" {
			t.Fatalf("images=%v", got)
		}
	})
	t.Run("cms uploads", func(t *testing.T) {
		root := t.TempDir()
		for _, p := range []string{
			"web/sites/default/files/upload.jpg",
			"web/wp-content/uploads/2026/photo.jpg",
			"public/storage/avatar.png",
			"web/cpresources/abc/thumb.png",
			"web/themes/custom/site/images/banner.jpg",
			"web/files/brochure-cover.png",
		} {
			bigImage(t, root, p)
		}
		got := strings.Join(largeImagePaths(root), " ")
		if got != "web/files/brochure-cover.png web/themes/custom/site/images/banner.jpg" {
			t.Fatalf("images=%q", got)
		}
	})
	t.Run("git-ignored files and directories", func(t *testing.T) {
		root := t.TempDir()
		initGitRepo(t, root)
		writeFixture(t, root, ".gitignore", "public/build/\npublic/cache-*.png\n")
		bigImage(t, root, "public/hero.png")
		gitCommit(t, root, ".gitignore", "public/hero.png")
		bigImage(t, root, "public/build/hero.abc123.png")
		bigImage(t, root, "public/cache-1.png")
		bigImage(t, root, "public/new.png")
		got := strings.Join(largeImagePaths(root), " ")
		if got != "public/hero.png public/new.png" {
			t.Fatalf("images=%q", got)
		}
	})
}
