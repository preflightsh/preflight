---
name: preflight
description: This skill should be used when the user asks to "run Preflight", "scan launch readiness", "check production readiness", "audit before deploy", "fix preflight findings", "set up preflight.yml", "wire Preflight into CI", or mentions the Preflight.sh CLI.
version: 0.1.0
---

# Preflight Launch Readiness

Use Preflight to scan a project for launch readiness issues before deploy. Treat the CLI output as a triage map for concrete engineering work: configuration gaps, service integration problems, security issues, SEO metadata, web standard files, secrets, and CI readiness.

## Core Workflow

1. Inspect the project before running commands.
   - Locate the project root and check for `preflight.yml`.
   - Skim the stack, deployment shape, env files, public web root, and CI config when relevant.
   - Preserve existing behavior and do not create or edit config until the user has approved changes.

2. Ensure the Preflight CLI is available.
   - Prefer an existing `preflight` binary on `PATH`.
   - Otherwise install it with the repo-documented Homebrew, npm, Go, Docker, or shell installer path.
   - Use `--ci` for agent runs so scans avoid interactive update checks.

3. Initialize config only when needed.
   - If `preflight.yml` is missing, explain that `preflight init` writes project config and may ask about production URLs and services.
   - Ask before running interactive initialization or writing a starter config.
   - Treat `preflight.yml` as potentially sensitive because it can contain staging and production URLs.

4. Run a parseable scan.
   - Prefer JSON for agent analysis:

     ```bash
     preflight scan --ci --format json --verbose
     ```

   - Use human output when the user wants terminal-readable results:

     ```bash
     preflight scan --ci --format human --verbose
     ```

   - Interpret exit codes directly: `0` means all checks passed, `1` means warnings only, and `2` means errors or command/config failure.

5. Triage findings into fixes.
   - Address errors before warnings.
   - For each failed check, inspect the source files or external URL behavior before editing.
   - Fix root causes rather than silencing checks.
   - Use `preflight ignore <id>` only for an intentional false positive or a check the project explicitly does not need.
   - For secrets findings, prefer a path plus `fingerprint: "sha256:<hex>"` allowlist entry over disabling the entire secrets check.

6. Rerun the same scan after changes.
   - Compare the new result against the original findings.
   - Call out any remaining warnings, skipped checks, network-dependent checks, or config assumptions.
   - Do not claim launch readiness when required checks are disabled, unconfigured, or unverifiable.

## Common Commands

Use these commands as the default command vocabulary:

```bash
preflight init
preflight scan --ci --format json
preflight scan --ci --format json --verbose
preflight scan --ci --format human --verbose
preflight ignore <check-or-service-id>
preflight unignore <check-or-service-id>
preflight checks
```

## CI Pattern

Recommend this GitHub Actions pattern when asked to wire Preflight into CI:

```yaml
- name: Run Preflight
  run: |
    curl -sSL https://preflight.sh/install.sh | sh
    preflight scan --ci --format json
```

For container-first projects, recommend:

```yaml
- name: Run Preflight
  run: docker run -v ${{ github.workspace }}:/app ghcr.io/preflightsh/preflight scan --ci --format json
```

## Reporting Standard

Finish with a concise report that includes:

- The exact command run and exit code.
- The failing check IDs, grouped by error and warning.
- The files, URLs, or config entries changed.
- The checks rerun and whether they now pass.
- Any residual launch risk or validation that could not be performed.

Keep the report factual. Passing a partial scan is not equivalent to a production-ready launch.
