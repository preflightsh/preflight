# Preflight.sh

[![Agent skill on skills.sh](https://skills.sh/b/preflightsh/preflight)](https://skills.sh/preflightsh/preflight)

[Preflight.sh](https://preflight.sh/) is a command-line tool that scans your codebase for launch readiness. Identifies missing configuration, integration issues, security concerns, SEO metadata gaps, and other common mistakes before you deploy to production.

Don't embarrass yourself in production. Just run the command.

## Installation

### Homebrew (macOS/Linux)

```bash
brew install preflightsh/preflight/preflight
```

### npm

```bash
npm install -g @preflightsh/preflight
```

### Go

```bash
go install github.com/preflightsh/preflight@latest
```

### Docker

```bash
docker pull ghcr.io/preflightsh/preflight
```

### Shell Script

```bash
curl -sSL https://preflight.sh/install.sh | sh
```

### Manual Download

Download the latest release from [GitHub Releases](https://github.com/preflightsh/preflight/releases).

From v0.23.0 each archive carries signed build provenance. To check that a download was built by this repo's release workflow:

```bash
gh attestation verify preflight_<version>_<os>_<arch>.tar.gz --repo preflightsh/preflight
```

## Quick Start

```bash
# Initialize in your project directory
cd your-project
preflight init
# (asks before replacing an existing preflight.yml; --force skips the question)

# Run all checks
preflight scan

# Scan a specific directory
preflight scan /path/to/project

# Run with verbose output (shows which files matched each check)
preflight scan --verbose
preflight scan -v  # short form

# Run in CI mode with JSON output
preflight scan --ci --format json

# Run only specific checks, or skip some, for fast iteration
# (one-off; unlike `preflight ignore` it doesn't change preflight.yml)
preflight scan --only seo_meta,og_twitter
preflight scan --skip vulnerability,secrets

# Silence a check
preflight ignore sitemap

# Unsilence a check
preflight unignore sitemap

# List all check IDs
preflight checks
```

## Agent Skill

This repo includes a skills.sh-compatible agent skill at [`skills/preflight/SKILL.md`](skills/preflight/SKILL.md). It gives coding agents a repeatable Preflight workflow: inspect `preflight.yml`, run CI-safe scans, triage findings, avoid unsafe ignores, rerun validation, and report residual launch risk.

List the skill from this repository:

```bash
# With Bun
bunx --yes skills add preflightsh/preflight --list

# Or with npm
npx --yes skills add preflightsh/preflight --list
```

Install only the Preflight skill:

```bash
# With Bun
bunx --yes skills add preflightsh/preflight --skill preflight

# Or with npm
npx --yes skills add preflightsh/preflight --skill preflight
```

## Dashboard & AI Suggestions

Preflight is fully usable from the command line with no account. The optional dashboard at [app.preflight.sh](https://app.preflight.sh) adds a hosted history of your scans and AI-generated fix suggestions for each finding. Your code never leaves your machine: scanning runs locally, and nothing is sent unless you publish. Dashboard bearer tokens are restricted to the origin that issued them, and authenticated redirects cannot cross origins or downgrade HTTPS.

### What publishing sends

- Each check's ID, title, status (passed, skipped, inconclusive, severity), and the summary counts.
- The real message for checks whose messages are built from fixed text, counts, repo-relative paths, DNS names, or public page content: the SEO and social checks, `security_headers`, `ssl`, `www_redirect`, `email_auth`, `debug_statements`, `error_pages`, `image_optimization`, `legal_pages`, and the web standard file checks. `debug_statements` and `image_optimization` include up to five findings (file and line, or file and size).
- Before sending, those messages are scrubbed: the configured staging and production URLs are cut to their origins, and the IndexNow key, the Stripe webhook URL, the `seoMeta` layout path, and the env file names are removed, as are URL credentials, query strings, and fragments.
- A generic message for everything else: `secrets`, `vulnerability`, `env_parity`, `health_endpoint`, `stripe_webhook`, `index_now`, every service check, and any "Check failed:" error.
- A redacted `preflight.yml`: project name, stack, URL origins, service declarations, and which checks are enabled. The IndexNow key, Stripe webhook URL, secrets allowlist, env file names, health path, layout path, and ignore list are dropped.

Suggestions, file contents, audit tool output, and secret values are never sent.

Create a free account, then connect the CLI:

```bash
preflight auth login    # opens your browser to authorize this CLI
preflight auth status   # show who you're logged in as
preflight auth logout   # remove stored credentials
```

Publish a scan to your dashboard with `--publish`. It prints a link to view the run. Publishing is best-effort: if you're offline or not logged in, the scan still runs and exits normally.

```bash
preflight scan --publish
```

On the dashboard you get each run's pass/warn/fail breakdown, the list of check outcomes, and a per-project history so you can see what changed between deploys.

You can also read that history from the terminal with `preflight history`:

```bash
preflight history                       # recent runs across your projects
preflight history --here                # only the current project's runs
preflight history <run-id>              # one run's full check results
preflight history --here --format json  # machine-readable, for agents
```

Requires `preflight auth login`. `--here` matches runs to the current repository by its git remote, the same key used when publishing. An app scanned from a subdirectory of its repository (one app in a monorepo) is keyed by that subdirectory too, so `apps/web` and `apps/api` publish to separate dashboard projects. `history --format json` carries the same `schema_version` and `cli_version` fields as scan JSON.

On CI or another machine without a browser, log in with a token instead: `preflight auth login --token -` reads it from stdin, or set `PREFLIGHT_TOKEN` and run `preflight auth login`. Either way the token is checked and stored like a browser login; later commands read the stored credentials, not the variable.

Open any failed or warning check on a published run to generate a step-by-step fix tailored to your detected stack, with copy-ready commands and code.

- **Free** includes 5 published runs per month.
- **Bring your own key:** add an OpenAI or Anthropic API key in your dashboard settings and publishing stays free and unlimited (you pay your provider directly).
- **Managed ($5/mo):** we cover the AI costs and runs are unlimited, no API key required.

## What It Checks

| Check | Description |
|-------|-------------|
| **ENV Parity** | Compares `.env` and `.env.example` for missing variables |
| **Health Endpoint** | Verifies site is reachable; tries `/health`, `/healthz`, `/api/health`, `/_health`, and `/status`, then falls back to root |
| **Vulnerability Scan** | Checks for dependency vulnerabilities with your package manager's audit tool (bundle-audit, npm audit, etc.) |
| **SEO Metadata** | Checks for title, description, and Open Graph tags |
| **OG & Twitter Cards** | Validates og:image, twitter:card and social sharing metadata |
| **Canonical URL** | Verifies canonical link tag is present |
| **Viewport** | Checks for proper viewport meta tag for mobile |
| **Lang Attribute** | Validates html lang attribute for accessibility |
| **Structured Data** | Checks for JSON-LD Schema.org markup |
| **Security Headers** | Validates HSTS, CSP, X-Content-Type-Options, and Referrer-Policy on both prod and staging; a weak CSP (such as `'unsafe-inline'` scripts) is a suggestion, not a failure |
| **SSL Certificate** | Checks SSL validity and warns before expiration; skipped for local URLs |
| **WWW Redirect** | Verifies www/non-www redirect to canonical URL |
| **Email Auth** | Checks SPF/DMARC records for the email sending domain, or the production URL's domain when none is set (opt-in) |
| **Secret Scanning** | Finds leaked API keys and credentials in code |
| **Debug Statements** | Detects console.log, var_dump, debugger left in code; statements behind a development guard (in code, or in Twig, ERB, Blade, Django, and Go templates, including same-line `&&` and ternaries) are not reported |
| **Error Pages** | Checks for custom 404/500 error pages |
| **Image Optimization** | Finds large images (>500KB) that hurt load times |
| **Legal Pages** | Checks for privacy policy and terms of service pages on the deployed site, falling back to the source when the host is blocked or down |
| **Favicon & Icons** | Checks for favicon, apple-touch-icon (.png, .webp, .svg), and web manifest, including icons declared in layout `<link>` tags and the Next.js `icons` metadata; a missing favicon is a warning |
| **robots.txt** | Verifies robots.txt exists and has content |
| **sitemap.xml** | Checks for a sitemap file or generator, including Next.js Pages Router, Astro, and SvelteKit endpoints |
| **llms.txt** | Checks for LLM crawler guidance file |
| **ads.txt** | Validates ads.txt for ad-supported sites (opt-in) |
| **humans.txt** | Checks for humans.txt to credit the team (opt-in) |
| **IndexNow** | Verifies the IndexNow key file; when the site is reachable, the deployed `/{key}.txt` decides (opt-in) |
| **LICENSE** | Checks for license file (opt-in, for open source projects) |

Cookie consent tools (CookieConsent, Cookiebot, OneTrust, and others) are checked as [services](#ignorable-service-ids), not as a check of their own.

## Supported Services (72)

Preflight auto-detects and validates configuration for these services:

**Payments**
- Stripe, PayPal, Braintree, Paddle, LemonSqueezy

**Error Tracking & Monitoring**
- Sentry, Bugsnag, Rollbar, Honeybadger, Datadog, New Relic, LogRocket

**Email & Newsletters**
- Postmark, SendGrid, Mailgun, AWS SES, Resend, Mailchimp, Kit, Beehiiv, AWeber, ActiveCampaign, Campaign Monitor, Drip, Klaviyo, Buttondown

**Analytics**
- Plausible, Fathom, Umami, Fullres Analytics, Datafa.st Analytics, Google Analytics, PostHog, Mixpanel, Amplitude, Segment, Hotjar

**Auth**
- Auth0, Clerk, WorkOS

**Chat**
- Intercom, Crisp

**Notifications**
- Slack, Discord, Twilio

**Infrastructure**
- Firebase, Supabase, Redis, Sidekiq, RabbitMQ, Elasticsearch, Convex

**Storage & CDN**
- AWS S3, Cloudinary, Cloudflare

**Search**
- Algolia

**SEO**
- IndexNow

**AI / LLMs**
- OpenAI, Anthropic Claude, Google AI (Gemini), Mistral, Cohere, Replicate, Hugging Face, Grok (X/Twitter), Perplexity, Together AI

## Configuration

Preflight uses a `preflight.yml` file in your project root:

```yaml
projectName: my-app
stack: rails  # rails, next, react, vite, laravel, etc.

urls:
  staging: "https://staging.example.com"
  production: "https://example.com"

services:
  stripe:
    declared: true
  sentry:
    declared: true

checks:
  envParity:
    enabled: true
    envFile: ".env"
    exampleFile: ".env.example"

  healthEndpoint:
    enabled: true
    path: "/health"  # optional; with enabled: true only this path is checked

  stripeWebhook:
    enabled: true
    url: "https://api.example.com/webhooks/stripe"  # optional - probed with a GET; a 404 or no response is reported

  seoMeta:
    enabled: true
    mainLayout: "app/views/layouts/application.html.erb"

  security:
    enabled: true

  secrets:
    enabled: true
    # Per-file allowlist for the secrets scan. Use this to suppress an
    # individual finding (e.g. a referrer-restricted public key) without
    # disabling the whole check.
    allowlist:
      - path: web/js/golden-hour.js
        fingerprint: "sha256:<hex>"   # recommended: pins to the exact secret
        reason: "HTTP-referrer-restricted Google Timezone key"
      - path: "web/tools/**/*.php"    # doublestar globs are supported

  indexNow:
    enabled: true
    key: "your32characterhexkeyhere00000"

  emailAuth:
    enabled: true  # opt-in; independent of website URLs
    domain: "mail.example.com"  # actual sending / envelope-from domain

  humansTxt:
    enabled: false  # opt-in, credits the team

  license:
    enabled: false  # opt-in, for open source projects

# Silence specific checks or services by ID
ignore:
  - sitemap
  - llms_txt
  - google_analytics
```

A block under `checks:` without an `enabled:` key keeps the check's default.
`healthEndpoint` runs whenever a URL is set and `seoMeta` runs when a layout
or URL is found, so a block that only sets `path` or `mainLayout` leaves them
on; only `enabled: false` turns them off. A `healthEndpoint` path with no
`enabled` key is probed first, then the common paths. One exception: the exact
block `healthEndpoint: {enabled: false, path: /health}`, which `preflight init`
used to write for CMS and static sites, keeps its pre-0.24 meaning (the check
still runs when a URL is set) and prints a note. `init` no longer writes it.

Without a URL, the network checks do not pass: `ssl`, `www_redirect`, and
`health_endpoint` are left out of the scan, and `security_headers` is reported
as skipped.

### Strict config loading

`preflight.yml` is read strictly. An unknown key is a usage error (exit 64)
that names it by its place in the file, such as
`unknown key "x" under checks: at line 12`, with a hint to check the spelling
or upgrade. Strictness cuts both ways: a newer Preflight may write keys an
older one rejects, so upgrade the CLI when a teammate's `init` adds a key
yours does not know.

A few legacy shapes still load, each with a note on stderr:

- A `groq` service is read as `grok`.
- A service ID this version does not know is dropped when it has
  `declared: false` (a newer `init` lists every service it knows). With
  `declared: true` it is still an error.
- A bare word in `ignore:` that is not a check or service ID (like `vendor`)
  matches only a file of that name at the project root. Use `vendor/**` to
  skip a directory.

## Ignoring Checks & Services

Silence specific checks or services using `preflight ignore <id>`:

```bash
preflight ignore sitemap        # Ignore sitemap check
preflight ignore sentry         # Ignore Sentry service validation
preflight unignore sitemap      # Re-enable sitemap check
preflight checks                # List all ignorable IDs
```

### Allowlisting a single secrets finding

Prefer allowlisting an individual finding over silencing the whole
`secrets` check. Add one-off exceptions from the command line:

```bash
preflight ignore secrets web/js/golden-hour.js
```

That appends a path entry under `checks.secrets.allowlist` in your
`preflight.yml`. The `path` field is a [doublestar](https://github.com/bmatcuk/doublestar)
glob (`**` matches across directories) resolved against the
project-relative file path.

**Pin the fingerprint.** A path-only allowlist silently accepts *any*
future secret dropped into that file. Edit the entry and add a
`fingerprint: "sha256:<hex>"`, the SHA-256 of the detected secret
value. Now if the key is rotated or a different secret shows up in the
same file, preflight re-alerts.

Findings are matched by **path + fingerprint**, not whole-file. An
allowlisted fingerprint in a file does not suppress other secrets on
other lines in the same file.

### Ignorable Check IDs

**SEO & Social:**
`seo_meta`, `canonical`, `structured_data`, `index_now` (opt-in), `og_twitter`, `viewport`, `lang`

**Security & Infrastructure:**
`security_headers`, `ssl`, `www_redirect`, `email_auth` (opt-in), `secrets`

**Environment & Health:**
`env_parity`, `health_endpoint`

**Code Quality & Performance:**
`vulnerability`, `debug_statements`, `error_pages`, `image_optimization`

**Legal & Compliance:**
`legal_pages`

**Web Standard Files:**
`favicon`, `robots_txt`, `sitemap`, `llms_txt`, `ads_txt` (opt-in), `humans_txt` (opt-in), `license` (opt-in)

### Check IDs renamed in 0.22

Every check ID is now snake_case. 0.22 accepted the old camelCase names
with a note on stderr; 0.25 rejects them. An old name in an `ignore:`
list, `--only`, or `--skip` is a usage error (exit 64). One error lists
every old ID it found, each with its new name and the fix:

```
Error: pre-1.0 check IDs are not accepted:
  unknown check ID "seoMeta" in ignore: renamed to "seo_meta" in v0.22.0; run 'preflight ignore seo_meta' to update the ignore list
  unknown check ID "ogTwitter" in --only: renamed to "og_twitter" in v0.22.0; use --only og_twitter
```

`preflight ignore <new-id>` rewrites an old entry in place and removes
duplicate spellings of the same ID. `preflight unignore` removes an entry
by either name. The keys under
`checks:` in `preflight.yml` (`healthEndpoint`, `seoMeta`, ...) are a
separate schema and did not change.

| Old | New |
|---|---|
| `seoMeta` | `seo_meta` |
| `ogTwitter` | `og_twitter` |
| `securityHeaders` | `security_headers` |
| `envParity` | `env_parity` |
| `healthEndpoint` | `health_endpoint` |
| `robotsTxt` | `robots_txt` |
| `llmsTxt` | `llms_txt` |
| `adsTxt` | `ads_txt` |
| `humansTxt` | `humans_txt` |
| `indexNow` | `index_now` |

### What a successful scan means

A pass means the check verified its stated requirement. Skipped checks are
reported separately and do not add to the passed count. Inconclusive checks
produce warnings and exit code 1 unless another check produces an error.
A scan containing only skipped checks also exits 1. Disabled checks are outside
the scan's scope; a partial scan cannot establish overall launch readiness.

JSON schema version **2** (since 0.24) adds `skipped` and `inconclusive` to
check outcomes and their summary counts. A skipped check has `passed: false`
and `severity: "info"`, and counts only toward `summary.skipped`. An
inconclusive check counts toward `summary.inconclusive` and also toward `warn`
(or `fail` for an error). Both fields are omitted when false or zero. Consumers
of schema 1 should update these semantics before consuming schema 2. Published
payloads and `history --format json` use the same version.

When a website URL is configured, metadata checks verify all requirements
against fetched HTML. Static templates cannot override missing deployed tags.
Dynamic `generateMetadata()` functions require rendered verification. Offline
source checks are heuristics; SDK references and local configuration do not
prove that production credentials or integrations work.

Secret scanning includes `.example` and `.sample` files and source/configuration
files up to 2 MB. Larger files are skipped; only a git-tracked source or config
file over the cap (not a data dump or a minified bundle) makes the scan
inconclusive, as does an unreadable file. In example files, a private key header
followed by placeholder text instead of key material is not reported. Public
telemetry identifiers such as Sentry DSNs and PostHog
project tokens are not classified as private credentials. Use explicit,
fingerprint-pinned allowlists for intentional secret-shaped test fixtures.

### Dependency audit scope

The vulnerability check discovers supported manifests and lockfiles recursively,
excluding dependency trees, build outputs, agent worktrees, and paths matched by
`ignore:` globs. It audits every discovered project/ecosystem target, including
mixed-language projects and nested applications. A workspace member whose
dependencies are covered by an ancestor's lockfile is not audited separately.
Each directory/tool outcome appears in the report. Yarn takes precedence when
both Yarn and npm lockfiles exist in one directory. Yarn 2+ is not run when a
`.yarnrc.yml` applies (it can load project code); that target is inconclusive.

Supported audit inputs are `Gemfile.lock`, `yarn.lock`, `package-lock.json`,
`composer.lock`, `requirements.txt`, `go.mod`/`go.sum`, and `Cargo.lock`.
`Pipfile.lock`, Poetry/uv locks, a bare `pyproject.toml`, pnpm/Bun lockfiles,
Maven/Gradle projects, and Elixir projects cannot currently
be audited directly. Export compatible pinned inputs or run those ecosystems'
auditors separately. Missing tools and unsupported inputs produce inconclusive
warnings rather than passes. A directory with no dependency manifests is skipped.

Each tool has a 60-second limit, the complete audit has a five-minute budget,
and discovery is limited to 64 targets. Scan smaller directories separately
when these limits are exceeded. Cancellation terminates subprocess trees on
Unix and Windows and bounds waits on inherited output pipes.

The Docker image contains the CLI and CA certificates, without package-manager
auditors. Dependency audits in that image report missing tools as inconclusive.
Run package-manager audits on the host or in the relevant language image.

### Email authentication domain

Set `checks.emailAuth.domain` to the actual email sending domain. SPF is checked
only at that exact domain. DMARC may fall back to its organizational domain only
when the child record is absent. Resolver errors, malformed records, and
duplicate records are reported as inconclusive. These checks inspect DNS
configuration; they do not send a test email or prove provider authorization
and deliverability.

Without a `domain`, the check uses the production URL's host, then its
organizational domain (`www.example.com`, then `example.com`), and its message
says the domain came from the production URL. Configs from before 0.24, which
had no `domain` key, keep working this way. With neither a `domain` nor a
production URL, the check is skipped. Set `domain` when you send mail from a
domain other than the one you serve.

The check performs basic record validation and conventional public-suffix-based
DMARC fallback. It does not evaluate SPF includes, DKIM, message alignment, or
the [RFC 9989 DNS tree-walk algorithm](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10).

### A note on scanning code you don't trust

Every check reads files; one runs a program. The `vulnerability` check
runs your package manager's audit tool (`npm audit`, `yarn audit`,
`composer audit`, `bundle-audit`, `pip-audit`, `govulncheck`, `cargo-audit`)
inside the project directory, with a scrubbed environment and a temporary
home so it cannot read your tokens. It avoids the known ways a repository
can hand that run to its own code: `cargo-audit` and `bundle-audit` run
directly rather than through `cargo` and `bundle`, Composer runs with
`--no-plugins --no-scripts`, Yarn classic ignores a `yarn-path`, and Yarn
2+ is not run under a `.yarnrc.yml`. Audit tools still read project-local
configuration, though, so this is a mitigation, not a sandbox. Scanning
your own projects is what Preflight is for. When scanning a repository
you don't trust, such as a fork's pull request in CI, add
`--skip vulnerability`. See [SECURITY.md](SECURITY.md) for how to report a
vulnerability in Preflight itself.

### Ignorable Service IDs

All services have validation checks that verify proper integration (env vars, SDK patterns, config files). Env keys are read from every `.env*` file at the project root: a value in `.env`, `.env.local`, `.env.test`, and the like sets a key, and a name in `.env.example`, `.env.sample`, or `.env.dist` documents it, which passes as configured but unverified (in CI, the example file is often all there is).

**Payments:** `stripe`, `paypal`, `braintree`, `paddle`, `lemonsqueezy`

**Error Tracking:** `sentry`, `bugsnag`, `rollbar`, `honeybadger`, `datadog`, `newrelic`, `logrocket`

**Transactional Email:** `postmark`, `sendgrid`, `mailgun`, `aws_ses`, `resend`

**Email Marketing:** `mailchimp`, `convertkit`, `beehiiv`, `aweber`, `activecampaign`, `campaignmonitor`, `drip`, `klaviyo`, `buttondown`

**Analytics:** `plausible`, `fathom`, `umami`, `google_analytics`, `fullres`, `datafast`, `posthog`, `mixpanel`, `amplitude`, `segment`, `hotjar`

**Auth:** `auth0`, `clerk`, `workos`, `firebase`, `supabase`

**Communication:** `twilio`, `slack`, `discord`, `intercom`, `crisp`

**Infrastructure:** `redis`, `sidekiq`, `rabbitmq`, `elasticsearch`, `convex`

**Storage & CDN:** `aws_s3`, `cloudinary`, `cloudflare`

**Search:** `algolia`

**AI:** `openai`, `anthropic`, `google_ai`, `mistral`, `cohere`, `replicate`, `huggingface`, `grok`, `perplexity`, `together_ai`

**SEO:** `indexnow` (the IndexNow service; its check ID is `index_now`, and either name works with `ignore`, `--only`, and `--skip`)

**Cookie Consent:** `cookieconsent`, `cookiebot`, `onetrust`, `termly`, `cookieyes`, `iubenda`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Warnings only |
| 2 | Errors found |
| 64 | Preflight could not run (bad path, unreadable or invalid config, unknown or pre-0.22 check ID, bad flag) |
| 130 | Scan cancelled (Ctrl-C / SIGTERM) |

Codes 1 and 2 mean the scan ran and reported something. Code 64 means it
never got that far, so CI can tell "this project has problems" apart from
"this invocation was wrong". The other commands (`auth`, `history`) exit 0 on
success, 2 when they fail (not logged in, network error), and 64 on a usage
error; they never exit 1.

## Shell Completions

Tab completion for commands, flags, and check IDs (including `--only` and `--skip` values):

```bash
# bash (add to ~/.bashrc)
source <(preflight completion bash)

# zsh (add to ~/.zshrc)
source <(preflight completion zsh)

# fish
preflight completion fish | source
```

`preflight help <command>` (or `preflight <command> --help`) shows any command's help.

## Environment Variables

| Variable | Effect |
|---|---|
| `NO_COLOR` | Turns off colored output ([no-color.org](https://no-color.org)) |
| `PREFLIGHT_TOKEN` | Token for `preflight auth login` to store instead of opening a browser |
| `PREFLIGHT_NO_UPDATE_CHECK` | Any non-empty value turns off the daily update check (it is already skipped with `--ci` and `--format json`) |
| `PREFLIGHT_INSTALL_DIR` | Where `install.sh` puts the binary (default `/usr/local/bin`) |
| `PREFLIGHT_VERSION` | Release tag for `install.sh` to install, such as `v0.25.0` (default: latest) |
| `PREFLIGHT_API_URL` | Dashboard base URL. Internal, for testing against a local dashboard only |

## Supported Stacks

**Backend Frameworks**
- Ruby on Rails, Laravel, PHP, Go, Python/Django, Rust, Node.js

**Frontend Frameworks**
- Next.js, Nuxt, Remix, React, Vue.js, Vite, Svelte/SvelteKit, Angular

**Traditional CMS**
- WordPress, Craft CMS, Drupal, Ghost

**Static Site Generators**
- Hugo, Jekyll, Gatsby, Eleventy (11ty), Astro

**Headless CMS**
- Strapi, Sanity, Contentful, Prismic

**Other**
- Static sites

## CI Integration

```yaml
# GitHub Actions example (curl)
- name: Run Preflight
  run: |
    curl -sSL https://preflight.sh/install.sh | sh
    preflight scan --ci --format json
```

```yaml
# GitHub Actions example (Docker)
- name: Run Preflight
  run: docker run -v ${{ github.workspace }}:/app ghcr.io/preflightsh/preflight scan --ci --format json
```

## License

MIT

## Release validation

CI and tagged releases share `.github/workflows/validate.yml`. Validation runs
race tests on Linux, macOS, and Windows, verifies modules, runs the configured
linter and vulnerability checker, checks formatting and the shell installer,
fuzzes parser trust boundaries, and smoke-tests the container. The release job
runs only after validation succeeds for the tagged commit and verifies that the
commit belongs to `main` before publishing. Keep the GitHub `release` environment
restricted to protected tag refs with required reviewers, and protect `main`.
These repository settings must be configured in GitHub; workflow code cannot
establish their current state.
