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

Preflight is fully usable from the command line with no account. The optional dashboard at [app.preflight.sh](https://app.preflight.sh) adds a hosted history of your scans and AI-generated fix suggestions for each finding. Your code never leaves your machine: scanning runs locally, and only check IDs, statuses, controlled status messages, and a redacted configuration summary are sent when you publish. Website URLs are reduced to their origins; raw findings, subprocess output, paths, query strings, and secret values stay local. Dashboard bearer tokens are restricted to the origin that issued them, and authenticated redirects cannot cross origins or downgrade HTTPS.

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

Requires `preflight auth login`. `--here` matches runs to the current repository by its git remote, the same key used when publishing.

Open any failed or warning check on a published run to generate a step-by-step fix tailored to your detected stack, with copy-ready commands and code.

- **Free** includes 5 published runs per month.
- **Bring your own key:** add an OpenAI or Anthropic API key in your dashboard settings and publishing stays free and unlimited (you pay your provider directly).
- **Managed ($5/mo):** we cover the AI costs and runs are unlimited, no API key required.

## What It Checks

| Check | Description |
|-------|-------------|
| **ENV Parity** | Compares `.env` and `.env.example` for missing variables |
| **Health Endpoint** | Verifies site is reachable; auto-detects `/health`, `/healthz`, `/api/health` or falls back to root |
| **Vulnerability Scan** | Checks for dependency vulnerabilities (bundle audit, npm audit, etc.) |
| **SEO Metadata** | Checks for title, description, and Open Graph tags |
| **OG & Twitter Cards** | Validates og:image, twitter:card and social sharing metadata |
| **Canonical URL** | Verifies canonical link tag is present |
| **Viewport** | Checks for proper viewport meta tag for mobile |
| **Lang Attribute** | Validates html lang attribute for accessibility |
| **Structured Data** | Checks for JSON-LD Schema.org markup |
| **Security Headers** | Validates HSTS, CSP, X-Content-Type-Options on both prod and staging |
| **SSL Certificate** | Checks SSL validity and warns before expiration |
| **WWW Redirect** | Verifies www/non-www redirect to canonical URL |
| **Email Auth** | Checks SPF/DMARC records for the configured email sending domain (opt-in) |
| **Secret Scanning** | Finds leaked API keys and credentials in code |
| **Debug Statements** | Detects console.log, var_dump, debugger left in code |
| **Error Pages** | Checks for custom 404/500 error pages |
| **Image Optimization** | Finds large images (>500KB) that hurt load times |
| **Legal Pages** | Checks for privacy policy and terms of service pages |
| **Cookie Consent** | Detects cookie consent solution (GDPR/CCPA compliance) |
| **Favicon & Icons** | Checks for favicon, apple-touch-icon (.png, .webp, .svg), and web manifest |
| **robots.txt** | Verifies robots.txt exists and has content |
| **sitemap.xml** | Checks for sitemap presence or generator |
| **llms.txt** | Checks for LLM crawler guidance file |
| **ads.txt** | Validates ads.txt for ad-supported sites (opt-in) |
| **humans.txt** | Checks for humans.txt to credit the team (opt-in) |
| **IndexNow** | Verifies IndexNow key file for faster search indexing (opt-in) |
| **LICENSE** | Checks for license file (opt-in, for open source projects) |

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
    path: "/health"  # optional - auto-detects common paths if not set

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
        fingerprint: "sha256:<hex>"   # recommended — pins to the exact secret
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
`fingerprint: "sha256:<hex>"` — the SHA-256 of the detected secret
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

Every check ID is now snake_case. The old camelCase names keep working
everywhere an ID is accepted (`ignore:` lists, `--only`, `--skip`,
`preflight ignore`) through the 1.x line, with a note on stderr, and go
away in 2.0. `preflight ignore` writes the new name. The keys under
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
| `indexnow` | `index_now` |

### What a successful scan means

A pass means the check verified its stated requirement. Skipped checks are
reported separately and do not add to the passed count. Inconclusive checks
produce warnings and exit code 1 unless another check produces an error.
A scan containing only skipped checks also exits 1. Disabled checks are outside
the scan's scope; a partial scan cannot establish overall launch readiness.

JSON schema version **2** adds `skipped` and `inconclusive` to check outcomes
and their summary counts. A skipped check has `passed: false`; inconclusive
checks count as warnings. Consumers of schema 1 should update these semantics
before consuming schema 2. Published payloads use the same version.

When a website URL is configured, metadata checks verify all requirements
against fetched HTML. Static templates cannot override missing deployed tags.
Dynamic `generateMetadata()` functions require rendered verification. Offline
source checks are heuristics; SDK references and local configuration do not
prove that production credentials or integrations work.

Secret scanning includes `.example` and `.sample` files and source/configuration
files up to 32 MiB. Oversized or unreadable in-scope files make the scan
inconclusive. Public telemetry identifiers such as Sentry DSNs and PostHog
project tokens are not classified as private credentials. Use explicit,
fingerprint-pinned allowlists for intentional secret-shaped test fixtures.

### Dependency audit scope

The vulnerability check discovers supported manifests and lockfiles recursively,
excluding dependency trees, build outputs, and agent worktrees. It audits every
discovered project/ecosystem target, including mixed-language projects and
nested applications. Each directory/tool outcome appears in the report.
Yarn takes precedence when both Yarn and npm lockfiles exist in one directory.

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

Set `checks.emailAuth.domain` to the actual email sending domain. It is required
when email authentication is enabled and is independent of `urls.production`
and `urls.staging`. SPF is checked only at that exact domain. DMARC may fall back
to its organizational domain only when the child record is absent. Resolver
errors, malformed records, and duplicate records are reported as inconclusive.
These checks inspect DNS configuration; they do not send a test email or prove
provider authorization and deliverability. Existing enabled email-auth configs
must add `domain` before their next scan.

The check performs basic record validation and conventional public-suffix-based
DMARC fallback. It does not evaluate SPF includes, DKIM, message alignment, or
the [RFC 9989 DNS tree-walk algorithm](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10).

### A note on scanning code you don't trust

Every check reads files; one runs a program. The `vulnerability` check
executes your project's own package manager (`npm audit`, `yarn audit`,
`composer audit`, `bundle audit`, `pip-audit`, `govulncheck`, `cargo audit`)
inside the project directory, with a scrubbed environment and a temporary
home so it cannot read your tokens. Package managers still honor
project-local configuration, and some of that configuration can run code
from the repository (a Yarn `yarnPath`, a Cargo alias, a Composer plugin).
Scanning your own projects is what Preflight is for. When scanning a
repository you don't trust, such as a fork's pull request in CI, add
`--skip vulnerability`.

### Ignorable Service IDs

All services have validation checks that verify proper integration (env vars, SDK patterns, config files):

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

**SEO:** `index_now`

**Cookie Consent:** `cookieconsent`, `cookiebot`, `onetrust`, `termly`, `cookieyes`, `iubenda`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Warnings only |
| 2 | Errors found |
| 64 | Preflight could not run (bad path, unreadable config, unknown check ID) |
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

Output also respects the [`NO_COLOR`](https://no-color.org) environment variable.

## Supported Stacks

**Backend Frameworks**
- Ruby on Rails, Laravel, PHP, Go, Python/Django, Rust, Node.js

**Frontend Frameworks**
- Next.js, Nuxt, Remix, React, Vue.js, Vite, Svelte, Angular

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
