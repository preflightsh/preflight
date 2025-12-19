# Preflight.sh

[Preflight.sh](https://preflight.sh/) is a command-line tool that scans your codebase for launch readiness. Identifies missing configuration, integration issues, security concerns, SEO metadata gaps, and other common mistakes before you deploy to production. [View the changelog here.](https://changelog.preflight.sh/)

Don’t embarrass yourself in production. Just run the command.

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

## Quick Start

```bash
# Initialize in your project directory
cd your-project
preflight init

# Run all checks
preflight scan

# Scan a specific directory
preflight scan /path/to/project

# Run with verbose output (shows which files matched each check)
preflight scan --verbose
preflight scan -v  # short form

# Run in CI mode with JSON output
preflight scan --ci --format json

# Silence a check
preflight ignore sitemap

# Unsilence a check
preflight unignore sitemap

# List all check IDs
preflight checks
```

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
| **Email Auth** | Checks SPF/DMARC DNS records for email deliverability (opt-in) |
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

## Supported Services (70)

Preflight auto-detects and validates configuration for these services:

**Payments**
- Stripe, PayPal, Braintree, Paddle, LemonSqueezy

**Error Tracking & Monitoring**
- Sentry, Bugsnag, Rollbar, Honeybadger, Datadog, New Relic, LogRocket

**Email & Newsletters**
- Postmark, SendGrid, Mailgun, AWS SES, Resend, Mailchimp, Kit, Beehiiv, AWeber, ActiveCampaign, Campaign Monitor, Drip, Klaviyo, Buttondown

**Analytics**
- Plausible, Fathom, Fullres Analytics, Datafa.st Analytics, Google Analytics, PostHog, Mixpanel, Amplitude, Segment, Hotjar

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
    url: "https://api.example.com/webhooks/stripe"

  seoMeta:
    enabled: true
    mainLayout: "app/views/layouts/application.html.erb"

  security:
    enabled: true

  indexNow:
    enabled: true
    key: "your32characterhexkeyhere00000"

  emailAuth:
    enabled: true  # opt-in, checks SPF/DMARC on production domain

  humansTxt:
    enabled: false  # opt-in, credits the team

  license:
    enabled: false  # opt-in, for open source projects

# Silence specific checks or services by ID
ignore:
  - sitemap
  - llmsTxt
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

### Ignorable Check IDs

**SEO & Social:**
`seoMeta`, `canonical`, `structured_data`, `indexNow` (opt-in), `ogTwitter`, `viewport`, `lang`

**Security & Infrastructure:**
`securityHeaders`, `ssl`, `www_redirect`, `email_auth` (opt-in), `secrets`

**Environment & Health:**
`envParity`, `healthEndpoint`

**Code Quality & Performance:**
`vulnerability`, `debug_statements`, `error_pages`, `image_optimization`

**Legal & Compliance:**
`legal_pages`

**Web Standard Files:**
`favicon`, `robotsTxt`, `sitemap`, `llmsTxt`, `adsTxt` (opt-in), `humansTxt` (opt-in), `license` (opt-in)

### Ignorable Service IDs (with validation checks)

These services have validation checks that verify proper integration:

**Payments:** `stripe`

**Error Tracking:** `sentry`, `bugsnag`, `rollbar`, `honeybadger`, `datadog`, `newrelic`, `logrocket`

**Email:** `postmark`, `sendgrid`, `mailgun`, `aws_ses`, `resend`

**Analytics:** `plausible`, `fathom`, `google_analytics`, `fullres`, `datafast`, `posthog`, `mixpanel`, `amplitude`, `segment`, `hotjar`

**Infrastructure:** `redis`, `sidekiq`

### Ignorable Service IDs (detection only)

These services are auto-detected but don't have validation checks yet:

**Payments:** `paypal`, `braintree`, `paddle`, `lemonsqueezy`

**Email:** `mailchimp`, `convertkit`, `beehiiv`, `aweber`, `activecampaign`, `campaignmonitor`, `drip`, `klaviyo`, `buttondown`

**Auth:** `auth0`, `clerk`, `workos`, `firebase`, `supabase`

**Communication:** `twilio`, `slack`, `discord`, `intercom`, `crisp`

**Infrastructure:** `rabbitmq`, `elasticsearch`, `convex`

**Storage & CDN:** `aws_s3`, `cloudinary`, `cloudflare`

**Search:** `algolia`

**AI:** `openai`, `anthropic`, `google_ai`, `mistral`, `cohere`, `replicate`, `huggingface`, `grok`, `perplexity`, `together_ai`

**SEO:** `indexnow`

**Cookie Consent:** `cookieconsent`, `cookiebot`, `onetrust`, `termly`, `cookieyes`, `iubenda`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Warnings only |
| 2 | Errors found |

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
    curl -sSL https://raw.githubusercontent.com/preflightsh/preflight/main/install.sh | sh
    preflight scan --ci --format json
```

```yaml
# GitHub Actions example (Docker)
- name: Run Preflight
  run: docker run -v ${{ github.workspace }}:/app ghcr.io/preflightsh/preflight scan --ci --format json
```

## License

MIT
