# Preflight.sh

A command-line tool that scans your codebase for launch readiness. Identifies missing configuration, integration issues, security concerns, SEO metadata gaps, and other common mistakes before you deploy to production.

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

### Shell Script

```bash
curl -sSL https://raw.githubusercontent.com/preflightsh/preflight/main/install.sh | sh
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

# Run in CI mode with JSON output
preflight scan --ci --format json
```

## What It Checks

| Check | Description |
|-------|-------------|
| **ENV Parity** | Compares `.env` and `.env.example` for missing variables |
| **Health Endpoint** | Verifies `/health` is reachable on staging/production |
| **Vulnerability Scan** | Checks for dependency vulnerabilities (bundle audit, npm audit, etc.) |
| **SEO Metadata** | Checks for title, description, and Open Graph tags |
| **OG & Twitter Cards** | Validates og:image, twitter:card and social sharing metadata |
| **Security Headers** | Validates HSTS, CSP, X-Content-Type-Options on both prod and staging |
| **SSL Certificate** | Checks SSL validity and warns before expiration |
| **Secret Scanning** | Finds leaked API keys and credentials in code |
| **Favicon & Icons** | Checks for favicon, apple-touch-icon (.png, .webp, .svg), and web manifest |
| **robots.txt** | Verifies robots.txt exists and has content |
| **sitemap.xml** | Checks for sitemap presence or generator |
| **llms.txt** | Checks for LLM crawler guidance file |
| **ads.txt** | Validates ads.txt for ad-supported sites (opt-in) |
| **IndexNow** | Verifies IndexNow key file for faster search indexing (opt-in) |
| **LICENSE** | Checks for license file (opt-in, for open source projects) |

## Supported Services (66)

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
- Auth0, Clerk, WorkOS, Firebase, Supabase

**Communication**
- Twilio, Slack, Discord, Intercom, Crisp

**Infrastructure**
- Redis, Sidekiq, RabbitMQ, Elasticsearch, Convex

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
    path: "/health"

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

  license:
    enabled: false  # opt-in, for open source projects
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Warnings only |
| 2 | Errors found |

## Supported Stacks

**Backend Frameworks**
- Ruby on Rails, Laravel, Go, Python/Django, Rust, Node.js

**Frontend Frameworks**
- Next.js, React, Vue.js, Vite, Svelte, Angular

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
# GitHub Actions example
- name: Run Preflight
  run: |
    curl -sSL https://raw.githubusercontent.com/preflightsh/preflight/main/install.sh | sh
    preflight scan --ci --format json
```

## License

MIT
