# Preflight CLI

A command-line tool that scans your codebase for launch readiness. Identifies missing configuration, integration issues, security concerns, SEO metadata gaps, and other common mistakes before you deploy to production.

## Installation

### Homebrew (macOS/Linux)

```bash
brew install phillips-jon/preflight/preflight
```

### Shell Script

```bash
curl -sSL https://raw.githubusercontent.com/phillips-jon/preflight.sh/main/install.sh | sh
```

### Manual Download

Download the latest release from [GitHub Releases](https://github.com/phillips-jon/preflight.sh/releases).

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
| **SEO Metadata** | Checks for title, description, and Open Graph tags |
| **OG & Twitter Cards** | Validates og:image, twitter:card and social sharing metadata |
| **Security Headers** | Validates HSTS, CSP, X-Content-Type-Options, Referrer-Policy |
| **SSL Certificate** | Checks SSL validity and warns before expiration |
| **Secret Scanning** | Finds leaked API keys and credentials in code |
| **Favicon & Icons** | Checks for favicon, apple-touch-icon, and web manifest |
| **robots.txt** | Verifies robots.txt exists for search engines |
| **sitemap.xml** | Checks for sitemap presence or generator |
| **llms.txt** | Checks for LLM crawler guidance file |
| **ads.txt** | Validates ads.txt for ad-supported sites (optional) |
| **LICENSE** | Checks for license file (opt-in, for open source projects) |

## Supported Services (47)

Preflight auto-detects and validates configuration for these services:

**Payments**
- Stripe, PayPal, Braintree, Paddle, LemonSqueezy

**Error Tracking & Monitoring**
- Sentry, Bugsnag, Rollbar, Honeybadger, Datadog, New Relic, LogRocket

**Email**
- Postmark, SendGrid, Mailgun, AWS SES, Resend, Mailchimp, ConvertKit

**Analytics**
- Plausible, Fathom, Fullres, Datafast, Google Analytics, Mixpanel, Amplitude, Segment, Hotjar

**Auth**
- Auth0, Clerk, Firebase, Supabase

**Communication**
- Twilio, Slack, Discord, Intercom, Crisp

**Infrastructure**
- Redis, Sidekiq, RabbitMQ, Elasticsearch

**Storage & CDN**
- AWS S3, Cloudinary, Cloudflare

**Search**
- Algolia

**AI / LLMs**
- OpenAI, Anthropic Claude, Google AI (Gemini), Mistral, Cohere, Replicate, Hugging Face, Grok (X/Twitter), Perplexity, Together AI

## Configuration

Preflight uses a `preflight.yml` file in your project root:

```yaml
projectName: my-app
stack: rails  # rails, next, node, laravel, static

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

  license:
    enabled: true  # opt-in, for open source projects
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Warnings only |
| 2 | Errors found |

## Supported Stacks

**Frameworks**
- Ruby on Rails, Next.js, Node.js (Express), Laravel, Go, Python/Django, Rust

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
    curl -sSL https://raw.githubusercontent.com/phillips-jon/preflight.sh/main/install.sh | sh
    preflight scan --ci --format json
```

## License

MIT
