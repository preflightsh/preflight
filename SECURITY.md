# Security Policy

## Supported versions

Security fixes go into the latest minor release of the current major
version. Older minors do not get backports, so upgrading to the latest
release is the fix.

| Version | Supported |
| ------- | --------- |
| 0.25.x  | Yes       |
| < 0.25  | No        |

Once 1.0 ships, the latest 1.x minor will be the supported line.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it
privately through GitHub's private vulnerability reporting:

https://github.com/preflightsh/preflight/security/advisories/new

Include the `preflight version` output, what you ran, and what happened.
A proof of concept helps, but is not required. You should get a reply
within a few days, and a fix or a plan once the report is confirmed.

## Scanning untrusted repositories

Most checks only read files and make HTTP requests, but the
`vulnerability` check runs the project's own package-manager tooling
(`npm audit`, `yarn audit`, `composer audit`, `bundle-audit`,
`pip-audit`, `cargo-audit`, or `govulncheck`) inside the scanned
directory. Preflight closes the known ways for a repository to run its
own code through them (Composer runs without plugins or scripts, the
Cargo and Bundler audit tools are called directly so project aliases do
not apply, and Yarn 2 and later is not audited when the project has a
`.yarnrc.yml`), but these tools still read project-level configuration,
so a hostile repository can influence what they do.

To scan a repository you do not trust, skip that check:

```sh
preflight scan --skip vulnerability
```

or run Preflight in a sandbox, such as the container image with the
project mounted read-only.
