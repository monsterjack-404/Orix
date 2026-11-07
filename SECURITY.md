# Security Policy

## Supported versions

ORIX is under active development. Security fixes are applied to the current `main` branch and current release line. Older snapshots may not receive backports.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting or Security Advisories for sensitive reports. Include the affected commit or release, Node.js version, operating system, exact command, a minimal non-sensitive reproducer and observed impact. Allow maintainers a reasonable opportunity to investigate before public disclosure.

Do not attach credentials, proprietary binaries, personal data or private target information to a public issue. If the sample itself is sensitive, provide a hash and a sanitized reproducer first.

## Security design

The current product is a local, static, read-only inspector. It rejects symlinks, limits file sizes and parser counts, uses bounded directory traversal and concurrency, and does not execute analyzed artifacts. These controls reduce risk but do not prove the absence of vulnerabilities.

See [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) for threats, mitigations, residual risks and requirements for any future dynamic-analysis subsystem.
