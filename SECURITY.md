# Security Policy

## Scope

ORIX is intended for authorized software engineering, defensive security, and reverse-engineering research.

## Reporting a vulnerability

Do not publish exploit details or sensitive artifacts in a public issue. Use GitHub's private vulnerability reporting feature for this repository if enabled. Include the affected commit, reproduction steps, impact, and a minimal proof of concept.

## Safe-use guarantees and limits

- The current artifact inspector is read-only and does not execute inspected files.
- File signatures are hints, not proof that a file is valid or safe.
- Hashes identify byte content; they do not establish trust.
- Do not analyze systems, accounts, or software without authorization.
- Future dynamic analysis must be isolated, opt-in, resource-limited, and separately reviewed before release.

## Maintainer checklist

- Treat all input artifacts as untrusted.
- Bound parser memory, recursion, and processing time.
- Avoid shell-string execution; pass executable arguments separately.
- Keep credentials and private artifacts out of logs and test fixtures.
- Add regression tests for every security-relevant bug.
