# ORIX Local Report Explorer

The browser viewer is a local presentation layer for saved ORIX report JSON. It is not a remote upload service, scanner or report database.

## Start

Requires Node.js 20.11 or newer:

```bash
npm ci
npm run web
```

Open http://127.0.0.1:4173. Set `ORIX_WEB_PORT` to select a port from 1 through 65535. The server binds only to IPv4 loopback.

## Supported report contracts

- `orix.artifact.v1`: one inspected artifact.
- `orix.scan.v1`: directory inventory and per-artifact findings.
- `orix.project.v1`: source inventory and redacted project findings.

Reports larger than 64 MiB, unsupported schemas and malformed identity/hash values are rejected. Search covers paths, hashes, rule IDs, titles and finding summaries. Severity and format filters can be combined. Select a row to review identity, parser state, findings and structured details. CSV export includes all report findings.

## Privacy and security

The selected file is read through the browser File API. Its bytes are not posted to the local server or any remote endpoint. Report-controlled values are rendered through DOM text nodes, not `innerHTML` or executable code. The normalized project finding model deliberately excludes `matched_value`. CSV cells are quoted and spreadsheet formula prefixes are neutralized.

The static server binds to `127.0.0.1`, serves an exact asset allowlist, accepts GET and HEAD only, and applies Content Security Policy, nosniff, no-store and no-referrer headers. CSP disables network connections, objects and framing.

The viewer presents evidence already in the input report. It does not run scans, determine vulnerability status or launch external reverse-engineering tools.
