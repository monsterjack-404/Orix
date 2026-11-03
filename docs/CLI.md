# CLI and Automation Guide

The CLI is the supported human and automation entry point for ORIX 0.2.1. It is a thin command layer over the same programmatic functions exported from `src/index.mjs`.

## Commands

```bash
node src/cli.mjs compare ./baseline.json ./current.json --json
node src/cli.mjs inspect ./sample.exe --ledger ./.orix/evidence.jsonl
node src/cli.mjs ledger verify ./.orix/evidence.jsonl
node src/cli.mjs ledger list ./.orix/evidence.jsonl
```

### Inspect one artifact

```bash
node src/cli.mjs inspect ./artifact.bin
node src/cli.mjs inspect ./artifact.bin --json
node src/cli.mjs inspect ./artifact.bin --format json --out ./artifact-report.json
```

An inspection report contains:

- `artifact`: resolved path, name, extension, size, modification time, number of bytes parsed and whether the full file was parsed;
- `integrity`: SHA-256 digest and a stability indicator;
- `detection`: signature candidate, description and confidence;
- `parser`: one of `parsed`, `rejected` or `not-supported`, plus parser result or structured error;
- `metrics`: byte entropy, extracted printable strings and a bounded hex preview;
- `indicators`: deterministic rule IDs, severity, confidence and bounded supporting observations;
- `evidence`: provenance records with offsets and confidence;
- `warnings`: limits, parser rejection and consistency warnings.

### Scan a directory

```bash
node src/cli.mjs scan ./release
node src/cli.mjs scan ./release --json --max-files 2000 --max-depth 12
node src/cli.mjs scan ./release --concurrency 2 --no-strings
```

A scan report stores the aggregate summary separately from each artifact result. It includes `files_with_indicators` and `indicator_counts`, while each artifact retains its own rule findings. Per-file errors are isolated. The inventory has a `truncated` flag and skipped-entry list; consumers must inspect these before claiming full coverage.

### Analyze a source project

```bash
node src/cli.mjs project ./repository
node src/cli.mjs project ./repository --json
node src/cli.mjs project ./repository --format cyclonedx --out ./sbom.cdx.json
node src/cli.mjs project ./repository --format sarif --out ./project-findings.sarif
```

Project SARIF export maps source findings to SARIF 2.1.0 file and line locations. ORIX exports the rule ID, severity, confidence and a stable finding fingerprint. Credential-shaped match values are deliberately excluded from messages, evidence properties and fingerprints. The project root and each finding path are checked so a report cannot manufacture file locations outside its declared root.

A project scan is still static and heuristic. SARIF output does not upgrade a pattern match into a confirmed secret, vulnerability or runtime behavior finding. Review the reported line in the source repository before taking action.

### List known signatures

```bash
node src/cli.mjs formats
```

This command lists both recognized signatures and, by implication, formats that still need structural parsers. Use the format support matrix for the precise parser state. Static indicator rules are separate from signature recognition; see [`INDICATORS.md`](INDICATORS.md) for trigger conditions and false-positive guidance.


### Optional static providers

List the providers declared in this ORIX build. Listing does not probe or install third-party tools:

```bash
node src/cli.mjs providers list --json
```

Use Rizin to extract static import metadata from an artifact. The executable path is explicit and must identify an installed Rizin binary:

```bash
node src/cli.mjs providers rizin imports ./sample.elf \
  --executable /opt/rizin/bin/rizin \
  --format json \
  --timeout-ms 30000 \
  --max-output-kib 4096 \
  --max-imports 100000
```

The command writes an `orix.rizin-imports.v1` report containing the normalized import list, Rizin version, input SHA-256, input size and stability status. The default output is Markdown; `--json` preserves the full normalized result. `--out` remains create-only.

The timeout is a total deadline across input hashing, the version probe and import extraction. Output capture is bounded per provider process. The process runner uses argv without a shell and does not inherit the entire parent environment. It is **not an OS sandbox**: the provider executable can still access resources available to its account. POSIX process groups are signalled during termination; Windows process-tree teardown is not guaranteed. The inspected target is not executed by this adapter. See [Provider Integrations](PROVIDERS.md) for the full contract and threat boundary.

## Output contracts

`--json` is intended for scripts and downstream tools. Do not parse the human Markdown table output as an API. The top-level `schema_version` field identifies the current report contract. Unknown fields should be ignored by consumers so the contract can grow without breaking compatible readers.

`--out` is create-only: if the destination already exists, ORIX refuses to overwrite it. This prevents an output typo from replacing existing evidence. Parent directories must exist before a report is written.

## Exit status

- `0`: command completed and report was produced.
- `1`: command, input, validation or output failure. The error is printed to standard error with a stable `ORIX_*` code when the failure is a typed ORIX error.

A scan that contains some per-file failures still returns a report and exits successfully; inspect `errors` and `inventory_skips` to evaluate coverage.

## Resource controls

| Option | Default | Range |
|---|---:|---:|
| `--max-files` | 10,000 | 1–1,000,000 |
| `--max-directories` | 10,000 | 1–1,000,000 |
| `--max-entries` | 100,000 | 1–10,000,000 |
| `--max-depth` | 24 | 0–256 |
| `--max-read-mib` | 16 MiB | 1–512 MiB |
| `--max-file-mib` | 128 MiB | 1–2,048 MiB |
| `--concurrency` | 4 | 1–32 |
| `--strings-limit` | 2,000 | 0–100,000 |

`max-read-mib` cannot exceed `max-file-mib`. Programmatic callers can supply the same limits in the `limits` object, where byte values are expressed in bytes rather than MiB.

## Reproducibility

For reproducible reports, preserve the exact artifact bytes, ORIX version, Node.js version, command-line options and report schema version. Modification time is informational and can change when files are copied. SHA-256 is the content identity field in the current report schema.


### Report comparison

`compare` consumes two previously saved JSON artifact or directory-scan reports. It matches normalized report-relative paths and SHA-256 digests, then reports added, removed, modified and unchanged artifacts plus introduced and resolved indicator findings.

Comparison is report-to-report; it does not access or rescan the original directories. A rename appears as a removal and an addition. The Markdown renderer is the default; `--json` emits the versioned `orix.comparison.v1` contract. SARIF is not defined for comparison output.

### Evidence ledger

`--ledger` appends a compact report record to a local JSONL ledger after inspection, scan or project analysis. The first append creates the file and parent directory. Records are sequence-numbered and SHA-256 chained; a writer lock prevents concurrent appends from interleaving. The ledger stores a report summary and artifact hashes rather than raw sample bytes.

```bash
node src/cli.mjs inspect ./artifact.exe --ledger ./.orix/evidence.jsonl
node src/cli.mjs scan ./release --ledger ./.orix/evidence.jsonl
node src/cli.mjs ledger verify ./.orix/evidence.jsonl
node src/cli.mjs ledger list ./.orix/evidence.jsonl
```

The chain detects edits, deletion, reordering and incomplete final records. It is tamper-evident, not tamper-proof: anyone able to rewrite the entire ledger can recompute its hashes. Preserve signed or externally timestamped checkpoints when independent chain-of-custody proof is required.


### Local MCP server

`npm run mcp` starts the stdio JSON-RPC server; `orix-mcp` is the package executable. The default workspace root is the current working directory. Set `ORIX_MCP_ROOTS` to an explicit platform-delimited list of allowed roots. See [`MCP.md`](MCP.md) for tool contracts and security limits.


## Browser report explorer

Run `npm run web` and open http://127.0.0.1:4173. Set `ORIX_WEB_PORT` to choose another port. Import `orix.artifact.v1`, `orix.scan.v1` or `orix.project.v1` JSON from the browser file picker or drag-and-drop. Search the inventory, combine severity and format filters, inspect record details and export findings as CSV. File contents remain in the browser and are not sent to the server. The static server binds to loopback, exposes only allowlisted assets and accepts GET/HEAD requests only. Input is limited to 64 MiB.
