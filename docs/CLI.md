# CLI and Automation Guide

The CLI is the supported human and automation entry point for ORIX 0.5.0. See the repository README and capability matrix for the current release surface. It is a thin command layer over the same programmatic functions exported from `src/index.mjs`.

## Commands

```bash
node src/cli.mjs compare ./baseline.json ./current.json --json
node src/cli.mjs inspect ./sample.exe --ledger ./.orix/evidence.jsonl
node src/cli.mjs ledger verify ./.orix/evidence.jsonl
node src/cli.mjs ledger list ./.orix/evidence.jsonl
node src/cli.mjs capabilities --json
```

### Investigation cases

```bash
node src/cli.mjs case create ./workspace "Sample investigation" "Authorized offline review"
node src/cli.mjs case list ./workspace
node src/cli.mjs case add-artifact ./workspace <case-uuid> ./workspace/sample.exe
node src/cli.mjs case analysis ./workspace <case-uuid> ./workspace/report.json orix 0.5.0
node src/cli.mjs case finding ./workspace <case-uuid> ORIX_RULE "Review candidate" "Evidence summary" medium observed
node src/cli.mjs case note ./workspace <case-uuid> "Needs manual confirmation"
node src/cli.mjs case finding-status ./workspace <case-uuid> <finding-uuid> triaged "Review started"
node src/cli.mjs case verify ./workspace <case-uuid>
node src/cli.mjs case export ./workspace <case-uuid> ./case-bundle
node src/cli.mjs case import ./workspace ./case-bundle
```

Case operations use a workspace-local append-only event history. Original artifact bytes are not copied; reports are stored with SHA-256 receipts. Portable bundles are unsigned. See [Investigation Cases](CASES.md) for the complete contract and boundaries.

### Capability inventory

```bash
node src/cli.mjs capabilities --json
node src/cli.mjs capabilities --json --out ./orix-capabilities.json
```

The inventory is assembled from the live format parser registry, MCP tool definitions and provider manifest. It labels interfaces, reports and intelligence domains as implemented, partial or planned and includes explicit boundaries. Provider availability is reported as `external-install-not-probed`; this command does not execute or probe external tools.

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

### Analyze a network capture

```bash
node src/cli.mjs har ./capture.har
node src/cli.mjs har ./capture.har --json
node src/cli.mjs har ./capture.har --max-har-entries 5000 --max-har-hosts 1000 --format markdown
```

The HAR command accepts HAR 1.2 JSON and performs offline metadata analysis. It reports request/response metadata, hosts, status codes, timings, SHA-256 provenance and evidence-linked security review leads. Shared operating-system temporary-directory paths are rejected as evidence intake; copy captures into a private workspace first. The default ceiling is 20,000 entries (maximum 100,000), the default host inventory ceiling is 5,000 distinct hosts (maximum 10,000), and the input-file ceiling is 32 MiB. The report marks entry and host truncation independently; `coverage.complete` is false whenever either inventory is incomplete. Request/response bodies, cookie values, query values and arbitrary header values are never included in the report. URL paths and server IP addresses may still be sensitive. No requests are sent and no target code is executed.

### Analyze an Android APK or App Bundle

```bash
node src/cli.mjs android ./app.apk
node src/cli.mjs android ./app.apk --json --max-archive-entries 2000
node src/cli.mjs android ./app.aab --format markdown --out ./android-report.md
```

This offline inventory reports safe ZIP metadata, bounded APK binary-XML permissions/components, stored and raw-DEFLATE DEX identifier/prototype/class-data/code-item metadata, multidex/native-library paths, v1 signature filename hints, APK Signing Block scheme-ID structure (v2/v3/v3.1), and a SHA-256 receipt for file-based analysis. DEX Adler-32 and SHA-1 fields are recomputed. Signing-block inspection is structural only: APK signatures, content digests, certificate chains and publisher identity are not cryptographically verified. AAB module manifests are decoded from AAPT2 protobuf XML, while `BundleConfig.pb` is inspected for tool version, bundle type, compression globs and recognized split/optimization metadata under a 4 MiB default / 64 MiB maximum programmatic size ceiling. Each module `resources.pb` is decoded within per-entry (16 MiB default / 64 MiB max), aggregate (64 MiB default / 512 MiB max) and entry-count (256 default / 4,096 max) limits. The report inventories package/type/entry IDs and names, visibility, configuration qualifiers, variant counts, and top-level values such as strings, direct references, files, primitives and compound-value kinds. Direct references are not resolved; binary StringPool contents remain opaque; compound values are not fully expanded; framework/overlay/runtime resolution and split/install relationships remain unsupported. The report does not extract entries to disk. Selected stored/raw-DEFLATE manifest, DEX and BundleConfig entries are expanded in memory under per-entry and aggregate byte ceilings; encrypted, malformed and unsupported entries are not parsed. App code is never executed. `--max-archive-entries` defaults to 1,000 (maximum 50,000). Android file input is capped at 1,024 MiB; the default is 512 MiB.

### Analyze a source project

```bash
node src/cli.mjs project ./repository
node src/cli.mjs project ./repository --json
node src/cli.mjs project ./repository --format cyclonedx --out ./sbom.cdx.json
node src/cli.mjs project ./repository --format sarif --out ./project-findings.sarif
```

Project SARIF export maps source findings to SARIF 2.1.0 file and line locations. ORIX exports the rule ID, severity, confidence and a stable finding fingerprint. Credential-shaped match values are deliberately excluded from messages, evidence properties and fingerprints. The project root and each finding path are checked so a report cannot manufacture file locations outside its declared root.

A project scan is still static and heuristic. SARIF output does not upgrade a pattern match into a confirmed secret, vulnerability or runtime behavior finding. Review the reported line in the source repository before taking action.

### Audit resolved dependencies against OSV

Run the project inventory first, then explicitly opt in to a public OSV.dev lookup:

```bash
node src/cli.mjs audit ./repository --osv
node src/cli.mjs audit ./repository --osv --json --out ./vulnerabilities.json
node src/cli.mjs audit ./repository --osv --max-packages 1000 --max-advisories 250 --max-network-mib 32 --timeout-ms 20000
```

The audit queries only exact package versions already present in supported lockfiles. It does not guess versions from manifest ranges. Unsupported ecosystems, unresolved versions, package ceilings, pagination ceilings, API errors and unavailable advisory details are recorded in the versioned `orix.vulnerability-audit.v1` report. Inspect `summary.complete`, per-package status and warnings; an incomplete audit is not a clean bill of health.

Network access is disabled by default. Without `--osv`, ORIX does not contact OSV.dev. With the flag, it sends package ecosystem, name and exact version identifiers to the public OSV API. Source files, lockfiles, manifests, artifact bytes and repository contents are not uploaded. Private package names and versions can still be sensitive metadata, so review the inventory before opting in.

OSV matches are vulnerability intelligence, not proof of reachability or exploitability. Review the linked advisory and affected version range, then validate against the application's actual use. See [Dependency Vulnerability Intelligence](VULNERABILITY-INTELLIGENCE.md).

### Analyze project architecture

Build a bounded report from the project's discovered local-import graph:

```bash
node src/cli.mjs architecture ./repository
node src/cli.mjs architecture ./repository --json
node src/cli.mjs architecture ./repository --format mermaid --out ./architecture.mmd
node src/cli.mjs architecture ./repository --json --out ./architecture.json
node src/cli.mjs architecture ./repository --max-nodes 10000 --max-edges 50000 --max-hotspots 40
```

The analyzer reports source-graph entry-point candidates, strongly connected components (circular imports and self-loops), graph reachability, isolated and leaf modules, connectivity hotspots, language/directory counts and external import specifiers. It reuses `--max-files`, `--max-entries` and `--max-depth` for inventory. Graph analysis has separate controls: `--max-nodes` (default 20,000, maximum 50,000), `--max-edges` (default 100,000, maximum 250,000) and `--max-hotspots` (default 25, maximum 100). If a graph limit is reached, the report marks graph coverage incomplete and records omitted work. Mermaid output is separately bounded to 120 nodes and 300 edges by default. Output files are create-only.

These are static heuristics over imports resolved by the project scanner—not compiler-backed call graphs, runtime traces or proof of dead code. Dynamic imports, reflection, generated code, conditional exports and unsupported language resolution may be absent. No source file, build, test, package script or target program is executed. See [Architecture Analysis](ARCHITECTURE-ANALYSIS.md) for report fields and interpretation limits.

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

Check that an explicitly selected Rizin executable starts and reports a parseable version. This does not search PATH or open an artifact:

```bash
node src/cli.mjs providers rizin doctor \
  --executable /opt/rizin/bin/rizin \
  --json
```

The doctor command emits an `orix.provider-probe.v1` report. It confirms only the version probe, not every Rizin command or binary format.

Use Rizin to extract static import metadata from an artifact. The executable path is explicit and must identify an installed Rizin binary:

```bash
node src/cli.mjs providers rizin imports ./sample.elf \
  --executable /opt/rizin/bin/rizin \
  --format json \
  --timeout-ms 30000 \
  --max-output-kib 4096 \
  --max-imports 100000
```

The command writes an `orix.rizin-imports.v1` report containing the normalized import list, Rizin version, input SHA-256, input size and stability status. ORIX creates a byte-bounded private snapshot of the artifact, passes that copy to Rizin, and verifies its digest after execution; the original input path is not passed to the provider. The default output is Markdown; `--json` preserves the full normalized result. `--out` remains create-only.

The timeout is a total deadline across input hashing, the version probe and import extraction. Output capture is bounded per provider process. The process runner uses argv without a shell and does not inherit the entire parent environment. It is **not an OS sandbox**: the provider executable can still access resources available to its account. POSIX process groups are signalled during termination; Windows process-tree teardown is not guaranteed. The inspected target is not executed by this adapter. See [Provider Integrations](PROVIDERS.md) for the full contract and threat boundary.

### Rizin function inventory and disassembly

List functions identified by Rizin automatic analysis:

~~~sh
node src/cli.mjs providers rizin functions ./sample.elf --executable /opt/rizin/bin/rizin --max-functions 10000 --json
~~~

Request an instruction window from one exact function entry:

~~~sh
node src/cli.mjs providers rizin functions ./sample.elf --executable /opt/rizin/bin/rizin --address 0x401000 --max-instructions 100 --json
node src/cli.mjs providers rizin functions ./sample.elf --executable /opt/rizin/bin/rizin --address 0x401000 --decompile --json
~~~

The function report uses `-A` and `aflj`; the optional instruction window uses `pdj`. Addresses must match an entry returned in the function inventory. Function listing is capped at 100,000 entries (default 10,000), and disassembly is capped at 1,000 instructions (default 100). The total workflow shares one timeout and output budget across all Rizin processes. Add `--decompile` with `--address` to ask the optional `pdg` command for pseudocode; this requires the separately installed `rz-ghidra` plugin and is heuristic, not a compilable source reconstruction.
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
| `--max-functions` | 10,000 | 1–100,000 |
| `--max-archive-entries` | 1,000 | 1–50,000 |
| `--max-instructions` | 100 | 1–1,000 |

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

Run `npm run web` and open http://127.0.0.1:4173. Set `ORIX_WEB_PORT` to choose another port. Import `orix.artifact.v1`, `orix.scan.v1`, `orix.project.v1`, `orix.rizin-imports.v1` or `orix.provider-probe.v1` JSON from the browser file picker or drag-and-drop. Search the inventory, combine severity and format filters, inspect record details and export findings and Rizin import metadata as CSV. File contents remain in the browser and are not sent to the server. The static server binds to loopback, exposes only allowlisted assets and accepts GET/HEAD requests only. Input is limited to 64 MiB.
