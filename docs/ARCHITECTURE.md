# ORIX Architecture

This document describes the 0.5.x implementation and the constraints new modules must preserve. The architecture is intentionally layered: file acquisition owns filesystem facts, the binary reader owns offset validation, format parsers own format interpretation, analyzers own orchestration, evidence owns provenance, renderers own presentation, and optional exports adapt findings to external report standards.

## 1. Runtime boundaries

ORIX currently runs as a Node.js command-line application and a small programmatic library. The current release is a local-first Node.js CLI/library with an append-only, hash-chained JSONL evidence ledger. It still has no daemon, remote service, plugin loader or relational database; a loopback-only browser report viewer is provided for saved reports. Those boundaries must not be implied by package names or roadmap documents.

The public call graph is:

```text
src/cli.mjs
  └─ src/cli/main.mjs
       ├─ src/cli/arguments.mjs
       ├─ src/core/inspect.mjs
       │    ├─ src/core/binary-reader.mjs
       │    ├─ src/core/hash.mjs
       │    ├─ src/core/entropy.mjs
       │    ├─ src/core/strings.mjs
       │    ├─ src/core/evidence.mjs
       │    └─ src/formats/index.mjs
       └─ src/analyzer/scan.mjs
            ├─ src/analyzer/walk.mjs
            └─ src/analyzer/compare.mjs

src/core/evidence-ledger.mjs owns persistent ledger integrity; src/evidence/ledger.mjs exposes the CLI-facing record adapter.

src/index.mjs exposes the supported programmatic surface, including SARIF and Rizin Markdown rendering, report comparison, provider execution and MCP server entry points. The dedicated `src/mcp.mjs` executable provides a JSON-RPC stdio transport. `src/evidence/ledger.mjs` owns the optional append-only hash-chained evidence journal.
```

## 2. Provider contract boundary

`schemas/provider-manifest.v1.schema.json` defines the declarative `orix.provider.v1` metadata contract: identity, capabilities, platform and format support, declared side effects, resource ceilings and redistribution status. `src/providers/manifest.mjs` validates bounded JSON manifests and safely reads regular files; `src/providers/registry.mjs` stores immutable metadata and provides deterministic capability queries.

`src/providers/process-runner.mjs` launches an explicitly selected static provider through an absolute executable path and an argument vector with `shell: false`. It validates argument/environment data, avoids inheriting the full parent environment, and bounds runtime, cancellation and captured output. `src/providers/rizin.mjs` is the first concrete adapter: it probes Rizin's version, requests JSON import metadata, records an input SHA-256 and checks the input identity after analysis. Its report schema is `schemas/rizin-imports.v1.schema.json`.

These features do not constitute a plugin loader, installer, automatic provider discovery or operating-system sandbox. The manifest is a declaration, not proof of executable behavior. ORIX cannot enforce a provider's filesystem/network restrictions; Windows process-tree teardown is not guaranteed. The Rizin adapter uses an external installation and does not execute the inspected target. See [PROVIDERS.md](PROVIDERS.md) for its API and limitations.
 
## 3. Ownership rules

| Component | Owns | Must not own |
|---|---|---|
| `core/inspect` | Path validation, file identity, bounded acquisition, complete-file hash, report assembly | Format-specific offset tables or user-facing Markdown |
| `core/binary-reader` | Buffer-relative bounds checks, typed reads, structured parse failures | Format guesses or high-level conclusions |
| `formats/registry` | Leading-byte signature recognition and supported-format metadata | Extension-based proof or parser behavior |
| `formats/*` | Format-specific field offsets, endianness, count and range validation | Filesystem access, execution, network or report output |
| `analyzer/walk` | Deterministic inventory, ignored directories, no-follow traversal, depth and count limits | Parsing file contents |
| `analyzer/scan` | Concurrency, per-file isolation, aggregate counts, indicator counts and coverage | Reinterpreting parser fields |
| `analyzer/indicators` | Deterministic rule evaluation over parser output and bounded metrics | Executing samples, network lookups, opaque scoring or final malware verdicts |
| `core/evidence` | In-memory evidence identity, provenance, confidence labels and details | User-facing verdicts |
| `core/evidence-ledger` | Canonical JSON records, bounded reads, writer lock, append-only writes, SHA-256 chain validation | Parser interpretation, automatic tamper repair or external timestamp claims |
| `evidence/ledger` | CLI-facing event adapter and normalized receipt/list/verify reports | Reimplementing the ledger format or hash algorithm |
| `reports/*` | JSON and Markdown rendering | New analysis or silent data loss |
| `cli/*` | Arguments, command routing, output destination selection | Parser implementation |

Consumers must use the owning component's normalized facts. Do not duplicate parsing logic in a report renderer or CLI command.

## 4. Acquisition and consistency

The inspector first obtains `lstat` metadata. It rejects symbolic links and non-regular files. It then opens the path read-only, requests no-follow behavior where the runtime exposes it, and compares opened-file identity metadata with the original lookup. This reduces path substitution risk but is not a universal guarantee against every filesystem race on every platform.

The inspector reads a bounded prefix for parsing and computes SHA-256 over the complete file in fixed-size chunks. It compares file metadata after reading and reports `stable_during_read`. A file that changes during inspection must not be treated as a stable forensic input. For high-assurance work, analyze a preserved copy acquired through a trusted evidence workflow.

`max_file_bytes` bounds the total file size eligible for hashing. `max_read_bytes` bounds the prefix retained for structural parsing and metrics. A full-file hash with prefix-only parsing is explicitly represented by `analysis_complete_for_file: false`.

## 5. Binary reader contract

`BinaryReader` wraps one immutable Buffer view and provides unsigned/signed integer reads, byte slices, ASCII reads and bounded C strings. Every read validates integer offsets and lengths before accessing the underlying `DataView` or Buffer.

Parser code must:

- Use file-relative offsets consistently.
- Validate `offset <= total` before evaluating `length <= total - offset`.
- Reject multiplication/offset overflow before deriving table ranges.
- Respect declared header lengths rather than assuming optional records exist.
- Keep unsupported values visible as `unknown-*` or explicit parser notes.
- Avoid converting 64-bit values to JavaScript numbers when precision would be lost.

A direct parser call may throw `OrixError`. `analyze_known_format` catches parser failures and returns the detected format together with `parser_status: rejected` and a stable error object.

## 6. Parsing pipeline

The registry identifies a candidate format from a leading signature. A parser is selected only when a corresponding parser is registered. After parsing, the indicator engine evaluates an explicit set of bounded rules against the parser result, entropy metrics, selected extracted strings and file-stability metadata. The engine emits rule IDs, severity, confidence and evidence references; it never executes the artifact. A signature can be forged, truncated or embedded in unrelated content; parsers therefore validate the relevant structures again.

Implemented structural parsers:

- **PE/COFF:** DOS header pointer, PE signature, COFF fields, PE32/PE32+ fixed fields, data-directory bounds and section headers.
- **ELF:** class, byte order, fixed header, section-header table and optional section-name table.
- **Mach-O:** thin header, CPU metadata and load-command framing.
- **WebAssembly:** version and section framing, strict UTF-8 names, function types, imports, exports, function/type indices, start function and code-body byte ranges. Table, memory, global, element, data, data-count and tag sections currently expose only bounded vector counts; instructions and initializers are not decoded.
- **ZIP:** end-of-central-directory lookup and bounded central-directory entry metadata; no extraction or decompression.

Parser output contains `notes` describing unimplemented work. The absence of a field is not evidence that the field or structure is absent from the original artifact.

## 7. Static indicator model

The initial indicator rules are intentionally transparent. They cover PE sections marked both writable and executable, PE section raw ranges outside supplied bytes, ZIP absolute/parent-traversal or symbolic-link entries, encrypted ZIP entries, high-entropy samples above a documented minimum size, selected process-memory and credential-access API-name strings, parser rejection, and metadata changes during acquisition.

Severity is triage priority, not a probability. High entropy is low severity because compression and encryption are common in benign data. API strings are heuristic because their presence does not prove an import or call. Parser rejection is an observed structural result, not a maliciousness verdict. The rules sort deterministically so the same report data yields the same finding order.

## 8. Evidence model

Evidence is emitted with:

- a generated identifier;
- a kind, such as `file-hash` or `format-structure`;
- a concise summary;
- a source path;
- an optional byte offset and length;
- one of `observed`, `derived` or `heuristic` confidence;
- structured details containing the source values needed to inspect the result.

The model is intended to evolve into persisted, cross-tool evidence without coupling parsers to a database. Future identifiers should be stable across process restarts, and evidence should gain artifact identity, tool version and parent-evidence references before cross-session reuse.

## 9. Directory scanning

The walker uses `Dirent` data, sorts entries deterministically and does not follow symlinks. Common generated directories are excluded. It returns both discovered files and skipped-entry reasons. Limits apply to file count and depth.

The scanner uses a bounded worker pool. Each file is inspected independently; one file's malformed content does not abort the scan. Per-file failures are retained as structured errors. Aggregate coverage must never imply that a truncated inventory is complete.

The current design is sequential at directory-inventory time and bounded-concurrent at file-analysis time. Do not add unbounded `Promise.all` over user-controlled directory contents.

## 10. Reports and compatibility

JSON is the canonical machine-readable output. Markdown is a view over the same report object. If a new report field is added, update schema/version documentation and both renderers where needed. Renderers must not invent fields or claim certainty beyond report evidence.

Report schema identifiers are currently `orix.artifact.v1`, `orix.scan.v1` and `orix.formats.v1`. Breaking output changes require a schema version change and migration notes.

## 11. Extension strategy

New analyzers should be independent modules with explicit resource budgets and typed output. New external engines should be implemented behind optional adapters that describe version detection, capability probing, input/output mapping, process ownership, timeouts, cancellation and cleanup. The core must remain useful when no external engine is installed.

Planned components such as databases, browser UI, collaboration and worker fleets should be added as vertical slices with end-to-end tests—not as disconnected empty folders. The local stdio MCP interface is implemented as a separate adapter over the same analysis services.


## 12. Persistent evidence ledger

The optional local ledger stores compact inspection, directory-scan or project-report records as JSON Lines. Each record contains a monotonically increasing sequence, UTC timestamp, event type, payload, previous-record SHA-256 and a SHA-256 digest over canonical JSON. A single-writer lock prevents concurrent appenders from interleaving writes. The verifier checks sequence continuity, previous-hash links, canonical record hashes, JSON framing and configured byte limits.

Use `orix inspect ./sample.exe --ledger ./.orix/evidence.jsonl` to append an inspection receipt. Use `orix ledger verify ./.orix/evidence.jsonl` to verify the chain and `orix ledger list ./.orix/evidence.jsonl` to display verified records.

The ledger is tamper-evident, not tamper-proof. A local administrator can replace both records and hashes. It is not a trusted timestamp authority, digital signature, remote transparency log, or write-once medium. Back up the ledger and preserve its head hash independently for stronger chain-of-custody workflows. An incomplete final line is rejected; ORIX never silently repairs or truncates evidence.


## 13. MCP boundary

`src/mcp/server.mjs` owns JSON-RPC framing, the advertised tool catalog, argument contracts, resource ceilings and dispatch into existing analysis modules. `src/mcp/security.mjs` confines file and directory paths to configured workspace roots and performs bounded no-follow report reads. `src/mcp.mjs` is the stdio executable. The default root is the process working directory; `ORIX_MCP_ROOTS` supplies an explicit platform-delimited allowlist.

The canonical evidence ledger implementation lives in `src/core/evidence-ledger.mjs`; `src/evidence/ledger.mjs` is a compatibility facade used by the CLI and MCP. The MCP adapter does not fork a second parser implementation. It reuses `inspect_file`, `scan_directory`, `scan_project`, `compare_reports` and the evidence ledger. Responses have a 2 MiB ceiling; incoming lines have a 4 MiB ceiling. The current implementation exposes tools only; HTTP transport, prompt/resource subscriptions, remote authentication and a hosted service are not implemented.


## 14. Local browser report explorer

`src/reports/view-model.mjs` normalizes artifact, directory-scan and project reports into inventory records, severity/format counts and deterministic filters. Project findings are copied into a display shape; raw matched credential values are not retained by the normalized finding model.

`web/app.mjs` reads the selected report in the browser, renders report-controlled values through DOM text nodes and exports formula-guarded CSV. It does not fetch report contents, evaluate report-provided code or modify the source report. `scripts/serve-web.mjs` is a loopback-only static server with an exact asset allowlist, GET/HEAD-only handling, no-store responses and a restrictive Content Security Policy (`connect-src 'none'`).

This is a local report explorer, not a server-side workspace, desktop shell, live scanner or plugin host. It displays evidence already in a report and cannot create new findings.


## Provider launch policy and receipt

The static process runner supports exact canonical executable allowlists and working-directory root allowlists. When omitted, the selected absolute executable and cwd are each treated as a one-entry allowlist for backward compatibility. Final symlink entries, sparse/accessor-backed lists, and paths outside the allowed roots are rejected. Environment inheritance is disabled; explicit overrides reject command-search and runtime-loader injection keys. The result preserves the Rizin adapter fields and adds a versioned `orix.provider-execution.v1` receipt with applied limits and a normalized termination reason.

These checks do not provide OS-level file, process or network isolation. Windows descendant-process cleanup remains a documented limitation.
