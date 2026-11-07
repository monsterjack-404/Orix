# ORIX — Open Research & Intelligence eXplorer

**Understand. Analyze. Engineer.**

> Product direction: [ORIX Product Charter](docs/PRODUCT_CHARTER.md) · [Capability Matrix](docs/CAPABILITY_MATRIX.md) · [Engineering Gap Register & Implementation Backlog](docs/IMPLEMENTATION_BACKLOG.md). These define the long-term target and planned work; they do not imply planned capabilities are already implemented.

ORIX is a local-first engineering intelligence workbench for inspecting software artifacts, reconstructing file-format structure, and preserving the evidence behind every conclusion. It is designed as a serious, extensible foundation for authorized reverse engineering and software research—not a wrapper that hides its methods and not a collection of aspirational feature folders.

> Current release line: **0.5.0 — Artifact, Project, Evidence, Interchange + MCP Intelligence**  
> Runtime: **Node.js 22 or newer**  
> Dependencies: **Node.js built-ins only**  
> Execution model: **local static analysis with opt-in bounded external static providers**

---

## What exists today

This repository contains working source code, bounded parsers, a usable CLI, programmatic exports, integration tests, and a CI workflow. The implemented surface is intentionally narrower than the long-term product vision; each capability below is tied to code and tests in this repository.

| Subsystem | Implemented behavior | Current boundary |
|---|---|---|
| Artifact intake | Regular-file validation, symlink rejection, size ceilings, bounded prefix reads | Does not acquire files from remote locations |
| Integrity | Streaming SHA-256 over the complete file using a bounded buffer | Does not authenticate the publisher or establish trust |
| Format registry | Signature recognition for ELF, PE/MZ, Mach-O, universal Mach-O, WebAssembly, classic PCAP/PCAPNG, UBIFS, SquashFS, cramfs, UBI, PDF, PNG, JPEG, SQLite, GZIP, CPIO newc and USTAR-compatible TAR | Signature recognition is not a complete format parser |
| PE parser | PE32/PE32+ headers, data directories, section records, file-backed RVA mapping, normal and delay-import DLLs with name/ordinal thunks, named/ordinal exports, resource trees, WIN_CERTIFICATE framing, base-relocation records and bounded CLR metadata stream inventory | Does not decode CLR metadata tables or IL, decompile assemblies, apply relocations or verify Authenticode trust |
| ELF parser | ELF32/ELF64 headers, bounded program segments, PT_INTERP, PT_DYNAMIC tags, GNU build IDs, symbol tables, REL/RELA relocation records and GNU symbol-version requirements/definitions, VERSYM mappings and bounded GNU hash bloom/bucket/chain tables | Does not apply relocations or decode DWARF |
| Mach-O parser | Thin and FAT/FAT64 universal images, per-slice parsing, segment/section commands, LC_SYMTAB symbols, LC_DYSYMTAB groups/indirect symbols and CodeDirectory metadata | Does not cryptographically verify signatures or decode chained fixups and Objective-C metadata |
| ZIP parser | ZIP32/ZIP64 central-directory indexing, extended entry sizes and offsets, unsafe path and symlink metadata | Multi-disk archives, extraction, decompression and CRC verification are not implemented |
| PDF parser | Classic xref tables, trailer metadata, incremental /Prev chain, indirect-object framing, encryption and active-content marker triage | Xref-stream entries, object streams, filters, attachment extraction, page-tree semantics and signature verification are not implemented |
| PNG parser | Bounded chunk index, IHDR, palette/transparency constraints, IDAT ordering, IEND and configurable CRC validation | Does not inflate IDAT, decode scanlines/pixels or validate color management |
| WebAssembly parser | Versioned module header, bounded specification-ordered section framing, strict UTF-8 names, module/function name maps, function types, imports, exports, function/type indices, start function and code-body ranges | Does not decode instructions or initializers, validate all section semantics, or decompile code |
| PCAP parser | Classic PCAP 2.4 framing, endian/timestamp variants, bounded Ethernet/VLAN, BSD loopback, Linux cooked and raw-IP metadata, IPv4/IPv6 endpoints and immediate TCP/UDP ports | No IPv6 extension traversal, reassembly, checksums, application protocols, payload export or replay |
| PCAPNG parser | Section/block framing, per-section byte order, interface options, enhanced/simple packet metadata, timestamp resolution, name-resolution counts, interface statistics and safe decryption-secret inventory | No IPv6 extension traversal, reassembly, checksum verification, application protocols, payload export or replay; secret contents are never exposed |
| Static metrics | Shannon entropy, ASCII/UTF-16LE string extraction and bounded hex preview | Metrics are descriptive, not malware verdicts |
| Static indicators | Explainable rules for PE writable/executable sections, invalid ranges, ZIP unsafe entries, encryption flags, high entropy, selected API-name strings, PDF active-content/embedded-content/encryption markers, parser rejection and acquisition instability | Heuristics are review leads, not malware classifications or proof of execution |
| Evidence and case workflows | Stable report evidence, append-only SHA-256 event ledger, persistent local cases, content-addressed artifact references, analysis report records, finding lifecycle, notes, typed relationships, timeline, verification and portable case bundles | Bundles are unsigned and do not embed source samples; no cross-case graph, multi-user database, trusted timestamp or signature |
| Directory scan | Deterministic traversal, ignored build/dependency folders, no symlink following, bounded concurrency | No distributed scanning or filesystem watcher |
| Dependency vulnerability audit | Explicit opt-in OSV lookup for exact lockfile-resolved versions, bounded batch pagination, advisory details and partial-coverage reporting | No offline advisory cache, local affected-range engine, reachability proof or exploitability verdict |
| MCP integration | Local stdio JSON-RPC server with typed tools for inspect, scan, project, architecture, HAR, case management, report comparison, formats, capabilities and evidence-ledger operations | No HTTP listener, remote auth, resource subscription or prompt catalog |
| Provider integrations | Declarative manifests, immutable registry, bounded shell-free process runner, Rizin version doctor, snapshot-isolated import adapter, function inventory, address-scoped instruction disassembly and optional rz-ghidra pseudocode, provider discovery/list CLI and JSON/Markdown reports | No bundled decompiler plugin or automatic plugin installer, OS sandbox, dynamic execution provider, installer, daemon or automatic provider discovery |
| Offline website analysis | Bounded offline HTML inventory, linked/inline JavaScript static imports and declaration candidates, depth/file/byte-capped local module graph, stylesheet/link/form/iframe metadata and review findings | No standards-complete DOM, CSS/source maps, script execution, network fetching or live browser observation |
| Electron static triage | Detects Electron package/source signals and reports literal risky `webPreferences` settings with file/line evidence during `project` scans | Heuristic only; no AST/data-flow analysis, runtime observation or exploitability verdict |
| Android APK | ZIP-container recognition via AndroidManifest.xml, bounded binary/plain XML manifest metadata, DEX header/table and class descriptor inventory, native ABI library inventory | No signing-block or certificate verification, DEX instruction/method analysis, resource resolution or runtime observation |
| HAR network analysis | Offline HAR 1.2 request inventory, host/status/timing summaries, review findings and SHA-256 evidence; bodies and secret header/query values are excluded | Does not capture live traffic, validate TLS certificates or prove that a capture is authentic |
| Firmware archive metadata | Raw CPIO newc/CRC-newc and USTAR/PAX/GNU TAR metadata inventory; GZIP wrapper decompression with CRC/ISIZE validation and nested CPIO/TAR recognition | No extraction, filesystem reconstruction, sparse map decoding or device installation |
| Firmware filesystem metadata | UBI EC/VID, bounded PEB inventory and opt-in layout-volume table record decoding; UBIFS superblock/master-node metadata; SquashFS v4.0 superblock/table offsets; cramfs superblock/root inode | No UBI attach/fastmap semantics, UBIFS index/journal/LPT traversal, file extraction, full payload decoding or mounting |

| Reports | JSON, Markdown, SARIF 2.1.0 for artifact, directory-scan and source-project findings, report comparison and CycloneDX 1.5 SBOM | No hosted dashboard or relational database |

Static indicator rules operate only on already-parsed metadata and bounded extracted strings. Each finding includes a rule ID, severity, confidence and supporting evidence. A clean report means only that the built-in rules did not match; it is not a safety certification.

Formats without a parser are still identified where their signatures are recognized. They are reported as `not-supported`, rather than pretending that a header was decoded.

The WebAssembly parser now exposes a bounded structural index of type, import, export, function and code-body metadata. Its exact validation boundary and API fields are documented in [`docs/WASM_ANALYSIS.md`](docs/WASM_ANALYSIS.md).

## Repository intelligence

### Project architecture analysis

The `architecture` command turns the source-import graph discovered by `project` into a separate, versioned structural report. It identifies candidate entry points, circular-import groups, reachable modules, isolated/leaf files, high-connectivity modules and observed external import specifiers.

```bash
node src/cli.mjs architecture ./source-tree
node src/cli.mjs architecture ./source-tree --json --out ./architecture.json
node src/cli.mjs architecture ./source-tree --format mermaid --out ./architecture.mmd
```

The same analysis is available to local MCP clients as `orix.analyze_architecture`, restricted to configured workspace roots and bounded by explicit inventory/graph ceilings. This is a source-import graph heuristic, not a compiler call graph, runtime tracer or proof that a file is unused. See [Architecture Analysis](docs/ARCHITECTURE-ANALYSIS.md).

The `project` command builds a bounded source and manifest index without running project scripts, builds or tests:

```bash
node src/cli.mjs project ./source-tree
node src/cli.mjs project ./source-tree --json
node src/cli.mjs project ./source-tree --format cyclonedx --out ./sbom.cdx.json
node src/cli.mjs project ./source-tree --format sarif --out ./project-findings.sarif
node src/cli.mjs audit ./source-tree --osv --json --out ./vulnerabilities.json
```

Dependency auditing is a separate explicit network opt-in. It sends only exact package ecosystem/name/version identifiers from supported lockfiles to OSV.dev; without `--osv`, no advisory lookup is performed. See [Vulnerability Intelligence](docs/VULNERABILITY-INTELLIGENCE.md).

It records file hashes, language counts, selected dependency declarations, npm package-lock v1-v3, Yarn classic/Berry, pnpm v5/v6/v9, Cargo.lock v1-v4, Composer.lock, Poetry, Pipenv and uv.lock resolved package inventories, plus Go checksums, bounded JavaScript/TypeScript lexical import and declaration analysis, source import edges, symbol candidates, redacted credential-shaped findings and bounded Git repository metadata (refs, tags, sanitized remotes and loose HEAD commit identity). Packed Git objects and linked-worktree gitdir targets are not decoded or followed. CycloneDX export includes resolved lockfile components and package relationships when supported lockfiles are present; otherwise it reports declared dependencies only. See [`docs/PROJECT_INTELLIGENCE.md`](docs/PROJECT_INTELLIGENCE.md) for parser boundaries and resource limits.

## Quick start

```bash
# Check your Node.js version
node --version

# Clone and enter the repository
git clone https://github.com/monsterjack-404/Orix.git
cd Orix

# Install from the lockfile (there are no third-party runtime dependencies)
npm ci

# Run tests and syntax checks
npm test
npm run check

# Inspect one file
node src/cli.mjs inspect ./sample.exe

# Emit JSON for automation
node src/cli.mjs inspect ./sample.exe --json

# Scan a directory with explicit resource ceilings
node src/cli.mjs scan ./build --max-files 3000 --max-depth 16 --concurrency 4

# List known signatures
node src/cli.mjs formats

# List implemented, partial and planned capabilities
node src/cli.mjs capabilities --json

# List optional providers and invoke Rizin static import extraction
node src/cli.mjs providers list --json
node src/cli.mjs providers rizin doctor --executable /usr/bin/rizin --json
# Wrapper executables may receive literal prefix arguments without a shell:
node src/cli.mjs providers rizin doctor --executable /usr/bin/node --executable-arg ./rizin-wrapper.mjs --json
node src/cli.mjs providers rizin imports ./sample.elf --executable /usr/bin/rizin --json --timeout-ms 30000 --max-output-kib 4096 --max-imports 100000
node src/cli.mjs providers rizin functions ./sample.elf --executable /usr/bin/rizin --max-functions 10000 --json
node src/cli.mjs providers rizin functions ./sample.elf --executable /usr/bin/rizin --address 0x401000 --max-instructions 100 --json
node src/cli.mjs providers rizin functions ./sample.elf --executable /usr/bin/rizin --address 0x401000 --decompile --json

# Start local MCP stdio server
npm run mcp

# Compare saved reports
node src/cli.mjs compare ./baseline.json ./current.json --json

# Launch local report explorer
npm run web

# Append and verify an evidence record
node src/cli.mjs inspect ./sample.exe --ledger ./.orix/evidence.jsonl
node src/cli.mjs ledger verify ./.orix/evidence.jsonl
```

## Evidence-first investigation cases

Create a durable case, attach workspace-local artifacts by SHA-256 reference, record analysis reports, manage finding states, add analyst notes and export a verifiable portable case directory:

```bash
node src/cli.mjs case create ./workspace "Sample investigation" "Authorized offline review"
node src/cli.mjs case list ./workspace
node src/cli.mjs case add-artifact ./workspace <case-uuid> ./workspace/sample.exe
node src/cli.mjs case analysis ./workspace <case-uuid> ./workspace/report.json orix 0.5.0
node src/cli.mjs case note ./workspace <case-uuid> "Needs manual confirmation"
node src/cli.mjs case verify ./workspace <case-uuid>
node src/cli.mjs case export ./workspace <case-uuid> ./case-bundle
```

Cases use an append-only event history. Analysis reports are stored inside the case; original sample bytes are not copied. Portable bundles are unsigned and require the original referenced artifacts to remain available for re-analysis. See [Investigation Cases](docs/CASES.md) for the storage contract, lifecycle, API and limits.

## HAR network investigation

Analyze a browser or proxy-exported HAR 1.2 capture without contacting its hosts or replaying requests:

```bash
node src/cli.mjs har ./capture.har
node src/cli.mjs har ./capture.har --json --max-har-entries 20000 --max-har-hosts 5000
```

The analyzer records a SHA-256 digest, bounded request metadata, host/method/status summaries, timing totals and evidence-linked review findings. It does not export request or response bodies, header values, cookie values or query parameter values. Shared operating-system temporary-directory paths are rejected; copy captures into a private workspace before analysis. URL paths and server IP addresses can still be sensitive; review reports before sharing. HAR observations describe the supplied capture, not independently verified live traffic. The same analyzer is available as the public API and the workspace-confined `orix.analyze_har` MCP tool.

See [Platform Expansion](docs/PLATFORM_EXPANSION.md) for the engineering plan covering Android, Electron/JavaScript, .NET, decompilation, firmware, browser observations and replayable AI/RL environments.

## Local report explorer

Open saved artifact, directory-scan, project, Rizin-import, Rizin-function/disassembly, WebAssembly-symbol and provider-diagnostic JSON reports in ORIX's browser-local viewer. It includes inventory search, severity/format filters, summary charts, record details and CSV export for findings, imported symbols and WebAssembly names. Report contents stay in the browser.

```bash
npm run web
# Open http://127.0.0.1:4173
```

Set `ORIX_WEB_PORT` to select another port. The server binds only to `127.0.0.1`, serves a fixed asset allowlist and disables network connections through Content Security Policy. See [the viewer guide](docs/WEB_VIEWER.md).

When the package is installed globally or linked locally, the `orix` command is exposed through `package.json#bin`:

```bash
npm install --global .
orix help
```

## CLI reference

See [`docs/MCP.md`](docs/MCP.md) for the local MCP server, tool schemas and workspace security model.

### `inspect`

```text
orix inspect <file> [--json|--markdown|--format sarif] [--out <path>]
                  [--no-strings] [--strings-limit <n>]
                  [--max-read-mib <n>] [--max-file-mib <n>]
```

The inspector rejects directories, symlinks, non-regular files, files larger than the configured cap, and files whose identity changes during acquisition. It hashes the complete file incrementally, then parses at most the configured prefix. If the file is larger than the parse window, `analysis_complete_for_file` is `false` and the report says so.

### `scan`

```text
orix scan <directory> [--json|--markdown|--format sarif] [--out <path>]
                 [--max-files <n>] [--max-directories <n>] [--max-entries <n>] [--max-depth <n>]
                 [--max-read-mib <n>] [--max-file-mib <n>]
                 [--concurrency <n>] [--no-strings]
```

Traversal is deterministic and does not follow symlinks. Common generated/dependency directories (`.git`, `node_modules`, `dist`, `build`, `.next`, and others) are excluded by default. A scan report records discovered files, skipped entries, errors, byte totals, format distribution, limits, and whether inventory was truncated.

### `compare`

```text
orix compare <baseline-report.json> <current-report.json> [--json|--markdown] [--out <path>]
```

Comparison classifies added, removed, modified and unchanged artifacts by normalized report-relative path and SHA-256. Project reports can be exported with `--format cyclonedx` as a CycloneDX 1.5 SBOM. Supported npm, Yarn, pnpm, Cargo, Composer and Ruby lockfiles contribute resolved package versions and dependency relationships; Go `go.sum` contributes module checksums and direct root links but no transitive graph; projects without supported lockfiles fall back to declared dependencies. It also reports introduced/resolved static indicators. Renames appear as removal plus addition; the command compares supplied snapshots and does not access original artifact trees.

### Reports and safe output files

Use `--format json` or `--json` for automation, `--format sarif` for GitHub code-scanning-compatible static findings, and Markdown for review and sharing. SARIF is supported by `inspect`, `scan` and `project`. Project SARIF exports redacted source findings with file and line locations; matched credential values are never copied into SARIF messages or properties. `--out` creates a new report file with restrictive permissions; it refuses to overwrite an existing path. Report output is not written into the target artifact or directory unless the caller explicitly names that location.

## MCP server

ORIX includes an optional stdio Model Context Protocol server. It exposes bounded artifact inspection, directory/project scans, format capabilities, report comparison, and workspace-confined evidence-ledger operations.

```bash
node ./src/mcp.mjs
```

Configure workspace roots with `ORIX_MCP_ROOTS` (path-delimited). If unset, the process working directory is the only workspace root. The transport caps input frames at 4 MiB and tool responses at 2 MiB. See [MCP integration](docs/MCP.md).

## Programmatic API

The public API is exported from `src/index.mjs` and declared in `package.json#exports`.

```js
import {
  inspect_file,
  scan_directory,
  parse_pe,
  parse_elf,
  calculate_entropy,
  extract_strings,
  render_inspection_markdown,
} from '@orix/cli';

const artifact = await inspect_file('./sample.bin', {
  limits: {
    max_file_bytes: 64 * 1024 * 1024,
    max_read_bytes: 8 * 1024 * 1024,
    max_strings: 500,
  },
});

console.log(artifact.detection.format);
console.log(artifact.integrity.digest);
console.log(artifact.indicators);
console.log(render_inspection_markdown(artifact));

const inventory = await scan_directory('./artifacts', {
  limits: { max_scan_files: 2_000, max_scan_concurrency: 3 },
});
console.log(inventory.scan.formats);
```

All parser entry points accept a `Buffer` and return plain JSON-compatible data. Malformed input is represented by typed `OrixError` values at direct parser boundaries; the format dispatcher preserves detection metadata and returns a structured parser rejection instead of losing the original signature result.

## Static indicator layer

Every artifact report includes an `indicators` array. The current rules are transparent and deterministic:

| Rule family | What is surfaced | Why it is not a verdict |
|---|---|---|
| PE section permissions | Sections marked both writable and executable | Some runtimes and specialized binaries legitimately use this combination |
| PE section ranges | Raw section ranges outside the analyzed bytes | Truncation and unsupported layouts can produce structural mismatches |
| ZIP entry metadata | Absolute paths, parent traversal, symbolic-link markers and encrypted entries | Risk depends on how another program handles extraction; ORIX does not extract |
| Entropy | Samples at or above 7.2 bits/byte with at least 1 KiB of data | Compression and encryption commonly have high entropy |
| Selected API strings | Exact names associated with process-memory or credential-access APIs | A string does not prove an import, call or behavior |
| Acquisition/parser state | Parser rejection and file metadata changes during reading | These are quality and integrity warnings, not maliciousness findings |

Findings carry a stable `rule_id`, severity, confidence and bounded supporting evidence. The scan command aggregates findings by severity and counts files that produced at least one result. Full trigger logic and false-positive notes live in [`docs/INDICATORS.md`](docs/INDICATORS.md). Versioned JSON Schema documents are in [`schemas/`](schemas/).

A report with no indicators means only that the current built-in rules did not match. It does not certify an artifact as safe.

## Architecture

```text
CLI / Programmatic API
        │
        ├── Argument validation and command dispatch
        │
        ├── Analyzer
        │     ├── bounded directory walker
        │     └── bounded concurrent scan
        │
        ├── Core
        │     ├── file identity and acquisition checks
        │     ├── streaming SHA-256
        │     ├── binary reader and typed errors
        │     ├── entropy and strings
        │     ├── deterministic static indicator rules
        │     ├── limits and evidence provenance
        │     └── report schema assembly
        │
        ├── Format registry and parsers
        │     ├── PE / COFF
        │     ├── ELF
        │     ├── thin Mach-O
        │     ├── WebAssembly
        │     └── PDF (classic xref + object index)
        │
        └── JSON / Markdown / SARIF 2.1 renderers
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for ownership boundaries, data flow and extension rules; [`docs/PROVIDERS.md`](docs/PROVIDERS.md) for static provider execution; [`docs/FORMATS.md`](docs/FORMATS.md) for parser coverage; and [`docs/INDICATORS.md`](docs/INDICATORS.md) for every built-in static triage rule.

## Evidence, not unsupported certainty

Every report separates direct observations from interpretation. Static indicators are rule-addressable findings with explicit severity and confidence; evidence remains attached to the exact input feature that triggered the rule:

- **Observed**: directly read from the file, such as a signature or hash.
- **Derived**: calculated from observed bytes, such as a parsed section table.
- **Heuristic**: a pattern-based suggestion that requires independent validation.

Evidence records retain a source path and, when meaningful, byte offsets and lengths. Missing, malformed, unsupported and truncated data are represented explicitly. ORIX does not convert a failed parse into a confident conclusion.

## Safety model

ORIX's built-in parsers and indicators are static and read-only: they do not execute the inspected sample, load its libraries, attach to its processes, inject code, or modify the artifact. An operator may separately opt into a declared-static external analysis engine such as Rizin; ORIX launches that provider process with a fixed argument vector, timeout and output ceiling. The process runner is not an OS sandbox and cannot enforce a provider's declared filesystem or network behavior. Do not run an untrusted provider executable on a sensitive host. It does not label a file safe or malicious solely from entropy, strings, a file extension or a header signature.

Built-in indicators never execute a sample. API-name matches can be false positives, high entropy can mean ordinary compression, and a writable/executable section can have legitimate uses. Rule output must be independently reviewed.

The input path is treated as untrusted. File size, prefix size, scan depth, file count, concurrency, parser section counts and retained strings are bounded. Symlinks are rejected by the file inspector and skipped during directory traversal. See [`SECURITY.md`](SECURITY.md) and [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).

Use ORIX only on software and systems you own or are authorized to examine. Dynamic analysis, if introduced later, must be an explicit opt-in subsystem with process ownership checks, isolation, resource ceilings, cleanup guarantees and separate evidence provenance.

## Development

```bash
npm ci
npm run check
npm test
npm run test:coverage
```

GitHub Actions validates Node.js 20, 22 and 24 on Linux, runs Windows and macOS smoke suites on Node.js 22, checks syntax, runs the full test suite, and generates Linux coverage on Node.js 22. A separate scheduled CodeQL `security-extended` workflow analyzes JavaScript/TypeScript; Dependabot checks npm and GitHub Actions dependencies.

The test suite includes handcrafted PE32/PE32+ fixtures with bounded import/export tables, ELF64, thin Mach-O, WebAssembly and classic PCAP and PCAPNG block fixtures; malformed-header and RVA boundaries; string extraction; evidence semantics; symlink handling; directory traversal; project-intelligence regression cases; and real CLI JSON output. The fixtures are generated as small byte buffers at test time and are not executable samples.

Before adding a parser:

1. Define the format's accepted magic, class, byte order and version behavior.
2. Use `BinaryReader` for bounds-checked access; do not scatter unchecked offsets.
3. Bound record counts and validate all offset/length arithmetic before iterating.
4. Preserve raw values and explicit unknown states; do not silently normalize away information.
5. Return parser limitations alongside decoded fields.
6. Add tests for valid minimal input, truncated input, out-of-range tables, count limits and both supported byte orders where applicable.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for source ownership and review expectations.

## Roadmap

The long-term direction includes richer format support, disassembly/decompiler adapters, a persistent case database, plugin contracts, a desktop/web interface and isolated dynamic-analysis providers. The local MCP interface, repository intelligence, evidence ledger and current interchange workflows are implemented vertical slices; see the roadmap for remaining boundaries. The near-term plan is broken into measurable vertical slices in [`docs/ROADMAP.md`](docs/ROADMAP.md). The upstream capability comparison and adapter priorities are maintained in [`docs/COMPETITIVE_LANDSCAPE.md`](docs/COMPETITIVE_LANDSCAPE.md); provider metadata contracts are defined in [`schemas/provider-manifest.v1.schema.json`](schemas/provider-manifest.v1.schema.json) and documented in [`docs/PROVIDERS.md`](docs/PROVIDERS.md).

## License

ORIX is distributed under the Apache License 2.0. See [`LICENSE`](LICENSE). Third-party engines and format specifications retain their own licensing and attribution requirements; integrations will remain optional and adapter-based.

## Repository and source intelligence (0.3.0)

ORIX includes a bounded `project` command. It inventories a local source tree, classifies common languages, reads selected dependency manifests, extracts source-level import and symbol candidates, resolves conservative local import edges, and emits a versioned project report.

~~~bash
node src/cli.mjs project ./my-repository
node src/cli.mjs project ./my-repository --json
node src/cli.mjs project ./my-repository --json --out ./project-report.json
~~~

The scanner recognizes npm-compatible `package.json`, Python `requirements.txt` and basic `pyproject.toml`, Cargo, Go modules, Composer, Maven, NuGet and Gemfile declarations. It does not install dependencies, execute scripts, run builds or tests, query package registries, or claim vulnerability status. Source parsing is syntax-pattern based, not a compiler front-end.

A small set of credential-shaped patterns is reported with file and line metadata; matched values are never included in the report. False positives require manual review. Traversal, file, byte, symbol and import work is bounded. Symlinks are skipped, generated/dependency directories are excluded, and reports mark incomplete coverage when limits are reached. See [Project Intelligence](docs/PROJECT_INTELLIGENCE.md).


## Persistent evidence ledger

ORIX can append compact inspection, scan and project records to a local SHA-256 hash-chained JSONL ledger. Use `orix inspect ./sample.exe --ledger ./.orix/evidence.jsonl` to record an inspection. Verify the chain with `orix ledger verify ./.orix/evidence.jsonl` or list verified records with `orix ledger list ./.orix/evidence.jsonl`.

The ledger detects content changes, broken ordering and partial writes. It is tamper-evident, not tamper-proof: it is not a digital signature, trusted timestamp authority, remote transparency log or write-once medium.


### Provider process allowlists and execution receipts

`run_static_provider()` accepts `allowed_executables` and `allowed_working_directories` arrays. When omitted, the exact executable and cwd already selected by the caller become single-entry allowlists; when supplied, each entry is canonicalized and checked, and symlinked entries are rejected. The child receives a minimal environment. Explicit overrides reject command-search and executable-loader variables such as `PATH`, `NODE_OPTIONS`, `LD_PRELOAD`, and `DYLD_INSERT_LIBRARIES`. Each run includes a versioned `orix.provider-execution.v1` receipt while preserving the Rizin adapter's existing result fields. These controls are not filesystem or network sandboxing.
