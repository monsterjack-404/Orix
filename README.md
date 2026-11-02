# ORIX — Open Research & Intelligence eXplorer

**Understand. Analyze. Engineer.**

ORIX is a local-first engineering intelligence workbench for inspecting software artifacts, reconstructing file-format structure, and preserving the evidence behind every conclusion. It is designed as a serious, extensible foundation for authorized reverse engineering and software research—not a wrapper that hides its methods and not a collection of aspirational feature folders.

> Current release line: **0.5.0 — Artifact, Project, Evidence, Interchange + MCP Intelligence**  
> Runtime: **Node.js 20.11 or newer**  
> Dependencies: **Node.js built-ins only**  
> Execution model: **local, static, read-only analysis**

---

## What exists today

This repository contains working source code, bounded parsers, a usable CLI, programmatic exports, integration tests, and a CI workflow. The implemented surface is intentionally narrower than the long-term product vision; each capability below is tied to code and tests in this repository.

| Subsystem | Implemented behavior | Current boundary |
|---|---|---|
| Artifact intake | Regular-file validation, symlink rejection, size ceilings, bounded prefix reads | Does not acquire files from remote locations |
| Integrity | Streaming SHA-256 over the complete file using a bounded buffer | Does not authenticate the publisher or establish trust |
| Format registry | Signature recognition for ELF, PE/MZ, Mach-O, universal Mach-O, WebAssembly, PDF, PNG, JPEG, SQLite and GZIP | Signature recognition is not a complete format parser |
| PE parser | PE32/PE32+ headers, data directories, section records, file-backed RVA mapping, normal and delay-import DLLs with name/ordinal thunks, named/ordinal exports, resource trees, WIN_CERTIFICATE framing, delay imports and base-relocation records | Relocation application, CLR metadata and Authenticode trust verification are not implemented |
| ELF parser | ELF32/ELF64 headers, bounded program segments, PT_INTERP, PT_DYNAMIC tags, GNU build IDs, symbol tables, REL/RELA relocation records and GNU symbol-version requirements/definitions, VERSYM mappings and bounded GNU hash bloom/bucket/chain tables | Does not apply relocations or decode DWARF |
| Mach-O parser | Thin and FAT/FAT64 universal images, per-slice parsing, segment/section commands, LC_SYMTAB symbols, LC_DYSYMTAB groups/indirect symbols and CodeDirectory metadata | Does not cryptographically verify signatures or decode chained fixups and Objective-C metadata |
| ZIP parser | ZIP32/ZIP64 central-directory indexing, extended entry sizes and offsets, unsafe path and symlink metadata | Multi-disk archives, extraction, decompression and CRC verification are not implemented |
| PDF parser | Classic xref tables, trailer metadata, incremental /Prev chain, indirect-object framing, encryption and active-content marker triage | Xref-stream entries, object streams, filters, attachment extraction, page-tree semantics and signature verification are not implemented |
| WebAssembly parser | Module version, bounded section framing and custom section names | Does not validate instruction semantics or decompile code |
| Static metrics | Shannon entropy, ASCII/UTF-16LE string extraction and bounded hex preview | Metrics are descriptive, not malware verdicts |
| Static indicators | Explainable rules for PE writable/executable sections, invalid ranges, ZIP unsafe entries, encryption flags, high entropy, selected API-name strings, parser rejection and acquisition instability | Heuristics are review leads, not malware classifications or proof of execution |
| Evidence model | Stable report evidence plus append-only SHA-256 chained JSONL ledger, verify/list commands and append receipts | Not a signature, trusted timestamp or external transparency log |
| Directory scan | Deterministic traversal, ignored build/dependency folders, no symlink following, bounded concurrency | No distributed scanning or filesystem watcher |
| MCP integration | Local stdio JSON-RPC server with eight typed tools for inspect, scan, project, formats, comparison and evidence ledger | No HTTP listener, remote auth, resource subscription or prompt catalog |
| Reports | JSON, Markdown, SARIF 2.1.0, report comparison and CycloneDX 1.5 SBOM | No hosted dashboard or relational database |

Static indicator rules operate only on already-parsed metadata and bounded extracted strings. Each finding includes a rule ID, severity, confidence and supporting evidence. A clean report means only that the built-in rules did not match; it is not a safety certification.

Formats without a parser are still identified where their signatures are recognized. They are reported as `not-supported`, rather than pretending that a header was decoded.

## Repository intelligence

The `project` command builds a bounded source and manifest index without running project scripts, builds or tests:

```bash
node src/cli.mjs project ./source-tree
node src/cli.mjs project ./source-tree --json
node src/cli.mjs project ./source-tree --format cyclonedx --out ./sbom.cdx.json
```

It records file hashes, language counts, selected dependency declarations, npm package-lock v1-v3, Yarn classic/Berry, pnpm v5/v6/v9, Cargo.lock v3/v4 and Composer.lock resolved package graphs, source import edges, symbol candidates, redacted credential-shaped findings and bounded Git repository metadata (refs, tags, sanitized remotes and loose HEAD commit identity). Packed Git objects and linked-worktree gitdir targets are not decoded or followed. CycloneDX export includes resolved lockfile components and package relationships when supported lockfiles are present; otherwise it reports declared dependencies only. See [`docs/PROJECT_INTELLIGENCE.md`](docs/PROJECT_INTELLIGENCE.md) for parser boundaries and resource limits.

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

# Start local MCP stdio server
npm run mcp

# Compare saved reports
node src/cli.mjs compare ./baseline.json ./current.json --json

# Append and verify an evidence record
node src/cli.mjs inspect ./sample.exe --ledger ./.orix/evidence.jsonl
node src/cli.mjs ledger verify ./.orix/evidence.jsonl
```

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

Comparison classifies added, removed, modified and unchanged artifacts by normalized report-relative path and SHA-256. Project reports can be exported with `--format cyclonedx` as a CycloneDX 1.5 SBOM. Supported npm, Yarn, pnpm, Cargo and Composer lockfiles contribute resolved package versions and dependency relationships; Go `go.sum` contributes module checksums and direct root links but no transitive graph; projects without supported lockfiles fall back to declared dependencies. It also reports introduced/resolved static indicators. Renames appear as removal plus addition; the command compares supplied snapshots and does not access original artifact trees.

### Reports and safe output files

Use `--format json` or `--json` for automation, `--format sarif` for GitHub code-scanning-compatible static findings, and Markdown for review and sharing. SARIF is supported by `inspect` and `scan`; project reports remain JSON/Markdown. `--out` creates a new report file with restrictive permissions; it refuses to overwrite an existing path. Report output is not written into the target artifact or directory unless the caller explicitly names that location.

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

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for ownership boundaries, data flow and extension rules; [`docs/FORMATS.md`](docs/FORMATS.md) for parser coverage; and [`docs/INDICATORS.md`](docs/INDICATORS.md) for every built-in static triage rule.

## Evidence, not unsupported certainty

Every report separates direct observations from interpretation. Static indicators are rule-addressable findings with explicit severity and confidence; evidence remains attached to the exact input feature that triggered the rule:

- **Observed**: directly read from the file, such as a signature or hash.
- **Derived**: calculated from observed bytes, such as a parsed section table.
- **Heuristic**: a pattern-based suggestion that requires independent validation.

Evidence records retain a source path and, when meaningful, byte offsets and lengths. Missing, malformed, unsupported and truncated data are represented explicitly. ORIX does not convert a failed parse into a confident conclusion.

## Safety model

ORIX's current analysis pipeline is static and read-only. It does not execute samples, load target libraries, attach to processes, inject code, alter binaries, bypass access controls, harvest credentials, persist in a host, or contact remote infrastructure. It does not label a file safe or malicious solely from entropy, strings, a file extension or a header signature.

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

The test suite includes handcrafted PE32/PE32+ fixtures with bounded import/export tables, ELF64, thin Mach-O and WebAssembly fixtures; malformed-header and RVA boundaries; string extraction; evidence semantics; symlink handling; directory traversal; project-intelligence regression cases; and real CLI JSON output. The fixtures are generated as small byte buffers at test time and are not executable samples.

Before adding a parser:

1. Define the format's accepted magic, class, byte order and version behavior.
2. Use `BinaryReader` for bounds-checked access; do not scatter unchecked offsets.
3. Bound record counts and validate all offset/length arithmetic before iterating.
4. Preserve raw values and explicit unknown states; do not silently normalize away information.
5. Return parser limitations alongside decoded fields.
6. Add tests for valid minimal input, truncated input, out-of-range tables, count limits and both supported byte orders where applicable.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for source ownership and review expectations.

## Roadmap

The long-term direction includes richer format support, disassembly/decompiler adapters, a persistent case database, plugin contracts, a desktop/web interface and isolated dynamic-analysis providers. The local MCP interface, repository intelligence, evidence ledger and current interchange workflows are implemented vertical slices; see the roadmap for remaining boundaries. The near-term plan is broken into measurable vertical slices in [`docs/ROADMAP.md`](docs/ROADMAP.md).

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
