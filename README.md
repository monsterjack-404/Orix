# ORIX — Open Research & Intelligence eXplorer

**Understand. Analyze. Engineer.**

ORIX is a local-first engineering intelligence workbench for inspecting software artifacts, reconstructing file-format structure, and preserving the evidence behind every conclusion. It is designed as a serious, extensible foundation for authorized reverse engineering and software research—not a wrapper that hides its methods and not a collection of aspirational feature folders.

> Current release line: **0.2.0 — Artifact Intelligence Core**  
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
| PE parser | PE32/PE32+ fixed headers, machine, subsystem, DLL flags, data directories and section records | Does not resolve imports, relocations or virtual-memory mappings |
| ELF parser | ELF32/ELF64 identification, endianness, core header fields and bounded section records with names | Program-header records are range-checked, not decoded into load segments |
| Mach-O parser | Thin 32-bit/64-bit header and bounded load-command framing | Does not expand universal containers or decode command-specific payloads |
| WebAssembly parser | Module version, bounded section framing and custom section names | Does not validate instruction semantics or decompile code |
| Static metrics | Shannon entropy, ASCII/UTF-16LE string extraction and bounded hex preview | Metrics are descriptive, not malware verdicts |
| Evidence model | Stable evidence records with source, offsets, confidence and structured details | Evidence is local to the generated report; no database is required |
| Directory scan | Deterministic traversal, ignored build/dependency folders, no symlink following, bounded concurrency | No distributed scanning or filesystem watcher |
| Reports | JSON and Markdown for single-file and directory results | No hosted dashboard yet |

Formats without a parser are still identified where their signatures are recognized. They are reported as `not-supported`, rather than pretending that a header was decoded.

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
```

When the package is installed globally or linked locally, the `orix` command is exposed through `package.json#bin`:

```bash
npm install --global .
orix help
```

## CLI reference

### `inspect`

```text
orix inspect <file> [--json|--markdown] [--out <path>]
                  [--no-strings] [--strings-limit <n>]
                  [--max-read-mib <n>] [--max-file-mib <n>]
```

The inspector rejects directories, symlinks, non-regular files, files larger than the configured cap, and files whose identity changes during acquisition. It hashes the complete file incrementally, then parses at most the configured prefix. If the file is larger than the parse window, `analysis_complete_for_file` is `false` and the report says so.

### `scan`

```text
orix scan <directory> [--json|--markdown] [--out <path>]
                 [--max-files <n>] [--max-directories <n>] [--max-entries <n>] [--max-depth <n>]
                 [--max-read-mib <n>] [--max-file-mib <n>]
                 [--concurrency <n>] [--no-strings]
```

Traversal is deterministic and does not follow symlinks. Common generated/dependency directories (`.git`, `node_modules`, `dist`, `build`, `.next`, and others) are excluded by default. A scan report records discovered files, skipped entries, errors, byte totals, format distribution, limits, and whether inventory was truncated.

### Reports and safe output files

Use `--format json` or `--json` for automation. Use Markdown for review and sharing. `--out` creates a new report file with restrictive permissions; it refuses to overwrite an existing path. Report output is not written into the target artifact or directory unless the caller explicitly names that location.

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
console.log(render_inspection_markdown(artifact));

const inventory = await scan_directory('./artifacts', {
  limits: { max_scan_files: 2_000, max_scan_concurrency: 3 },
});
console.log(inventory.scan.formats);
```

All parser entry points accept a `Buffer` and return plain JSON-compatible data. Malformed input is represented by typed `OrixError` values at direct parser boundaries; the format dispatcher preserves detection metadata and returns a structured parser rejection instead of losing the original signature result.

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
        │     ├── limits and evidence provenance
        │     └── report schema assembly
        │
        ├── Format registry and parsers
        │     ├── PE / COFF
        │     ├── ELF
        │     ├── thin Mach-O
        │     └── WebAssembly
        │
        └── JSON / Markdown renderers
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for ownership boundaries, data flow and extension rules. See [`docs/FORMATS.md`](docs/FORMATS.md) for parser coverage and known limitations.

## Evidence, not unsupported certainty

Every report separates direct observations from interpretation:

- **Observed**: directly read from the file, such as a signature or hash.
- **Derived**: calculated from observed bytes, such as a parsed section table.
- **Heuristic**: a pattern-based suggestion that requires independent validation.

Evidence records retain a source path and, when meaningful, byte offsets and lengths. Missing, malformed, unsupported and truncated data are represented explicitly. ORIX does not convert a failed parse into a confident conclusion.

## Safety model

ORIX's current analysis pipeline is static and read-only. It does not execute samples, load target libraries, attach to processes, inject code, alter binaries, bypass access controls, harvest credentials, persist in a host, or contact remote infrastructure. It does not label a file safe or malicious solely from entropy, strings, a file extension or a header signature.

The input path is treated as untrusted. File size, prefix size, scan depth, file count, concurrency, parser section counts and retained strings are bounded. Symlinks are rejected by the file inspector and skipped during directory traversal. See [`SECURITY.md`](SECURITY.md) and [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).

Use ORIX only on software and systems you own or are authorized to examine. Dynamic analysis, if introduced later, must be an explicit opt-in subsystem with process ownership checks, isolation, resource ceilings, cleanup guarantees and separate evidence provenance.

## Development

```bash
npm ci
npm run check
npm test
npm run test:coverage
```

The test suite includes handcrafted PE32/PE32+, ELF64, thin Mach-O and WebAssembly fixtures; malformed-header boundaries; string extraction; evidence semantics; symlink handling; directory traversal; and real CLI JSON output. The fixtures are generated as small byte buffers at test time and are not executable samples.

Before adding a parser:

1. Define the format's accepted magic, class, byte order and version behavior.
2. Use `BinaryReader` for bounds-checked access; do not scatter unchecked offsets.
3. Bound record counts and validate all offset/length arithmetic before iterating.
4. Preserve raw values and explicit unknown states; do not silently normalize away information.
5. Return parser limitations alongside decoded fields.
6. Add tests for valid minimal input, truncated input, out-of-range tables, count limits and both supported byte orders where applicable.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for source ownership and review expectations.

## Roadmap

The long-term direction includes richer format support, disassembly/decompiler adapters, a local evidence store, repository intelligence, plugin contracts, MCP integration, a desktop/web interface and isolated dynamic-analysis providers. Those are roadmap items, not implemented features. The near-term plan is broken into measurable vertical slices in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## License

ORIX is distributed under the Apache License 2.0. See [`LICENSE`](LICENSE). Third-party engines and format specifications retain their own licensing and attribution requirements; integrations will remain optional and adapter-based.
