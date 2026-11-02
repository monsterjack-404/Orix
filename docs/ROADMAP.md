# ORIX Roadmap

This roadmap is a sequence of testable product capabilities, not a promise that every item already exists. Work is accepted into the implemented status only when source, tests, docs and CI agree.

## Release 0.2.x — Artifact Intelligence Core

**Status: implemented in this repository**

- Local CLI and public programmatic entry points.
- Signature registry for common executable, archive, document, image and database formats.
- Bounded PE32/PE32+, ELF, thin Mach-O, WebAssembly and ZIP structural parsing.
- Streaming SHA-256, entropy, bounded string extraction and evidence records.
- Symlink-safe directory inventory and bounded concurrent inspection.
- JSON and Markdown report renderers.
- SARIF 2.1.0 renderer for artifact and directory-scan findings, with rule metadata, severity mapping, byte ranges and artifact hashes.
- Deterministic static indicator rules with severity, confidence, rule IDs and supporting evidence.
- Aggregated indicator counts in directory scans.
- Hash-chained append-only evidence ledger with writer lock, bounded records, tamper detection and verify/list commands.
- SARIF 2.1.0 output for artifact and directory-scan findings.
- Baseline/current report comparison with artifact change classes and indicator deltas.
- CycloneDX 1.5 SBOM export from recognized direct dependency declarations, package URLs and manifest provenance.
- Malformed input, parser, indicator, report, filesystem and CLI integration tests.

## 0.3 — Repository and Source Intelligence

**Status: first vertical slice implemented**

- Deterministic local project inventory with symlink rejection and bounded traversal.
- Language classification and per-file SHA-256 identity.
- Selected dependency manifests for npm, Python, Cargo, Go, Composer, Maven, NuGet and Ruby.
- Dependency declaration inventory, script metadata and source-manifest provenance.
- [x] Bounded npm package-lock v1-v3, Yarn classic/Berry and Cargo.lock v1-v4 inventory with resolved package identities, integrity metadata and dependency edges.
- [x] CycloneDX 1.5 export consumes lockfile-resolved packages and package-to-package relationships when lockfiles are present.
- Best-effort source import extraction, local import edges and symbol candidates.
- Project structure signals for README, license, CI, tests and container files.
- Redacted credential-shaped indicators and versioned project report schema.

**Remaining:** pnpm/Cargo/Composer/Python/Go lockfile parsers, compiler-backed symbol resolution, incremental cache, workspace persistence and deeper language parsers.

**Exit criteria:** deterministic results, explicit coverage, cache invalidation tests and no implicit build or package scripts.

## 0.4 — Structural Analysis Expansion

**Status: PE, ELF, Mach-O and ZIP64 structural-analysis slices implemented; other format work remains planned.**

- [x] PE import/export tables and file-backed RVA mapping, including named/ordinal imports, named exports and forwarded-export markers.
- [x] PE resource directory traversal and WIN_CERTIFICATE record framing.
- [x] PE base-relocation block and entry parsing (metadata only; no relocation application).
- [ ] CLR metadata and Authenticode trust verification.
- [x] ELF program headers, PT_INTERP, PT_DYNAMIC tags, GNU build identifiers, symbol tables and REL/RELA relocation records.
- [x] GNU version requirements, definitions and version-symbol table mapping.
- [x] GNU hash bloom filters, bucket arrays and terminal-bit chain decoding with aggregate work limits.
- [ ] Extended ELF numbering and DWARF decoding.
- [x] Mach-O FAT/FAT64 architecture tables, bounded slices, segment/section commands, bounded LC_SYMTAB nlist decoding, LC_DYSYMTAB symbol groups/indirect entries and CodeDirectory metadata.
- [ ] Chained fixups, cryptographic trust verification and Objective-C metadata.
- [x] ZIP64 EOCD/locator and per-entry extended size/offset parsing with safe-integer and central-directory bounds.
- [ ] Decompression-bomb safeguards and bounded safe entry streaming; extraction remains opt-in.
- [x] Deterministic malformed-input mutation and truncation smoke corpus for all registered binary parsers.
- [x] PDF classic xref tables, trailer metadata, bounded incremental /Prev chain, xref-stream recognition and indirect-object index with explicit active-content triage; compressed xref/object streams remain unsupported.
- Versioned JSON Schema documents and golden report fixtures.
- [x] SARIF 2.1.0 export and baseline/current report comparison.
- [x] SARIF 2.1.0 export for artifact and directory reports.

**Exit criteria:** each parser has valid and malformed fixtures, explicit unsupported cases, resource bounds, and format documentation. Fuzz harnesses must demonstrate bounded failures before release.

## 0.4 — Repository and Project Intelligence

- Git repository inventory without executing project hooks.
- Language and build-system detection based on bounded manifests.
- [x] npm package-lock v1-v3 and Yarn classic/Berry dependency graph analysis.\n- [ ] pnpm, Cargo, Composer, Python and Go lockfile parsers.
- Source symbol index and cross-reference model.
- Architecture map assembled from observed files and declared dependencies.
- Incremental cache keyed by content hash, parser version and analysis options.

**Exit criteria:** deterministic results, explicit coverage, cache invalidation tests and no implicit build or package scripts.

## 0.5 — Analysis Providers and Disassembly Adapters

- Capability interface for optional Ghidra, IDA, Hopper and other licensed/installed engines.
- Provider version probing, health state, timeouts and structured diagnostics.
- Function, symbol, callgraph and disassembly evidence contracts.
- External process ownership, cancellation and cleanup tests.
- Offline mode and provider-free operation as first-class paths.

**Exit criteria:** adapters are opt-in, respect upstream licenses, never claim a provider ran when it did not, and preserve exact tool/version provenance.

## 0.6 — Evidence Store and Workspaces

- SQLite-backed local artifact and evidence store.
- Content-addressed artifact identity and immutable analysis runs.
- Search, comparison, annotations and exportable case bundles.
- Schema migrations, recovery and database integrity checks.
- Workspace-level access and retention controls.

**Exit criteria:** interrupted writes recover safely; evidence can be exported and validated without the database.

## 0.7 — Agent and MCP Interface

**Status: local stdio tools vertical slice implemented; protocol expansion remains planned**

- [x] JSON-RPC stdio server with MCP 2025-03-26 initialize, ping, tools/list and tools/call.
- [x] Workspace-confined artifact, directory, project, format, comparison and evidence-ledger tools.
- [x] Tool argument contracts, path checks, no-follow report reads and input/output byte budgets.
- [ ] Tool catalog generated from typed operation contracts.
- [x] MCP server exposing artifact, project, comparison and evidence workflows.
- [ ] HTTP transport, resource/prompt subscriptions and remote authentication.
- Compact and full argument profiles with canonical server validation.
- Pagination, cancellation and report-size budgets.
- Prompt-injection-resistant handling of strings and metadata extracted from artifacts.

**Exit criteria:** tool schemas validate against the selected MCP dialect; every advertised tool has integration tests and real, documented behavior. The current stdio slice is not a remote service.

## 0.8 — Desktop and Web Workspace

- Desktop shell with local-first storage.
- Artifact overview, parser views, evidence timeline and project graph.
- Keyboard-accessible navigation, virtualization and large-report handling.
- Optional local API with explicit binding and authentication model.
- Import/export case workflows.

**Exit criteria:** installation, upgrades, storage migrations, accessibility and security review pass on supported operating systems.

## 0.9 — Isolated Runtime Observation

- Explicitly authorized dynamic observation in disposable environments.
- Snapshot, process and network observation providers.
- Enforced resource, duration and network policies.
- Cancellation and cleanup guarantees.
- Runtime evidence linked to static evidence without conflating confidence.

**Exit criteria:** isolation design review, threat model, failure-injection tests, provider ownership tests and documented containment limitations.

## 1.0 — Stable Platform

- Versioned public APIs and report schemas.
- Reproducible release artifacts and signed provenance.
- Supported operating-system matrix and long-term compatibility policy.
- Plugin SDK with capability and trust boundaries.
- Full documentation, migration guides and maintainer operations.

## Quality gates for every milestone

1. No empty placeholder modules advertised as features.
2. Every user-facing capability maps to source and tests.
3. Every untrusted-input loop has a resource ceiling.
4. Malformed, truncated and boundary-sized input is covered.
5. Coverage and parser limitations are explicit in reports.
6. CI checks syntax, tests and dependency/license changes.
7. No external project code or assets are copied without license and attribution review.
