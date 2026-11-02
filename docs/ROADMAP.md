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
- Deterministic static indicator rules with severity, confidence, rule IDs and supporting evidence.
- Aggregated indicator counts in directory scans.
- Malformed input, parser, indicator, report, filesystem and CLI integration tests.

## 0.3 — Repository and Source Intelligence

**Status: first vertical slice implemented**

- Deterministic local project inventory with symlink rejection and bounded traversal.
- Language classification and per-file SHA-256 identity.
- Selected dependency manifests for npm, Python, Cargo, Go, Composer, Maven, NuGet and Ruby.
- Dependency declaration inventory, script metadata and source-manifest provenance.
- Best-effort source import extraction, local import edges and symbol candidates.
- Project structure signals for README, license, CI, tests and container files.
- Redacted credential-shaped indicators and versioned project report schema.

**Remaining:** lockfile transitive graph parsing, compiler-backed symbol resolution, incremental cache, workspace persistence and deeper language parsers.

**Exit criteria:** deterministic results, explicit coverage, cache invalidation tests and no implicit build or package scripts.

## 0.4 — Structural Analysis Expansion

**Status: PE and ELF structural-analysis slices implemented; other format work remains planned.**

- [x] PE import/export tables and file-backed RVA mapping, including named/ordinal imports, named exports and forwarded-export markers.
- [x] PE resource directory traversal and WIN_CERTIFICATE record framing.
- [ ] Base relocations, CLR metadata and Authenticode trust verification.
- [x] ELF program headers, PT_INTERP, PT_DYNAMIC tags, GNU build identifiers, symbol tables and REL/RELA relocation records.
- [ ] Extended ELF numbering, GNU symbol-version resolution and DWARF decoding.
- [x] Mach-O FAT/FAT64 architecture tables, bounded slices, segment/section commands and CodeDirectory metadata.
- [ ] Chained fixups, cryptographic trust verification and Objective-C metadata.
- ZIP64 parser, decompression-bomb safeguards and safe entry streaming; no extraction by default.
- PDF object and cross-reference parser with object-count and recursion budgets.
- Versioned JSON Schema documents and golden report fixtures.

**Exit criteria:** each parser has valid and malformed fixtures, explicit unsupported cases, resource bounds, and format documentation. Fuzz harnesses must demonstrate bounded failures before release.

## 0.4 — Repository and Project Intelligence

- Git repository inventory without executing project hooks.
- Language and build-system detection based on bounded manifests.
- Dependency graph and lockfile analysis with ecosystem-specific parsers.
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

- Tool catalog generated from typed operation contracts.
- MCP server exposing artifact, project and evidence workflows.
- Compact and full argument profiles with canonical server validation.
- Pagination, cancellation and report-size budgets.
- Prompt-injection-resistant handling of strings and metadata extracted from artifacts.

**Exit criteria:** tool schemas validate against the selected MCP dialect; every advertised tool has integration tests and real, documented behavior.

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
