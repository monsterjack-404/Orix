# ORIX Capability and Implementation Matrix

This file is the status ledger for product claims. It is deliberately conservative. “Implemented” means the current main-branch source and tests contain a working vertical slice; it does not mean the domain is complete. “Partial” means a useful slice exists with material scope limitations. “Planned” means the capability is not operational in the current repository.

**Baseline:** ORIX 0.5.0, feature branch `feat/ubi-volume-table-parser`, reviewed 2026-11-05.  
**Authority:** source + tests + current CI, not the project vision or README aspiration.

## Status vocabulary

- **Implemented:** behavior exists in source, has relevant tests and is documented.
- **Partial:** a bounded subset exists; major structures, workflows or platform behavior remain absent.
- **Planned:** no operational implementation is present in the current main branch.
- **Research required:** design/provider/license/compatibility review is a prerequisite; no commitment to a specific implementation.

## A. Runtime, repository and developer experience

| Capability | Status | Current evidence / boundary | Completion direction |
|---|---|---|---|
| Node.js CLI | Implemented | Command router, typed errors, JSON/Markdown outputs | Stable CLI compatibility and packaging |
| Public JS API | Implemented | src/index.mjs exports current services and parsers | Versioned API policy and consumer fixtures |
| Runtime dependency policy | Implemented | Node.js built-ins only; Node >=20.11 | Reassess dependencies individually |
| Public npm release | Planned | package.json marks package private | Package validation, tarball, provenance and release process |
| Cross-platform CI | Partial | Linux Node 20/22/24; Windows/macOS Node 22 smoke jobs | Expanded OS/runtime matrix and release gates |
| Syntax checks | Implemented | scripts/check-syntax.mjs | Keep CI enforced |
| Documentation consistency gate | Implemented | `npm run check` validates release, parser registry, format docs, MCP version and indicator-rule coverage | Expand contracts to capability registry and generated docs |
| Machine-readable capability inventory | Implemented | `orix capabilities --json`, public API and `orix.capabilities` MCP tool derive format and tool records from runtime registries | Expand registry coverage to generated CLI/report contracts and validate every output against the schema |
| Reproducible release artifacts | Planned | No signed release artifact pipeline or published version | Build provenance and signatures |
| Desktop installer / updater | Planned | No desktop shell | Architecture after stable workspace APIs |
| Telemetry | Not planned by default | Local-first privacy posture | Any opt-in telemetry needs explicit consent and minimization |

## B. Artifact and format intelligence

| Capability | Status | Current evidence / boundary | Completion direction |
|---|---|---|---|
| Safe regular-file intake | Implemented | Symlink rejection, regular-file checks, bounded reads | Stronger platform-specific race tests |
| Full-file SHA-256 | Implemented | Streaming hash with bounded buffer and size ceiling | Acquisition provenance and optional signed receipts |
| Signature registry | Implemented | ELF, PE/MZ, Mach-O, universal Mach-O, WASM, PDF, PNG, JPEG, SQLite, GZIP, ZIP, CPIO newc, USTAR-compatible TAR | Extend with fixtures and confidence semantics |
| PE parser | Partial | PE32/PE32+, sections, imports, delay imports, exports, resources, relocation records, WIN_CERTIFICATE framing, bounded CLR header and metadata stream inventory | CLR metadata tables/IL decoding, decompilation, relocation application, Authenticode verification, debug data |
| ELF parser | Partial | ELF32/64, program/section metadata, dynamic tags, symbols, REL/RELA, GNU versions and GNU hash tables | Extended numbering, relocation semantics, DWARF, architecture-specific naming |
| Mach-O parser | Partial | Thin/FAT/FAT64, segments, sections, symbols, indirect symbols, CodeDirectory metadata | Chained fixups, Objective-C metadata, signature verification |
| WebAssembly parser | Partial | Bounded section framing, types, imports, exports, references, code-body ranges and name section | Instruction decoding, validation, control flow, debug info and component model |
| ZIP parser | Partial | EOCD/ZIP64, entries, paths, flags, local ranges | Safe bounded decompression, CRC verification, multi-disk support |
| PDF parser | Partial | Classic xref tables, trailers, /Prev, object framing and active-content lexical markers | Xref/object streams, filters, page tree, attachments and signature verification |
| PNG | Partial | Bounded chunk structure, IHDR, ordering, palette/transparency constraints and CRC budget | IDAT decompression, scanline and pixel decoding, color management |
| JPEG | Signature only | SOI recognition | Marker/segment parser |
| SQLite | Signature only | Database signature recognition | Page/schema/WAL parser |
| UBIFS | Partial | 4096-byte superblock and 512-byte master-node metadata, common-header CRC, filesystem geometry, root-index/journal/LPT references, space counters, flags, compression and UUID; no tree or payload traversal | Duplicate-master recovery, index/journal/LPT/orphan traversal, inode/directory/data nodes, HMAC/hash verification |
| UBI | Partial | EC/VID header parsing, header CRC validation and optional explicit-geometry PEB inventory; no volume-table decoding | Layout-volume records, fastmap and UBI volume payload decoding |
| cramfs | Partial | Superblock and root-inode validation, endian detection and bounded image/root offsets; no directory traversal or block decompression | Directory entries, inode graph, compressed block decoding, extraction and reconstruction |
| SquashFS | Partial | SquashFS v4.0 superblock, endian, block geometry, compression/flags and bounded top-level table offsets; no table decompression or inode traversal | Metadata block decoding, inode/directory semantics, fragments, xattrs and file extraction |
| GZIP | Partial | Bounded DEFLATE member decompression, optional header CRC16, trailer CRC32/ISIZE validation, concatenated members and nested CPIO/TAR parsing | Other compression methods and arbitrary nested-format recursion |
| Parser dispatch | Implemented | Parsed/rejected/not-supported status | Capability details and parser version metadata |
| Binary reader | Implemented | Bounds-checked reads and safe ranges | Continue fuzz/differential testing |
| Parser resource limits | Partial | Count/range ceilings across current parsers | Per-format aggregate CPU/memory budgets and coverage |
| Fuzz/mutation tests | Partial | Deterministic mutations and random-byte smoke coverage | Retained corpora, longer scheduled fuzzing and crash minimization |
| Differential parser validation | Planned | No broad independent-oracle test harness | Compare output with trusted upstream parsers |

## C. Repository and source intelligence

| Capability | Status | Current evidence / boundary | Completion direction |
|---|---|---|---|
| Bounded project traversal | Implemented | Deterministic sorted walk, no symlink traversal, limits | Incremental indexing and explicit ignore policy |
| Language classification | Partial | Extension-based inventory across 25+ languages, including TypeScript, Python, Go, Rust, C/C++, Java, Kotlin, C#, Swift, PHP, Ruby, Dart, Scala, scripting and functional languages | Content-aware and parser-backed detection |
| Manifest inventory | Partial | Selected npm, Python, Cargo, Go, Composer, Maven, NuGet and Ruby manifests | Broader ecosystem coverage and schema validation |
| Lockfile readers | Partial | npm, Yarn, pnpm, Cargo, Composer, Poetry, uv, Pipenv, Go sum, Ruby, NuGet and Gradle | More versions/edge cases and compatibility corpora |
| Dependency graph | Partial | Resolved package/root edges where lockfiles expose them | Workspace resolution and graph confidence |
| Source import extraction | Partial | Bounded JavaScript/TypeScript tokenizer plus syntax-pattern imports for 25+ languages; best-effort local relative-import graph | Compiler ASTs, semantic resolution, scopes, type/data-flow and dynamic/runtime loading |
| Symbol candidates | Partial | Syntax-pattern extraction | Compiler-backed symbols and cross-reference index |
| Local import resolution | Partial | Conservative relative path candidates | Language-aware module resolution |
| Git metadata | Partial | HEAD, loose/packed refs, tags, sanitized remotes and verified loose HEAD commit identity | Packed object and commit history indexing |
| Build-system detection | Partial | Manifest/filename signals | Explicit build graph and generated-source boundaries |
| Project architecture graph | Planned | No full architecture graph | Build from verified symbol/import/module relationships |
| Incremental cache | Planned | Full bounded scan model | Content-hash/parser-version/options keyed cache |
| LSP integration | Planned | Not present | Optional language server providers |

## D. Security and supply chain

| Capability | Status | Current evidence / boundary | Completion direction |
|---|---|---|---|
| Static indicator engine | Partial | Deterministic structural and lexical rules | More rules, precision review and rule test corpus |
| PDF active-content triage | Implemented | Lexical action markers, no reachability proof | Object graph and stream decoding before stronger claims |
| Source credential-shaped patterns | Partial | Redacted heuristic findings | Secret scanner providers and precision/false-positive evaluation |
| Vulnerability database matching | Partial | Explicit opt-in OSV querybatch audit for exact lockfile-resolved versions; bounded advisory details and affected-range records | Local ecosystem-specific range evaluation, offline snapshots/cache and reachability evidence |
| License inventory | Partial | Some package metadata exists; no complete license decision engine | Evidence-based SPDX normalization and policy engine |
| SBOM CycloneDX | Partial | CycloneDX 1.5 export from declared and resolved packages | Import, validation, SPDX and broader ecosystems |
| SARIF | Implemented | SARIF 2.1.0 for artifact, scan and project findings | Import, validation and external-provider ingestion |
| Build provenance / attestations | Planned | No verified attestation pipeline | Standards and trust policy research |
| Container/image security | Planned | No image layer or filesystem provider | Syft/Trivy adapters and safe image acquisition |
| Malware verdict | Not implemented | Heuristic triage only | Do not add an unsupported single-score verdict |
| Publisher trust verification | Planned | Certificate framing is not cryptographic trust validation | Authenticode, Apple signing and trust-store policy |

## E. Providers and reverse engineering

| Capability | Status | Current evidence / boundary | Completion direction |
|---|---|---|---|
| Provider manifest schema | Implemented | orix.provider.v1; metadata only | Signed provider identities and trust policy |
| Provider registry | Implemented | Immutable in-memory manifest registry | Persistent registry and discovery |
| Static subprocess runner | Partial | argv-only, shell-free, time/output limits, minimal environment | OS-level containment and process-tree guarantees |
| Rizin version probe | Implemented | Explicit executable, version report | Real-version compatibility matrix |
| Rizin imports adapter | Partial | Static import metadata using private snapshot | More commands, disassembly and symbol/function analysis |
| Rizin function inventory and disassembly | Partial | `-A` + `aflj`, address-validated `pdj` windows, bounded output, hashed private snapshot | Real-version golden tests, xrefs, symbols/sections/strings, call graphs and decompiler backend |
| Optional Rizin pseudocode decompilation | Partial | `pdg` request routed to externally installed `rz-ghidra`; explicit opt-in and bounded output | Real plugin/version/architecture compatibility matrix; plugin is not bundled or installed |
| Ghidra/decompiler adapter | Planned | No dedicated Ghidra headless adapter; optional Rizin `pdg` is heuristic plugin-backed pseudocode, not source reconstruction | Verified source-like decompilation, headless analysis, script contract and isolated process lifecycle |
| JADX adapter | Planned | No adapter | APK/DEX analysis and resource mapping |
| Semgrep adapter | Planned | No adapter | SARIF ingestion and language/rule provenance |
| Syft adapter | Planned | No adapter | SBOM provider and inventory reconciliation |
| OSV-Scanner adapter | Planned | No adapter | Network-aware vulnerability enrichment |
| Trivy adapter | Planned | No adapter | Structured security findings and data source metadata |
| Frida adapter | Research required | No runtime provider | Only inside explicit authorized disposable lab |
| IDA / Binary Ninja | Research required | No adapter | User-installed, licensed integration only |
| Plugin loader / SDK | Planned | Manifest is not a plugin loader | Capability-limited SDK, signing and isolation |

## F. Evidence, storage and cases

| Capability | Status | Current evidence / boundary | Completion direction |
|---|---|---|---|
| In-memory evidence records | Implemented | Observation, provenance, offsets and confidence | Stable cross-run IDs and lineage |
| Hash-chained JSONL ledger | Implemented | Append, lock, verify and list | Independent signed checkpoints and portability |
| Tamper-proof ledger | Not implemented | Hash chain is tamper-evident, not tamper-proof | External checkpoint/signature/trusted timestamp options |
| Persistent database | Partial | Local event-sourced JSONL case store with immutable event history; no SQLite database | SQLite adapter, migrations, cross-case search and multi-user storage |
| Content-addressed artifact store | Planned | Hashes in reports, no managed object store | Deduplication, retention and verification |
| Immutable analysis runs | Partial | Case records store report files, tool/version, options digest, coverage and report SHA-256 | Provider invocation expansion, cross-case indexing and schema migrations |
| Case management | Partial | Local event-sourced case workspace with UUID cases, notes, finding lifecycle, case-local relationships, timeline and unsigned bundle export/import | Bookmarks/tags, cross-case ownership/search, multi-user collaboration and browser case UI |
| Evidence search | Planned | No persisted cross-case search | Indexed structured search |
| Portable case bundles | Planned | Individual report and ledger exports | Signed manifest and independent verifier |

## G. AI, workflows and interfaces

| Capability | Status | Current evidence / boundary | Completion direction |
|---|---|---|---|
| MCP stdio server | Implemented | Ten tools, workspace-confined operations, lifecycle validation, bounded batches and per-session rate limits | Per-tool authorization policy and append-only tool audit receipts |
| MCP protocol current support | Implemented | 2025-03-26; JSON-RPC validation, initialization lifecycle, notification/batch semantics and tool safety annotations | Evaluate 2026-07-28 compatibility before upgrade |
| MCP HTTP transport | Planned | No HTTP listener or remote auth | Streamable HTTP, auth, origin/session policy |
| MCP resources/prompts/subscriptions | Planned | Tools only | Typed resources and prompts with trust labeling |
| Built-in LLM/model router | Planned | No direct model provider | Replaceable provider API, privacy/cost metadata |
| Evidence-grounded investigation agent | Planned | No autonomous agent loop | Plans, approvals, citations, replay and budgets |
| Autonomous code editing | Planned | No coding agent | Patch preview, explicit approval and sandboxed tests |
| Workflow engine | Planned | No workflow graph/runtime | Typed steps, cancellation, idempotency and audit |
| Browser report viewer | Partial | Imports reports, filters, details, CSV; not live scanning | Full local workspace |
| Desktop application | Planned | No desktop shell | Stable service/API then desktop delivery |
| Remote multi-user service | Planned | Not present | Tenant isolation, auth, authorization and retention |
| Collaboration | Planned | Not present | Case sharing and review controls |

## H. Release and operational maturity

| Capability | Status | Current evidence / boundary | Completion direction |
|---|---|---|---|
| Versioned report schemas | Partial | Artifact, scan, project, comparison, ledger and provider contracts | More complete validation/migration fixtures |
| Package private setting | Intentional current constraint | package.json has private=true | Publish only after release audit |
| Changelog | Implemented | 0.5.0 and unreleased changes | Release automation and signed artifacts |
| CodeQL | Implemented | Scheduled security-extended workflow | Review alerts and fix policy |
| Dependabot | Implemented | GitHub Actions dependency updates | Review and merge compatible PRs |
| Performance benchmarks | Planned | No reproducible benchmark harness | Corpora, metrics, baselines and regression budgets |
| Documentation contract test | In progress | Added in this foundation change | Keep required docs/source invariants enforced |

## I. Extended platform workstreams

| Capability | Status | Current evidence / boundary | Completion direction |
|---|---|---|---|
| Native binary structural analysis | Partial | PE, ELF, Mach-O and WebAssembly parsers | Complete format semantics and address model |
| Native decompilation | Planned | No decompiler adapter; Rizin imports only | Provider-neutral function/xref/disassembly/decompiler contract |
| JavaScript / Electron | Partial | Dedicated bounded JavaScript/TypeScript tokenizer, static import/re-export and declaration candidates; polyglot source import/symbol inventory for 25+ languages | Full ECMAScript/TypeScript AST and type/data-flow; Electron main/preload/renderer/IPC model |
| .NET / CLR / IL | Partial | Bounded CLI header, runtime flags, entry-point token and metadata stream inventory | Metadata tables, IL bodies/instructions, PDB/debug data, decompilation and Authenticode trust verification |
| Electron configuration triage | Partial | Detects Electron project metadata and literal unsafe `webPreferences` settings with file/line evidence; no AST or runtime proof | AST-aware main/preload/renderer/IPC model and disposable browser observation |
| Android APK / manifest / DEX | Partial | Existing APK parser supports bounded stored/raw-DEFLATE entry reads with CRC32 verification and bounded binary/plain XML metadata; package inventory adds validated ZIP metadata, APK binary XML component/permission metadata and stored unencrypted DEX 035/037/038/039 map/string/type/class metadata | DEX bytecode/method analysis, resources and intent-filter resolution, signing-block/certificate verification, runtime/device observations |
| Android App Bundle (AAB) | Partial | ZIP bundle-layout detection, BundleConfig.pb and module manifest-path presence, safe archive/native/DEX candidate inventory | Protobuf manifest/resources, full module/split semantics, signature verification and device/runtime observations |
| Android App Bundle (AAB) | Planned | No AAB bundle-module or bundle-metadata parser | Bundle manifest/resource inspection and split-APK relationship analysis |
| Android device observations | Planned | No ADB/emulator/Frida provider | Explicit device approval, scope, capture budgets and cleanup |
| Website structure | Partial | Bounded offline HTML inventory, linked/inline JavaScript static imports and declaration candidates, recursive local module graph with path/query redaction, script/style/link/form/iframe and metadata inventory | Standards-complete DOM, CSS/source-map analysis, dynamic execution and browser observation |
| Browser observations | Planned | No live browser provider | Disposable Playwright/CDP session and local fixture corpus |
| HAR network analysis | Implemented | Bounded offline HAR 1.2 metadata parser, CLI/API/MCP, evidence IDs and SHA-256 | Broader validation, corpus, normalized browser/proxy input |
| PCAP / PCAPNG | Partial | Classic PCAP 2.4 plus bounded PCAPNG section/block/interface/packet metadata, timestamp options and safe secret-block inventory; endpoint/port metadata from supported link types | IPv6 extension traversal, reassembly, checksum validation, application protocols, payload export and live capture remain unsupported |
| Firmware and filesystems | Partial | UBI EC/VID and layout-volume table metadata, UBIFS superblock and master-node metadata, cramfs superblock/root-inode metadata, SquashFS v4.0 superblock metadata plus raw CPIO newc/CRC-newc and USTAR/PAX/GNU TAR metadata parsers with bounded file ranges, checksum validation and path-safety inventory; GZIP wrappers validate CRC/ISIZE and can parse nested CPIO/TAR; no extraction | SquashFS metadata decompression/inode traversal, cramfs directory/block decoding, UBI fastmap/attach semantics and UBIFS index/journal/LPT/orphan and inode/data-node decoding, ext, boot images and device-tree parsers |
| Evidence investigation workflows | Partial | Local event-sourced cases, SHA-256 ledger, artifact references, analysis reports, finding lifecycle, notes, typed case-local relationships, timeline and portable unsigned bundle import/export | Cross-case graph/search, embedded content-addressed samples, signatures/trusted timestamps, retention controls, multi-user access control and browser case workspace |
| Recorded behavior replay | Planned | No event trace or replay runtime | Versioned trace schema and deterministic test-environment replay |
| AI / RL environments | Planned | No environment adapter/training integration | Allowlisted observation/action API and replay/permission gates |

## Priority order

1. **P0 — Truth and release quality:** reconcile docs, enforce documentation contracts, validate CI on all current platforms, strengthen parser/provider tests and clean install/package verification.
2. **P1 — Persistent evidence:** storage abstractions, artifact identity, immutable runs, case workspace, lineage, migrations and portable exports.
3. **P2 — Provider depth:** Ghidra, Rizin expansion, JADX, Semgrep, Syft and OSV/Trivy adapters with operational proof and provenance.
4. **P3 — Correlated intelligence:** source/binary/dependency relationships, advisory matching, license evidence and cross-provider normalization.
5. **P4 — AI and agent workflows:** model abstraction, evidence-grounded plans, approvals, tool logs, replay and bounded code changes.
6. **P5 — Product workspace:** live web workspace, graphs, timelines, desktop shell and accessible operator experience.
7. **P6 — Authorized runtime lab:** isolated dynamic observation with authorization, containment, cleanup and auditability.
8. **1.0 — Stable platform:** compatibility policy, signed releases, supported OS matrix, migrations, provider SDK and maintenance process.

## Rule for changing this matrix

A status may move to Implemented only when a reviewer can point to the owning source module, meaningful tests, current documentation and CI evidence. If a feature is only a prototype or a provider fixture, retain Partial or Planned and state that boundary.