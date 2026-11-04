# ORIX Engineering Gap Register & Execution Backlog

**Status:** Planned work; this document does not claim these capabilities are implemented.  
**Source of truth:** [Product Charter](PRODUCT_CHARTER.md)  
**Baseline reviewed:** repository release line 0.5.0, branch `main`.  
**Expanded platform scope:** see [Platform Expansion Blueprint](PLATFORM_EXPANSION.md) for explicit Android, Electron/JavaScript, .NET, website/browser, HAR/PCAP, firmware, evidence-workflow and AI/RL workstreams. HAR metadata analysis is the first implemented vertical slice; the remaining workstreams remain planned or partial until source, tests and CI prove otherwise.

This backlog turns the product charter into reviewable engineering work. It is intentionally ordered by dependency and risk, not by how impressive a feature sounds. Each work package must be split into small pull requests with tests and evidence.

## 0. Baseline verification (do before feature expansion)

### G0.1 — Reconcile docs with code
- [x] Add a source-backed capability inventory with CLI, public API and MCP exposure.
- [x] Add CI documentation contracts for release markers, parser registry rows, MCP protocol claims and indicator rule coverage.
- [ ] Generate additional README/CLI/MCP tables from the inventory rather than maintaining parallel hand-written summaries.
- Correct the stale CLI version reference in `docs/CLI.md`.
- Reconcile `docs/FORMATS.md` with actual ELF GNU-hash and WebAssembly type/import/export/function-name support.
- Reconcile `docs/INDICATORS.md` with every emitted rule, including PDF rules.
- Generate or maintain a single machine-readable capability matrix used by CLI help, README and docs.
- Add a test that enumerates registered parsers/rules and verifies every public capability has documentation.
- Acceptance: no doc claims unsupported behavior; no implemented public behavior is omitted from the support matrix.

### G0.2 — Reproducible CI and release gates
- [x] Run Node.js 20/22/24 test matrices, Windows/macOS smoke suites and CodeQL; upgrade checkout/setup-node actions to v7.
- [ ] Add release artifact provenance, signing and retention checks.
- Verify `npm ci`, `npm run check`, `npm test`, and coverage on supported Node versions and OS matrix.
- Publish CI test/coverage artifacts and retain failure diagnostics.
- Add dependency/license/security checks appropriate to a zero-runtime-dependency Node project.
- Add release workflow with clean checkout, reproducible test, provenance and signed/tagged release plan.
- Acceptance: a clean checkout reproduces the same validation; release cannot be cut on failing required jobs.

### G0.3 — Threat-model and adversarial regression suite
- [x] Document MCP JSON-RPC/workspace boundaries, viewer CSP/CSV formula handling, OSV disclosure limits, evidence-ledger integrity and future case-store requirements.
- [x] Add CSV formula-injection regression tests for the browser report export.
- [ ] Add dedicated symlink-swap race tests, malicious provider output corpus and prompt-injection fixtures for future agent workflows.
- Add explicit threat models for parsers, directory walking, provider process runner, MCP, viewer and future database.
- Add adversarial fixtures for symlink swaps, path traversal, malformed lengths, integer overflow, huge counts, zip bombs (metadata-only tests until decompression exists), malicious provider output, prompt injection in scanned text and cancellation races.
- Acceptance: every fixed security issue gains a regression test; tests remain deterministic and bounded.

## 1. Core architecture and contracts

### G1.1 — Capability registry
- [x] Add versioned `orix.capabilities.v1` report, JSON Schema, CLI command, public API and read-only MCP tool.
- [ ] Extend source-derived entries to every CLI command, report schema and workflow before treating the registry as exhaustive.
- Define versioned machine-readable capabilities for formats, parsers, reports, providers, analyzers and transports.
- Include status, supported variants, resource ceilings, limitations, platform support and test fixture references.
- Generate CLI `formats`, README tables and docs from one source.
- Acceptance: no duplicated manually maintained support lists.

### G1.2 — Unified evidence schema
- Normalize evidence fields across core parsers, project analyzers and providers.
- Add source artifact identity, byte/file/address location, engine/version, confidence, timestamp, coverage and evidence lineage.
- Preserve original provider payload in bounded, attributable form.
- Add schema compatibility and migration tests.
- Acceptance: findings can link to one or more immutable evidence records without losing source provenance.

### G1.3 — Finding lifecycle and correlation
- Introduce states such as observed, suspected, validated, dismissed and accepted-risk without conflating them with severity.
- Add stable fingerprints and deduplication rules that do not leak secret values.
- Correlate parser, source, dependency and provider observations with explicit relationship confidence.
- Acceptance: every derived conclusion lists its evidence and derivation; uncertain matches remain hypotheses.

### G1.4 — Architecture-neutral address model
- Model file offsets, virtual addresses, RVAs, section-relative offsets, DEX indices and WASM indices distinctly.
- Include architecture, bitness, endianness, image base and slice identity.
- Acceptance: conversions are explicit and tested; no address field is overloaded.

## 2. Parser and artifact coverage

### G2.1 — Parser hardening and fuzzing
- [x] Add deterministic mutation and random-byte smoke coverage for PE, ELF, Mach-O, universal Mach-O, WebAssembly, ZIP, PDF and PNG parsers.
- [ ] Add coverage-guided campaigns with documented duration/corpus and crash/hang triage.
- Add coverage-guided fuzz harnesses for all parsers; seed with valid and malformed corpus.
- Track parser crashes, hangs, memory ceilings and mutation regressions.
- Add differential tests against trusted tools where output semantics can be compared.
- Acceptance: fuzz campaigns have documented duration/corpus and zero untriaged crashes before release.

### G2.2 — PE completion
- Add extended data-directory and CLR metadata parsing with strict count/offset bounds.
- Add Authenticode structure inspection separately from trust verification; certificate-chain and revocation checks must be explicit, optional and network-gated.
- Parse debug directory/PDB identity and richer load-config/CFG metadata.
- Do not imply relocation application or runtime loader equivalence.
- Acceptance: PE fixtures include signed/unsigned, malformed, managed, forwarded-export and architecture variants.

### G2.3 — ELF completion
- Add extended section/program numbering, notes, core-dump metadata and architecture-specific relocation naming.
- Add bounded DWARF indexing as a separate optional parser layer.
- Improve symbol/version/relocation cross-references and architecture coverage.
- Acceptance: fixtures cover 32/64-bit, endian variants, stripped/unstripped, malformed extended numbering and large-table budgets.

### G2.4 — Mach-O completion
- Add chained-fixup metadata, richer code-signature structures, Objective-C metadata and dyld shared-cache support only as separate bounded modules.
- Keep signature parsing distinct from cryptographic verification and trust policy.
- Acceptance: thin/FAT/FAT64, arm64e and malformed load-command fixtures.

### G2.5 — ZIP and archive safety
- Add safe entry streaming only after a decompression budget model exists: total output, per-entry output, ratio, nesting, CPU, path normalization and cancellation.
- Add TAR, gzip, 7z and other formats through a capability registry, not ad hoc extension checks.
- Never auto-extract during inspect.
- Acceptance: traversal, symlink, hardlink, duplicate path, nested archive and decompression-bomb tests.

### G2.6 — PDF completion
- Add bounded xref-stream and object-stream decoding, filter support with decompression budgets, page-tree and attachment indexing.
- Keep JavaScript/action markers as lexical observations unless object reachability is established.
- Add digital-signature structure parsing separately from cryptographic trust verification.
- Acceptance: incremental update, hybrid xref, encrypted, object-stream and malformed fixtures.

### G2.7 — WebAssembly completion
- Add instruction decoding, element/data segments, globals, tables, memories, tags, start semantics and validation through a trusted validator/provider.
- Keep parsing distinct from full spec validation and execution.
- Add component-model support only with explicit versioned coverage.
- Acceptance: valid/invalid modules, index-space boundary and custom-section tests.

### G2.8 — New artifact families
- Android APK/AAB, DEX/ART, Android binary XML/resources.
- Java class/JAR, .NET PE/CLI metadata, PDB, minidump/core dumps.
- Firmware and filesystem images with bounded recursive extraction plans.
- SQLite structural inspection beyond signature recognition.
- Image/media metadata only where it provides real engineering value.
- Acceptance: each family has a scoped parser spec, corpus, resource model, clear limitations and tests before registration.

## 3. Project, dependency and supply-chain intelligence

### G3.1 — Lockfile completeness
- Add supported Python lock formats and Go module graph data where encoded.
- Add Maven/Gradle resolved dependency graph support with format/version-specific completeness.
- Add Swift Package.resolved, Dart/Flutter pubspec.lock, .NET packages.lock and additional ecosystems only after fixture research.
- Preserve source URL, checksum, integrity, scope and dependency relationship.
- Acceptance: malformed lockfiles never produce fabricated resolved versions; partial graph status is explicit.

### G3.2 — Git history and workspace graph
- Add packed object support, refs, tags, submodules and linked worktrees with path confinement.
- Record commit identity, parent links, tree/file changes and author metadata with privacy-aware defaults.
- Acceptance: no external git command or hook executes implicitly; large repos obey budgets.

### G3.3 — Source language intelligence
- Replace regex-only parsing incrementally with parser-backed AST adapters for selected languages.
- Add symbol definitions, references, call relationships, imports and test mapping.
- Add architecture map from observed evidence, not guesses.
- Acceptance: each language adapter reports parser version, syntax coverage and unresolved edges.

### G3.4 — Vulnerability intelligence
- [x] Add opt-in OSV.dev `querybatch` lookup for exact lockfile-resolved package versions with ecosystem mapping.
- [x] Follow per-package pagination tokens, fetch advisory detail by ID, retain source timestamps/links and separate withdrawn records.
- [x] Keep source files and lockfile contents local; report unsupported packages, query failures, omitted packages and partial coverage explicitly.
- [x] Add deterministic mock-service fixtures for matching, aliases, withdrawn records, pagination, malformed responses, limits and CLI opt-in.
- [ ] Add a persistent, timestamped advisory cache/snapshot format and offline re-evaluation.
- [ ] Extend ecosystem coverage and validate all OSV affected-range events locally against pinned package-version semantics.
- [ ] Add dependency graph reachability only where source evidence supports it; runtime-observed status requires a separate observation provider.
- Acceptance: fixtures cover ranges, aliases, withdrawn advisories, unknown versions and false matches.

### G3.5 — SBOM and license policy
- Validate CycloneDX output against selected spec versions; evaluate SPDX import/export and license expression parsing.
- Add file/package provenance, dependency graph completeness and cryptographic hashes.
- License policy results must cite detected license text and matching confidence.
- Acceptance: round-trip fixtures and external validator tests; no unsupported schema version claims.

### G3.6 — Config and infrastructure analyzers
- Add scoped analyzers for Dockerfiles, Kubernetes, Terraform, GitHub Actions and common CI configurations.
- Findings need source line locations, rule metadata, confidence and remediation context.
- Treat workflow text and repository content as untrusted data.
- Acceptance: positive, negative, malformed and secret-redaction fixtures for each rule family.

## 4. Specialist reverse-engineering providers

### G4.1 — Provider contract v2
- Define typed request/response schemas for file, project, function, symbol, xref, graph, decompiler and diagnostics.
- Add capability negotiation, version compatibility, deterministic invocation metadata, cancellation and health probes.
- Separate process execution permission from provider availability.
- Acceptance: conformance test suite can be run by third-party adapters.

### G4.2 — Ghidra adapter
- Headless analysis only after explicit provider approval; record Ghidra version, processor language, scripts, options and output.
- Import functions, symbols, disassembly, decompiler output and references with provider provenance.
- Avoid bundling Ghidra unless its license/distribution terms are reviewed.
- Acceptance: golden fixtures for PE/ELF/Mach-O architectures; no target execution.

### G4.3 — Rizin adapter expansion
- [x] Add bounded function inventory with `-A` + `aflj`, explicit output ceilings, private input snapshot and SHA-256 provenance.
- [x] Add address-validated, instruction-limited `pdj` disassembly.
- [x] Add opt-in `pdg` pseudocode when the external `rz-ghidra` plugin is present; no plugin bundling or automatic installation.
- [ ] Add sections, strings, symbols and xrefs as separate bounded capabilities.
- [ ] Compare provider results against native parsers; preserve provider warnings and unsupported formats.
- Acceptance: adapter contract tests across supported Rizin versions/platforms; golden checks against real Rizin releases remain outstanding.

### G4.4 — Android provider adapters
- Integrate JADX and Apktool through explicit executable paths and safe snapshots.
- Normalize manifest, DEX classes/methods, resources and native library links.
- ADB/device operations remain disabled until a separate approval/session model exists.
- Acceptance: benign APK fixture suite, malformed APK limits, provider provenance and licensing review.

### G4.5 — Runtime providers
- Frida/debugger adapters are a later milestone, not part of static analysis.
- Require explicit target identity, device/process scope, action list, time limit, data capture limit and user approval.
- Acceptance: lab-only integration tests, kill switch, cleanup and audit receipts.

## 5. Durable evidence and cases

### G5.1 — SQLite case store
- Add a database abstraction and schema migrations.
- Store artifact identities, analysis runs, findings, evidence, provider invocations, annotations and case relationships.
- Use transactions, foreign keys, integrity checks and crash-recovery tests.
- Acceptance: export remains usable without database; migrations tested from every released schema.

### G5.2 — Content-addressed artifact storage
- Deduplicate by algorithm+digest; avoid storing samples unless user explicitly opts in.
- Support references to external files with stability checks.
- Define retention, deletion, permissions and backup behavior.
- Acceptance: no accidental sample upload; store integrity verifiable.

### G5.3 — Case bundles and signing
- Portable export/import with manifest, schemas, reports, evidence and checksums.
- Optional signature and trusted timestamp integration must identify trust roots and verification status.
- Acceptance: tamper tests detect modified, missing, reordered and substituted members.

### G5.4 — Analyst workflow
- Add notes, bookmarks, tags, evidence pinning, case timeline and review status.
- Keep analyst assertions distinct from machine observations.
- Acceptance: every edit is attributable and exportable.

## 6. AI and workflow orchestration

### G6.1 — Model adapter layer
- Support local model endpoints and opt-in remote providers behind one interface.
- Track model ID/version, prompt/template version, context sources, token/cost budgets and output schema.
- Do not require a paid model for core static functionality.
- Acceptance: provider failures, offline mode, timeouts and untrusted output are tested.

### G6.2 — Evidence-grounded retrieval
- Search only user-approved workspace content and evidence.
- Chunk with stable source locations and content hashes.
- Return citations/links to exact files, byte ranges and analysis records.
- Acceptance: answers without supporting evidence are labeled uncertain; prompt injection cannot change tool policy.

### G6.3 — Governed agent runtime
- Plan → policy check → approval (if required) → execute bounded tool → validate output → record evidence.
- Read-only mode by default; separate permissions for filesystem writes, process execution, network, devices and uploads.
- Add step/time/token budgets, loop detection, cancellation and human handoff.
- Acceptance: denial tests prove agents cannot self-escalate or bypass approval through MCP/provider outputs.

### G6.4 — Workflow recipes
- Versioned pipelines for artifact triage, repository review, APK review, SBOM generation and case comparison.
- Dry-run and explain plan before execution.
- Acceptance: each recipe is deterministic where possible, restartable and emits a complete run record.

## 7. Workspace, UX and interoperability

### G7.1 — Browser workspace evolution
- Move from static report viewer to case-oriented workspace only after case-store contracts exist.
- Add artifact inventory, evidence graph, side-by-side comparison, provider status and analyst notes.
- Keep local file handling local; strict CSP, loopback binding, CSRF/origin and upload limits.
- Acceptance: security tests cover browser boundary and imported hostile reports.

### G7.2 — Desktop application
- Select a desktop framework after UX and local storage threat model; avoid premature framework lock-in.
- Add native file picker, secure local workspace and provider configuration.
- Acceptance: signed builds, update integrity and platform security review.

### G7.3 — MCP hardening
- [x] Bound request frames, tool responses, JSON-RPC batches and per-connection tool-call rate.
- [x] Validate request IDs, initialize parameters and tools/call argument envelopes.
- [x] Negotiate the supported protocol version and align advertised capability families with implemented routes.
- [x] Enforce initialize → initialized → operation lifecycle on each stdio connection.
- [x] Add protocol, notification, batch, rate-limit and workspace-confinement regression tests.
- [ ] Add per-tool authorization policy and append-only tool audit receipts.
- [ ] Remote transport requires authentication, TLS, origin protection and multi-user isolation; no remote listener is currently exposed.
- Acceptance: protocol conformance and confused-deputy tests.

### G7.4 — CI and automation
- GitHub Actions integration for project/SBOM/SARIF workflows.
- Support baseline comparisons and policy gates with explicit exit semantics.
- Avoid leaking secrets or uploading raw artifacts by default.
- Acceptance: reproducible CI examples and least-privilege permissions.

## 8. Suggested delivery order

| Order | Work package | Why now | Exit gate |
|---|---|---|---|
| P0 | G0.1 docs/capability reconciliation | Establish trustworthy baseline | docs-vs-code test |
| P0 | G0.2 CI/release verification | Prevent regressions | green supported matrix |
| P0 | G0.3 threat model/adversarial suite | Protect current attack surface | regression + resource tests |
| P1 | G1.1–G1.4 contracts | Avoid incompatible feature islands | schemas + golden fixtures |
| P1 | G2.1 parser fuzzing | Strengthen existing core | bounded fuzz campaign |
| P2 | G5.1–G5.4 case store | Needed for durable analyst work | migration/export/recovery |
| P2 | G3.1–G3.6 project/supply chain | High practical user value | provenance-backed results |
| P3 | G4.1–G4.4 specialist adapters | Avoid rewriting mature tools | provider conformance |
| P4 | G6.1–G6.4 governed AI | AI should operate on trustworthy evidence | approval and audit tests |
| P4 | G7.1–G7.4 workspace/MCP/CI | Productize stable workflows | security and UX gates |
| P5 | G4.5 runtime lab | Highest operational risk | isolated lab and kill switch |
| P6 | 1.0 stabilization | Compatibility and trust | release checklist complete |

## 9. Pull request rules

- One PR should deliver one coherent capability or tightly coupled vertical slice.
- Every PR updates tests, docs, schemas and generated capability output where applicable.
- No placeholder modules, fake buttons, no-op success paths or aspirational changelog entries.
- No dependency added without license, maintenance, security and platform review.
- No provider integration without bounded invocation, provenance and cancellation.
- No feature may silently widen filesystem, process, network, device or upload permissions.
- Never merge a branch solely because it compiles; run the relevant tests and inspect the diff.
- Record exact commands and results. If CI cannot be run, say so and do not claim it passed.

## 10. Research references to revalidate per work package

- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [Rizin](https://github.com/rizinorg/rizin)
- [JADX](https://github.com/skylot/jadx)
- [Apktool](https://github.com/iBotPeaches/Apktool)
- [Frida documentation](https://frida.re/docs/home/)
- [OSV API](https://google.github.io/osv.dev/api/)
- [Syft](https://github.com/anchore/syft)
- [Trivy](https://github.com/aquasecurity/trivy)
- [CycloneDX specification](https://cyclonedx.org/specification/overview/)
- [SPDX specifications](https://spdx.dev/specifications/)
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [MCP specification](https://modelcontextprotocol.io/specification/2025-03-26)

Research must use primary sources, pin versions/commits where behavior matters, record license compatibility, and include a minimal reproducible fixture before adopting a capability.
