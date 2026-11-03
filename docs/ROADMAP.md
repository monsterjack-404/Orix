# ORIX Engineering Roadmap

This roadmap describes testable product milestones, not promises that every listed capability already exists. The current implementation truth is the [Capability Matrix](CAPABILITY_MATRIX.md); the full target is the [Product Charter](PRODUCT_CHARTER.md).

## Current baseline

- Current main-branch release line: 0.5.0.
- Current runtime: Node.js 20.11 or newer.
- Runtime dependencies: Node.js built-ins only.
- Working surfaces: CLI, public JavaScript API, bounded static parsers, project inventory, lockfile analysis, reports, evidence ledger, local MCP stdio server, optional Rizin static-import adapter and browser-local report viewer.
- Current MCP protocol implementation: 2025-03-26.
- No public npm release, hosted service, desktop app, persistent case database, built-in LLM agent, full decompiler, vulnerability database or dynamic-analysis lab is claimed.

## P0 — Truth, correctness and release quality

**Goal:** ensure that the current product is accurately described, reliably tested and safe to extend.

- [ ] Complete documentation/source consistency checks in CI.
- [ ] Synchronize README, CLI, format matrix, indicator catalogue, provider docs and schemas.
- [ ] Add current fixtures for every supported format and documented feature.
- [ ] Add differential parser checks against trusted upstream tools where practical.
- [ ] Retain reproducible malformed-input and fuzz corpora.
- [ ] Verify clean install, npm package contents and documented commands on a fresh host.
- [ ] Exercise Windows, Linux and macOS file-system edge cases.
- [ ] Review every provider invocation for timeout, cancellation, output ceilings and cleanup.
- [ ] Add explicit coverage summaries for truncation, skipped entries and unsupported structures.
- [ ] Audit dependencies, GitHub Actions, license declarations and repository secrets policy.
- [ ] Add reproducible performance and memory baselines before claiming speed or scale.

**Exit gate:** source, tests, docs and CI agree; no known documentation drift; no undocumented destructive or network side effects.

## P1 — Persistent evidence and workspaces

**Goal:** move from isolated report files to durable, searchable investigations.

- [ ] Decide the storage adapter and minimum Node/runtime policy before choosing a SQLite implementation.
- [ ] Define migrations, transactions, locking, recovery, backup and integrity checks.
- [ ] Add content-addressed artifact records and immutable analysis-run records.
- [ ] Persist normalized findings, evidence, provider receipts and coverage.
- [ ] Add stable evidence IDs and parent/child lineage across runs.
- [ ] Add local workspace and case model with annotations and artifact relationships.
- [ ] Add case search, timeline, compare and portable export/import.
- [ ] Keep the hash-chained ledger independently verifiable; support signed checkpoints only through a documented trust model.
- [ ] Add retention and deletion controls that do not silently break evidence references.

**Exit gate:** interrupted writes recover safely; schema migrations are tested; exports can be verified without the database; large cases remain bounded.

## P2 — Specialist provider foundation

**Goal:** make specialist tooling reliable, observable and interchangeable without losing provenance.

- [ ] Define provider installation, health, capability, identity and version-state contracts.
- [ ] Separate metadata discovery from provider invocation.
- [ ] Add a general provider result envelope with original output digest and normalized evidence.
- [ ] Improve POSIX/Windows process-tree ownership and cleanup.
- [ ] Evaluate OS-level containment for providers that process untrusted artifacts.
- [ ] Add Ghidra headless adapter for authorized static analysis and decompilation.
- [ ] Expand Rizin to symbols, functions, disassembly and metadata only after real-version compatibility testing.
- [ ] Add JADX APK/DEX adapter.
- [ ] Add Semgrep finding import and SARIF normalization.
- [ ] Add Syft SBOM adapter and inventory reconciliation.
- [ ] Add OSV-Scanner advisory enrichment with database/source timestamps and exact version matching.
- [ ] Add Trivy integration for image/configuration/security findings where overlap is justified.
- [ ] Keep IDA/Binary Ninja integrations optional and user-licensed.
- [ ] Define provider conformance fixtures, timeout fixtures, failure cases and license checks.

**Exit gate:** a provider is never advertised as available without a real probe; every result has provider/version/input provenance; failure and partial output are explicit.

## P3 — Correlated engineering intelligence

**Goal:** connect source, binary, dependencies, findings and build provenance into a coherent model.

- [ ] Improve language analysis with AST/compiler/LSP integrations by ecosystem.
- [ ] Index functions, symbols, references, imports, call graphs and cross-module relationships.
- [ ] Add APK/DEX and package/container structure analysis.
- [ ] Build artifact-to-source and package-to-binary relationship contracts.
- [ ] Add vulnerability matching over exact package URL, ecosystem, version ranges and advisory aliases.
- [ ] Add license evidence and policy evaluation.
- [ ] Add SBOM import and SPDX interoperability.
- [ ] Add build provenance and attestation verification.
- [ ] Add baseline comparisons across source revisions, providers and policy versions.
- [ ] Preserve missing/ambiguous graph links instead of guessing.

**Exit gate:** every relationship has a source and confidence; graph construction is reproducible; vulnerability matches are independently testable.

## P4 — AI intelligence and controlled engineering agents

**Goal:** enable AI-assisted investigation based on actual evidence, not ungrounded guesses.

- [ ] Define a model-provider interface with local/remote capability, privacy, cost and retention metadata.
- [ ] Add explicit offline behavior and deterministic non-LLM workflows.
- [ ] Build a planner that uses repository and evidence context.
- [ ] Add a tool policy layer for filesystem, network, process, write and execution capabilities.
- [ ] Require human approval for code edits, builds, network access and destructive operations.
- [ ] Add execution receipts, structured logs, budgets, cancellation and replay.
- [ ] Add evidence citations and uncertainty statements to agent responses.
- [ ] Prevent file content, extracted strings, provider output and repository instructions from changing system policy.
- [ ] Add approved patch workflows with diffs, tests and rollback guidance.
- [ ] Integrate with external coding agents through versioned MCP and API contracts.

**Exit gate:** actions are policy-checked; every agent conclusion links to evidence; every write has an approval and recoverable patch; runs can be replayed or inspected.

## P5 — Web and desktop product workspace

**Goal:** turn the report viewer into an operator workspace without making the current local viewer unsafe.

- [ ] Add live local analysis through a narrow application API.
- [ ] Add workspaces, cases, artifacts, runs, findings and evidence navigation.
- [ ] Add interactive dependency, symbol, import and call-graph visualizations.
- [ ] Add comparison, filters, saved views and investigation timeline.
- [ ] Add provider health/installation guidance and explicit invocation controls.
- [ ] Add accessible keyboard navigation and large-report virtualization.
- [ ] Add desktop shell only after local service and storage boundaries stabilize.
- [ ] Add import/export, backup, migration and recovery flows.
- [ ] Add remote collaboration only after authentication, authorization and tenant isolation reviews.

**Exit gate:** UI is a presentation of canonical services; report content is safely rendered; local data does not leave the machine without consent.

## P6 — Authorized runtime investigation

**Goal:** support runtime observation only within an explicit, disposable, auditable lab.

- [ ] Define authorization record and target scope.
- [ ] Define disposable VM/container/snapshot requirements per supported OS.
- [ ] Enforce process, filesystem, network, memory, CPU and time policies outside the provider process.
- [ ] Add process ownership and descendant cleanup guarantees.
- [ ] Add read-only observation mode before instrumentation.
- [ ] Integrate runtime providers such as Frida only with explicit scope and isolation.
- [ ] Capture event provenance and distinguish observed runtime behavior from static inference.
- [ ] Test crashes, hangs, cancellation, host isolation and cleanup failure.
- [ ] Preserve complete audit records and safe lab reset behavior.

**Exit gate:** no dynamic target executes on the host by accident; policy is enforced by the isolation layer; all outcomes and cleanup failures are visible.

## 1.0 — Stable platform

- [ ] Versioned and supported public APIs, schemas and provider SDK.
- [ ] Reproducible release artifacts and signed provenance.
- [ ] Documented supported OS/runtime matrix and compatibility policy.
- [ ] Release, migration, backup, incident and vulnerability-response processes.
- [ ] Full security and privacy review.
- [ ] Benchmark results with reproducible corpora and no unsupported superiority claims.
- [ ] Maintainer documentation and verified installation paths.

## Cross-cutting quality gates

1. No placeholder module is presented as a capability.
2. Every advertised feature maps to source and meaningful tests.
3. Every untrusted-input loop and process boundary has resource limits.
4. Malformed, truncated and boundary input is tested.
5. Coverage and unsupported states are visible.
6. Public report and provider contracts are versioned.
7. No inspected artifact or project script runs implicitly.
8. Network access and data egress are explicit.
9. External provider licensing and attribution are reviewed.
10. CI passes on each claimed platform and runtime.
11. Documentation is checked against source contracts.
12. A feature is complete only when its acceptance criteria and failure behavior are tested.

## Release discipline

Use small, reviewable changes. Prefer a focused PR for one vertical slice over a giant unreviewable change. Do not merge a provider adapter on the strength of a fake executable fixture alone; require real-tool verification or label the adapter experimental. Do not claim benchmarks without a repeatable protocol. Keep the main branch as the source of truth and remove stale branches only after their unique work has been reviewed.