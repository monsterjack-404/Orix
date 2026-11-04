# ORIX Product Charter

**Status:** Product direction and engineering contract  
**Applies to:** ORIX CLI, core libraries, providers, MCP, browser/desktop workspaces, reports and future agents  
**Release baseline:** 0.5.0  
**Default branch:** `main`

## 1. Product definition

ORIX (Open Research & Intelligence eXplorer) is a local-first, evidence-first engineering intelligence platform for understanding software artifacts and software projects. It combines deterministic native analysis, specialist tools, dependency and supply-chain intelligence, security research workflows, persistent cases, and carefully governed AI assistance behind one consistent evidence model.

ORIX is not intended to reimplement every specialist reverse-engineering or security product. Its durable advantage must be the integration layer: safe acquisition, normalized findings, provenance, cross-tool correlation, reproducible workflows, and a usable workspace that makes specialist capabilities work together.

**Product promise:** every conclusion must show what was inspected, which engine produced it, what evidence supports it, what limits apply, and how another engineer can reproduce or challenge it.

## 2. Product principles (non-negotiable)

1. **Evidence before confidence.** No AI or heuristic conclusion is promoted to fact without inspectable supporting evidence.
2. **Local-first by default.** Files and source trees remain local unless a user explicitly configures and approves an external service or provider.
3. **No execution by surprise.** Static inspection never runs target files, project scripts, build steps, package hooks, macros, or provider-supplied code.
4. **Explicit authorization.** Dynamic analysis, device access, network capture, debugger attachment, mutation, upload, and external provider execution require a clearly scoped user action and an auditable approval.
5. **Bound every untrusted input.** File size, bytes read, parser counts, recursion, decompression, CPU time, memory, output, concurrency, path traversal and cancellation must have explicit limits.
6. **Fail closed, report honestly.** Unsupported, partial, truncated, timed-out, unstable, or failed analysis is represented as such; never silently convert it into a clean result.
7. **Reproducibility.** Record content identity, ORIX build, engine/provider versions, options, timestamps, environment-relevant facts, coverage and limitations.
8. **Composable, not coupled.** Core contracts remain usable without a GUI, database, AI model, network connection or optional provider.
9. **Interoperability.** Prefer stable public formats and protocols (SARIF, CycloneDX, JSON Schema, MCP) where they fit.
10. **Security is a product feature.** Threat models, secure defaults, dependency review, fuzzing and adversarial tests are release requirements.
11. **Honest capability labels.** Every feature is marked Implemented, Experimental, Planned or Unsupported, with evidence and tests behind Implemented.
12. **Accessible engineering.** CLI workflows, machine-readable output, clear errors and documentation remain first-class alongside visual interfaces.

## 3. Who ORIX serves

- Reverse engineers examining software they own or are authorized to assess.
- Application-security and product-security engineers.
- Malware and incident responders working in controlled, authorized environments.
- Software maintainers investigating unfamiliar repositories, dependencies and build provenance.
- Researchers and educators studying file formats, compilers, runtime behavior and software supply chains.
- AI coding agents that need bounded, auditable tools rather than unrestricted shell access.

## 4. Scope map

### A. Artifact intelligence
- Safe file acquisition and stable identity; SHA-256 and future algorithm agility.
- Format identification with confidence and parser capability registry.
- Structural parsers for executable, bytecode, archive, document, database, firmware and mobile formats.
- Metadata, strings, symbols, imports/exports, sections/segments, resources, relocations, signatures and embedded-object indexes.
- Hex/byte-range evidence and format-aware navigation.
- Explicit partial parsing, unsupported structures and parser warnings.

### B. Reverse engineering and code understanding
- Disassembly, function boundaries, cross-references, control-flow and call graphs through specialist providers.
- Decompiler output as attributed provider evidence, never silently treated as ground truth.
- Symbol/type recovery, demangling, compiler/runtime fingerprints and library identification.
- Diffing at byte, structure, function and semantic levels when a provider supports it.
- Persistent analyst annotations, names, comments, bookmarks and typed hypotheses.
- Provider-neutral function, symbol, address, reference and graph contracts.

### C. Android and mobile intelligence
- APK/AAB/DEX/ARSC/AndroidManifest parsing and package inventory.
- Permissions, exported components, intent filters, SDK levels, signing metadata and network-security configuration.
- DEX class/method/string/reference indexes and Java/Kotlin decompilation through optional specialist providers.
- Native library analysis for ABI slices.
- App-to-native-library linkage, manifest-to-code evidence and dependency/SBOM correlation.
- Optional authorized device/emulator workflows (ADB, runtime logs, instrumentation) behind explicit scope and approval.
- No covert collection, unauthorized account access, or stealth/bypass workflows.

### D. Repository and architecture intelligence
- Bounded inventory, language/build-system detection, source symbols and import/reference graph.
- Lockfile-resolved dependency graph, manifests, licenses, package integrity and provenance.
- Git refs/history, submodules and worktrees only where safely and explicitly supported.
- Architecture maps, entry points, service boundaries, API surfaces, configuration and CI/CD inventory.
- Incremental content-addressed indexing with cache invalidation tied to parser/version/options.
- No implicit package install, build, test, lifecycle script or project execution.

### E. Security and supply-chain intelligence
- Explainable static rules with stable IDs, evidence, confidence and false-positive guidance.
- Secret-shaped data detection that redacts values by default.
- Vulnerability enrichment from versioned, attributable advisory sources (for example OSV) with ecosystem/package matching and affected-range reasoning.
- SBOM generation and validation (CycloneDX; SPDX as a planned interchange target).
- License and policy analysis with source attribution and uncertainty.
- Configuration, container, IaC and CI workflow checks as separately scoped analyzers.
- Correlation across code, dependency, binary, build and runtime evidence.
- A finding is not a confirmed vulnerability until validation evidence supports that status.

### F. Runtime and dynamic investigation (future, opt-in)
- Debugger, tracing, instrumentation, sandbox and process observation adapters.
- Network and filesystem behavior capture only inside a declared authorized lab scope.
- Snapshot/restore, disposable environments, resource ceilings, kill switch and evidence capture.
- Runtime observations linked to exact artifact hashes and environment fingerprints.
- Dynamic execution must never be silently triggered by static inspection or AI planning.
- No malware deployment, persistence, evasion, credential theft, unauthorized exploitation or stealth features.

### G. Evidence, cases and collaboration
- Content-addressed artifact store and immutable analysis-run records.
- SQLite local case database with migrations, integrity checks, backup/restore and crash recovery.
- Evidence graph connecting artifact → parser/provider → observation → finding → analyst decision.
- Hash-chained audit events, exportable case bundles and optional signed checkpoints.
- Annotations, tags, timelines, comparison, provenance and retention controls.
- Clear distinction between tamper-evident and tamper-proof; hashes alone do not establish trusted authorship/time.

### H. AI intelligence and governed agents
- Model/provider abstraction with local and remote model options; no mandatory paid API.
- Retrieval over user-approved local evidence and project indexes.
- Specialist task routing to parsers/providers with capability checks.
- Planning, tool execution and result synthesis separated into explicit stages.
- Read-only mode by default; writes, network, device, execution and external uploads require scoped approval.
- Structured tool schemas, typed outputs, budgets, cancellation, loop limits and complete action logs.
- AI-generated code, pseudocode, summaries and hypotheses are labeled and linked to evidence.
- Model output cannot override authorization, tool policy, workspace roots or safety constraints.
- MCP is an interoperability surface, not a permission bypass.

### I. User experiences and automation
- Stable CLI and Node API as the automation foundation.
- Browser-local report explorer and future full workspace.
- Desktop shell only after core workflows and local persistence are mature.
- MCP stdio first; remote transports only with authentication, authorization, origin controls, TLS and threat model.
- CI integrations, SARIF uploads and reproducible batch workflows.
- Optional headless/server mode only after multi-user security and data-isolation design.

## 5. Target architecture

```text
CLI / Node API / MCP / Web / Desktop / CI
                  |
        Workspace & Policy Layer
                  |
      Workflow / Job Orchestrator
                  |
       ORIX Intelligence Core
       |       |       |       |
   Artifact  Project  Security  Evidence
   Engine    Engine   Engine    & Case Store
       |       |       |       |
       +---- Normalized Evidence Graph ----+
                  |
        Provider Adapter Boundary
   Ghidra / Rizin / JADX / Apktool / Frida /
   OSV / SBOM validators / debuggers / others
                  |
       Optional AI Planning & Synthesis
       (policy-gated, evidence-grounded)
```

The core owns schemas, policy, resource budgets, identity, provenance, correlation and case persistence. Providers own specialist algorithms. The UI renders contracts; it must not contain a second, divergent analysis implementation.

## 6. Canonical data contracts

All engines should converge on versioned contracts for:

- `ArtifactIdentity`: algorithm, digest, byte length, acquisition method and stability.
- `AnalysisRun`: run ID, input identities, ORIX version, provider versions, options, limits, start/end, status and coverage.
- `EvidenceRecord`: source artifact, source engine, source version, byte/file/address location, observed value, confidence, timestamp and provenance.
- `Finding`: stable rule/advisory ID, title, severity, confidence, status, evidence references, affected scope, remediation and false-positive notes.
- `Symbol`, `Function`, `Reference`, `Graph`: address-space-aware, architecture-aware and provider-attributed.
- `DependencyComponent` and `DependencyEdge`: ecosystem, package URL, version, scope, hashes, licenses, source and relationship completeness.
- `ProviderManifest`: capabilities, supported formats/platforms, executable identity, license, side effects, permissions, resource needs and protocol version.
- `CaseBundle`: portable manifest, artifacts or references, reports, evidence, annotations, signatures/checkpoints and integrity verification.

Contracts must be versioned, schema-validated, deterministic where possible, and tested against golden fixtures. Unknown fields should be safely tolerated by readers; breaking changes require migration notes.

## 7. Provider strategy

Integrate specialist tools instead of reimplementing them without a clear reason. Evaluate each candidate for: license compatibility, maintenance, platform support, reproducible invocation, output schema, resource behavior, security boundary, provenance, test fixtures and distribution constraints.

Initial provider candidates:
- Native reverse engineering: Ghidra, Rizin, LLVM/objdump where appropriate.
- Android: JADX, Apktool, ADB (authorized device workflows only).
- Runtime observation: Frida and platform debuggers in explicit lab scope.
- Supply chain: OSV data/services, Syft, Trivy and CycloneDX/SPDX validators.
- Protocol: MCP SDK/spec-compatible clients and servers.

A provider adapter must not claim OS isolation unless a real OS sandbox/container/VM boundary is configured and verified. A shell-free child process is safer than shell interpolation, but is not a sandbox.

## 8. Security and privacy model

Threats include malformed hostile files, decompression bombs, parser algorithmic complexity, path traversal, symlink races, malicious provider output, prompt injection in source/comments/documents, dependency confusion, secrets in reports, compromised model endpoints, MCP confused-deputy attacks and workspace cross-access.

Required controls:
- Validate paths after canonicalization and at use time; defend against symlink and TOCTOU races.
- Keep workspace roots explicit; reject traversal and unexpected schemes.
- Bound bytes, counts, nesting, CPU, memory, output, queue size and wall time.
- Treat every artifact, source file, report, provider response and model response as untrusted data, never as policy instructions.
- Redact secrets in logs and exports; never send local content externally without consent.
- Use minimal child-process environments and explicit executable paths.
- Verify provider binary/version and capture exact invocation metadata.
- Protect databases and evidence files with least-privilege permissions.
- Secure MCP with per-tool authorization and strict input validation; remote MCP requires authentication and transport security.
- Keep audit logs append-only where feasible and export signed checkpoints when stronger integrity is needed.
- Never describe a hash chain as immutable against an administrator who can rewrite the entire store.

## 9. Quality bar and definition of done

A feature is **Implemented** only when all relevant items pass:
1. Production source code exists and is wired into public CLI/API/UI surfaces.
2. Valid, malformed, truncated, boundary, adversarial and resource-exhaustion tests exist.
3. Error paths, cancellation, partial coverage and unsupported cases are explicit.
4. Schema and golden fixtures are updated.
5. Documentation describes actual behavior, defaults, limits and non-goals.
6. Security review covers path, process, network, data exposure and trust boundaries.
7. CI passes on supported Node/platform matrix; results are visible and reproducible.
8. Performance and memory behavior are measured for representative workloads.
9. No placeholder, fake success, silently skipped operation or unverified claim remains.
10. Changelog and release notes explain compatibility and migration impact.

Feature states:
- **Implemented:** shipped and verified by source, tests and CI.
- **Experimental:** real code exists, but limitations or compatibility prevent stable support.
- **Planned:** design/backlog only; not available.
- **Unsupported:** explicitly out of scope or not currently handled.

## 10. Release gates

- **0.6 — Durable Cases:** SQLite store, content-addressed artifact/run records, migrations, crash recovery, case export/import, evidence graph and CLI/API integration.
- **0.7 — Specialist Intelligence:** provider-neutral symbols/functions/xrefs/callgraphs, Ghidra and expanded Rizin adapters, Android APK/DEX vertical slice, provider contract tests.
- **0.8 — Supply-chain & Security Correlation:** vulnerability enrichment, CycloneDX validation, SPDX interchange evaluation, license policies, config/container/IaC analyzers and evidence correlation.
- **0.9 — Governed AI & Workspace:** local/remote model adapters, retrieval over approved evidence, task planning, approvals, action logs, workspace UI and MCP hardening.
- **0.10 — Authorized Runtime Lab:** disposable isolated lab adapters, runtime event schemas, resource budgets, environment fingerprints and reproducible captures.
- **1.0 — Stable Platform:** compatibility policy, migration guarantees, signed releases, security response process, performance baselines, full docs and cross-platform release verification.

Milestones are goals, not claims about the current build. They may be split into smaller releases when required for quality.

## 11. Explicit non-goals

ORIX will not become a tool for unauthorized access, credential theft, stealth, persistence, evasion, destructive actions, malware deployment, DRM/license circumvention, anti-cheat bypass, or indiscriminate exploitation. It will not execute user projects by default, upload samples by default, or let an AI agent silently expand its permissions.

## 12. External standards and upstream references

Use primary sources and re-check current versions before implementation:
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) — native reverse-engineering platform.
- [Rizin](https://github.com/rizinorg/rizin) and [Cutter](https://github.com/rizinorg/cutter) — reverse-engineering framework and GUI.
- [JADX](https://github.com/skylot/jadx) — DEX to Java decompiler.
- [Apktool](https://github.com/iBotPeaches/Apktool) — Android package/resource tooling.
- [Frida](https://frida.re/docs/home/) — dynamic instrumentation; use only in explicitly authorized environments.
- [OSV](https://osv.dev/) — open-source vulnerability database and API.
- [Syft](https://github.com/anchore/syft) and [Trivy](https://github.com/aquasecurity/trivy) — SBOM and security scanning ecosystems.
- [CycloneDX](https://cyclonedx.org/specification/overview/) and [SPDX](https://spdx.dev/specifications/) — SBOM interchange standards.
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — static-analysis result interchange.
- [Model Context Protocol](https://modelcontextprotocol.io/specification/2025-03-26) — tool interoperability; apply ORIX authorization independently of protocol capabilities.

Upstream tools and standards have their own licenses, release cycles and security models. ORIX must not imply that integration grants redistribution rights.
