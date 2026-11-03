# ORIX Product Charter

**Product:** ORIX — Open Research & Intelligence eXplorer  
**Product promise:** Understand. Analyze. Engineer.  
**Status:** Target architecture and acceptance contract; not a statement that every capability is implemented.  
**Current implementation baseline:** 0.5.0 on the main branch, reviewed 2026-11-03.

## 1. North star

ORIX is an evidence-first engineering intelligence platform for understanding software across its complete lifecycle: source repositories, dependencies, binaries, file formats, build outputs, security posture, runtime observations and engineering workflows.

The product must make it possible to move from a question or artifact to a reproducible investigation:

1. Acquire or select an input within an explicit trust boundary.
2. Identify what is present and what can be analyzed.
3. Select bounded native analysis and, when appropriate, an explicitly configured specialist provider.
4. Preserve exactly what each tool observed, derived or inferred.
5. Correlate related artifacts, source files, dependencies, symbols, findings and runtime observations.
6. Explain conclusions with evidence, coverage and limitations.
7. Help an authorized operator decide the next step.
8. Execute only approved actions, with visible plans, limits, logs and recovery information.
9. Export a portable investigation record that can be independently reviewed.

ORIX is not merely a file scanner, a decompiler, a vulnerability feed, a chatbot, an agent shell or a dashboard. It is the orchestration and evidence layer that unifies these domains without pretending that one engine can replace every specialist tool.

## 2. Product principles

### 2.1 Evidence before conclusions

Every substantive finding must retain its origin, subject identity, tool and version, time, analysis profile, source location, confidence, severity, coverage and limitations. Observed facts, derived facts and heuristics must remain distinguishable. A missing result is not proof that a property is absent.

### 2.2 Explicit truth about capability

A feature is implemented only when working source, meaningful tests, documentation and CI agree. A schema, manifest, UI mock, command name, empty folder or roadmap checkbox does not by itself constitute an operational feature. Provider availability must be probed; a provider that was not invoked must never appear as if it produced findings.

### 2.3 Safe by default

Parsing and static analysis must not execute inspected artifacts or project-supplied code. File-system access must be bounded and symlink-aware. External processes, network access, writes, debugging and runtime observation must be separate capabilities with explicit policies, approvals, resource limits, cancellation and cleanup. A process timeout is not a sandbox.

### 2.4 Local-first and useful offline

The core must remain useful without an account, cloud service, paid API or installed specialist tool. Network enrichment is opt-in, clearly identified, cache-aware and recorded with source and retrieval time. Core reports and evidence must remain exportable without a hosted ORIX service.

### 2.5 Specialist integration, not shallow imitation

ORIX owns intake, orchestration, normalized evidence, correlations, reproducibility, workflow policy and operator experience. Specialist engines own the domain analysis for which they are authoritative. Adapters preserve original findings and version metadata instead of silently translating heuristics into facts.

### 2.6 One coherent platform

CLI, library API, MCP, web/desktop clients and automation must call the same application services and report contracts. They must not reimplement parsers or apply different meanings to the same finding.

### 2.7 Honest coverage and graceful failure

Every scan records limits, skips, unsupported inputs, truncation, provider failures and partial completion. One malformed file should not silently erase the rest of a scan. A failed provider must remain a failure, not an empty-success result.

### 2.8 Maintainable engineering

Prefer small vertical slices over disconnected feature lists. Public contracts are versioned. Resource ceilings are applied at the operation that consumes resources. Tests include malformed, boundary, adversarial and cross-platform cases. Dependencies and external engines require license and supply-chain review.

## 3. Users and jobs to be done

| User | Primary job | ORIX outcome |
|---|---|---|
| Software developer | Understand an unfamiliar repository, dependencies and build outputs | Source map, dependency graph, findings, explanations and reproducible reports |
| Reverse engineer | Inspect authorized binaries and understand structures and code | Parser facts, symbols, disassembly/decompilation provider results and cross-references |
| Security researcher | Investigate a sample or project without unsupported certainty | Bounded static triage, provider evidence, provenance and reviewable case record |
| App analyst | Understand Android and other packaged application contents | Package inventory, manifests, resources, bytecode and signing metadata through appropriate engines |
| Maintainer / release engineer | Compare releases and identify new risk | Artifact identity, SBOM, dependency deltas, SARIF and signed release evidence |
| AI coding agent | Retrieve trustworthy project context and request bounded operations | Versioned tools, structured reports, explicit approvals and replayable tool records |
| Team / organization | Retain and share investigations | Access-controlled workspaces, portable case bundles, audit history and retention policy |

## 4. Product surfaces

### 4.1 CLI

The CLI is the automation-first interface. It must expose predictable commands, machine-readable JSON, stable exit codes, safe output behavior, clear help, cancellation and resource limits. Human output is a presentation layer, not an API.

### 4.2 Programmatic library

The public library is the canonical callable application surface. Public exports, schemas and compatibility policy must be explicit. CLI and MCP should call the same services.

### 4.3 MCP and agent interoperability

MCP exposes narrowly scoped ORIX operations, not arbitrary shell access. Tool schemas are validated on the server. Inputs and outputs are bounded. The tool catalog must communicate side effects, required approvals, data access, network behavior and output limits. Extracted file strings, repository content and provider output are untrusted data, never instructions.

The current server implements the 2025-03-26 stdio protocol. The 2026-07-28 MCP specification is the research target for a future compatibility upgrade; it is not currently claimed as supported. HTTP transport requires its own authentication, authorization, origin and session threat model.

### 4.4 Local web workspace

The existing browser report explorer is a report viewer, not yet a live analysis workspace. Its target evolution includes artifact/project inventory, filters, evidence details, dependency and symbol graphs, comparison, case history, provider state, workflow plans and accessible navigation. Browser rendering must treat report content as untrusted text and must not leak local artifacts to remote services by default.

### 4.5 Desktop workspace

A desktop shell is a later product surface for local file access, persistent workspaces, provider management, case review and richer graphs. It must not be started before stable application services, storage contracts and security boundaries exist.

### 4.6 API and automation

A local API and remote service are distinct deployments. Local APIs require explicit bind addresses and local access controls. Remote APIs require authentication, authorization, tenant isolation, audit trails, quotas, data-retention policy and secure secret handling. No public listener should be introduced as an accidental side effect of a local feature.

## 5. Capability domains and target outcomes

### 5.1 Artifact intake and identity

Support regular files, directories, archives and explicitly authorized remote acquisition through separate adapters. Record canonical identity, size, timestamps, acquisition source, content hashes, byte coverage and stability. Reject unsafe path types and symlink substitution. Remote acquisition must validate scheme, redirects, host policy, response size, timeouts and content hashes.

### 5.2 Format registry and parser framework

Maintain a versioned registry that separates signature recognition, parser availability, parser coverage and semantic validation. Each parser is pure over bounded bytes, uses checked arithmetic, reports unsupported structures, and has explicit limits for counts, strings, recursion and work. Preserve raw values and distinguish file offsets, virtual addresses, RVAs, indices and lengths.

Target format families include PE/COFF, ELF, Mach-O, WebAssembly, Android APK/DEX, ZIP-family containers, PDF, common image and database formats, package/container metadata and additional documented formats selected by demand. Recognition must never be described as parsing or validation.

### 5.3 Native binary analysis

Grow PE, ELF and Mach-O parsers through testable slices: extended tables, relocations, symbols, versioning, debug metadata, unwind information, resources, signing structures and architecture-specific metadata. Cryptographic verification must use well-defined algorithms and trust policies; merely decoding a certificate or CodeDirectory is not verification.

### 5.4 Disassembly and decompilation

Use specialist providers for mature instruction decoding and decompilation. Normalize functions, basic blocks, instructions, references, imports, exports, strings, data types, call graphs and decompiler output while preserving provider-native identifiers and exact versions. Function addresses and architecture context must remain explicit. No provider output should be labeled as ORIX-native parsing when an external engine produced it.

### 5.5 Source and repository intelligence

Expand bounded inventory into a structured project model: languages, build systems, entry points, source files, imports, symbols, module relationships, tests, configuration, containers, generated files, Git metadata, workspaces and architecture candidates. Replace regex-only extraction incrementally with language-aware parsers or LSP/compiler indexes where justified. Coverage must indicate which parser or heuristic produced each edge.

### 5.6 Dependency and software supply-chain intelligence

Resolve lockfiles where possible; preserve ecosystem, source, exact version, integrity, dependency scope and graph completeness. Support CycloneDX and SPDX interoperability, package URL normalization, license evidence, build provenance and signed attestations. Vulnerability enrichment must be a separate network-aware phase that records database/advisory source, retrieval time, affected-version range, aliases, fixed versions, package identity and match method. A dependency name match without version/range evaluation is not a confirmed vulnerability.

### 5.7 Security analysis

Separate deterministic structural indicators, source-code rules, secret scanning, vulnerability advisories, configuration checks and provider findings. Every rule requires a stable identifier, explanation, confidence, severity policy, bounded evidence and false-positive guidance. No generic score may disguise uncertainty. An empty finding list is not a safety certification.

### 5.8 Provider system

A provider integration is operational only after it has a reviewed manifest, explicit capabilities, platform checks, license metadata, executable identity/version probe, invocation adapter, normalized output contract, timeout/cancellation, output limits, process lifecycle handling, failure mapping, provenance and integration tests. A manifest is descriptive metadata, not a signature, authorization or sandbox.

Provider families to evaluate include Rizin, Ghidra, JADX, Semgrep, Syft, OSV-Scanner, Trivy and Frida. Proprietary tools such as IDA or Binary Ninja must remain user-installed and separately licensed unless redistribution is explicitly authorized. Integration priority is determined by domain value, quality, installation burden, supported platforms and evidence quality—not by tool count.

### 5.9 Runtime and dynamic investigation

Dynamic analysis is a distinct, opt-in subsystem. Before it is implemented, define authorization scope, disposable environment, snapshot lifecycle, process ownership, network policy, filesystem policy, time/memory/CPU quotas, cancellation, cleanup, telemetry integrity and evidence separation. Runtime observations must never be merged with static inference without provenance. No target should be run on the host merely because a user asked to inspect it.

### 5.10 Evidence and case management

Move from process-local identifiers and a local append-only ledger toward persistent, content-addressed evidence records and immutable analysis runs. Evidence needs stable IDs, artifact identity, parent/child links, tool/version, invocation profile, timestamp, source location, confidence, raw-output digest, limitations and retention policy. Cases should support annotations, timelines, relationships, comparison, export and independent verification.

The present SHA-256 JSONL ledger is tamper-evident, not tamper-proof, signed or a trusted timestamp service. Future storage must preserve the current portable verification story.

### 5.11 AI intelligence and engineering agents

The target AI layer is not a chatbot that guesses from filenames. It must operate on indexed project context and structured evidence. Required stages are: understand request, inspect available context, create a bounded plan, identify missing prerequisites, request approvals, invoke tools, validate results, summarize with citations to evidence, and propose next steps.

Model providers must be replaceable and carry capability, privacy, retention, cost and availability metadata. A fully offline mode should be possible for workflows that do not require a remote model. Model output is untrusted and cannot override authorization or policy. Code edits and builds require a patch preview, explicit approval and reproducible test evidence.

### 5.12 Workflow automation

Provide reusable investigation pipelines with typed inputs/outputs, branch conditions, time budgets, cancellation, retry policy, idempotency, audit logs and human approval gates. CI integrations must emit machine-readable results and must not silently download or execute untrusted provider binaries.

### 5.13 Visualization and reporting

Provide artifact structure views, section maps, import/export tables, symbol browsing, source navigation, dependency graphs, call graphs, evidence timelines, comparison views and report exports. Every visualization must link back to the exact underlying evidence. Visual summaries cannot hide skipped files, truncation or provider failure.

## 6. Cross-cutting quality requirements

| Area | Requirement |
|---|---|
| Correctness | Known-good fixtures, malformed fixtures, differential tests where an independent oracle exists |
| Resource safety | Explicit byte, count, depth, time, concurrency and output limits |
| Reliability | Structured errors, cancellation, cleanup, crash-safe storage and deterministic output |
| Security | Least privilege, no implicit execution, path confinement, secret redaction and reviewed network boundaries |
| Privacy | Local-first defaults, explicit data egress, retention controls and sanitized telemetry |
| Portability | CI on supported Node versions and Windows, Linux and macOS where behavior is claimed |
| Compatibility | Versioned schemas, migrations, additive evolution and deprecation policy |
| Performance | Reproducible corpora, peak memory/CPU and wall-clock measurements; no unsupported superiority claims |
| Accessibility | Keyboard support, readable contrast, semantic controls and large-report navigation |
| Licensing | SPDX review, attribution, license compatibility and no unauthorized vendor assets |
| Observability | Structured logs, operation IDs, limits, provider diagnostics and actionable failure details |
| Reproducibility | Commit, input digest, versions, options, schema, provider and time recorded for every run |

## 7. Canonical data model

The product architecture should converge on these domain concepts rather than creating separate incompatible shapes in each interface:

- **Artifact:** stable content identity, acquisition metadata, content type, hashes, size and custody facts.
- **Project:** repository root, revision, files, modules, manifests, lockfiles and project graph.
- **Analysis run:** immutable invocation, options, toolchain, start/end times, coverage, status and outputs.
- **Finding:** stable rule/provider identity, subject, severity, confidence, status, explanation and evidence references.
- **Evidence:** observed/derived/heuristic record with source, location, tool, version, digest and lineage.
- **Provider:** declared capabilities, actual installed identity, version, health, license, permissions and operational state.
- **Case:** collection of artifacts, runs, findings, evidence, annotations, relationships and export history.
- **Workflow:** versioned graph of typed steps, limits, approvals, execution receipts and results.
- **Workspace:** local or remote storage boundary, owners, access policy, retention and migration state.

Schema changes must be additive where possible. Breaking changes require a new schema version and migration notes. No data model should store raw secrets merely to support a display feature.

## 8. Security and trust boundaries

1. Artifact bytes, paths, file names, repository text, extracted strings, manifests, provider output and AI output are untrusted.
2. Static parsers never execute input bytes.
3. Project inventory never runs package scripts, build hooks or tests unless a separate, approved execution service is introduced.
4. Provider metadata is not proof of provider behavior.
5. A subprocess runner is not an OS sandbox.
6. Network enrichment is explicit and records what left the device.
7. Remote services require authentication, authorization, tenant isolation and auditability.
8. Secrets are redacted at collection and serialization boundaries, not merely hidden in the UI.
9. Dynamic analysis requires a disposable lab and explicit target authorization.
10. Destructive actions and code modifications require a plan and human approval.
11. Cancellation must terminate owned work and clean temporary artifacts to the extent guaranteed by the host platform.
12. Failure to enforce a security requirement must produce an explicit blocked/error state, not a silent downgrade.

## 9. Current truth and project links

The current implementation is narrower than this target. The implementation truth is maintained in [CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md), with technical details in the [README](../README.md), [architecture](ARCHITECTURE.md), [security model](SECURITY_MODEL.md), [format matrix](FORMATS.md), [provider contract](PROVIDERS.md), [MCP guide](MCP.md) and [roadmap](ROADMAP.md).

Do not claim that a target feature is present until source, tests, docs and CI agree.

## 10. Definition of done

A feature is complete only when all applicable gates pass:

- User-visible behavior has a precise contract and supported failure states.
- The owning module and public interface are identified.
- Inputs are validated and all untrusted work is bounded.
- Authorization and side effects are documented.
- Reports retain provenance, coverage and limitations.
- Unit, integration, malformed-input and regression tests are added.
- Cross-platform behavior is tested where claimed.
- Schemas, CLI help, MCP, UI and docs are updated consistently.
- License, dependency and data-egress implications are reviewed.
- CI passes on the supported matrix.
- The feature is labeled implemented only after the evidence above exists.

## 11. Research references

- [Model Context Protocol — 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28)
- [Model Context Protocol — 2026-07-28 release notes](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [Ghidra Headless Analyzer](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/Intermediate/HeadlessAnalyzer.html)
- [Rizin project and licensing notes](https://github.com/rizinorg/rizin)
- [Frida project](https://github.com/frida/frida)
- [OSV-Scanner JSON output](https://google.github.io/osv-scanner/output/)
- [OSV-Scanner source and SBOM scanning](https://google.github.io/osv-scanner/scan-source/)
- [Syft project](https://github.com/anchore/syft)
- [Trivy project](https://github.com/aquasecurity/trivy)
- [JADX project](https://github.com/skylot/jadx)

These references guide integration research. Their capabilities, versions, licensing and interfaces must be revalidated when an adapter is implemented.
