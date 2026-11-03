# ORIX Competitive Landscape and Integration Strategy

**Status:** research baseline, not a benchmark result  
**Reviewed:** 2026-11-03  
**Scope:** reverse engineering, binary analysis, software supply-chain security, AI engineering agents, and interoperability.

This document is a product-engineering research artifact. It distinguishes capabilities documented by upstream projects from ORIX implementation status. It does not claim ORIX is faster, more accurate, or more capable than any competitor without reproducible measurements.

## 1. Executive position

ORIX should not attempt to reimplement every mature specialist engine. Its strongest product position is a unified, evidence-first workbench that:

1. Acquires and identifies artifacts safely.
2. Runs bounded native parsers for formats where ORIX can validate its own results.
3. Integrates specialist tools through explicit provider adapters.
4. Normalizes observations into a stable evidence model.
5. Correlates artifact, source, dependency, runtime, and security findings.
6. Exposes the same workflows through CLI, MCP, APIs, and eventually visual clients.
7. Preserves provenance, limitations, authorization scope, and reproducibility.

A specialist tool remains the authority for its own deep-analysis domain. ORIX owns orchestration, provenance, cross-domain correlation, workflow reproducibility, and the user-facing investigation record.

## 2. Competitive capability matrix

| Project | Primary strength documented upstream | ORIX response | Integration posture |
|---|---|---|---|
| [REA](https://github.com/morluto/rea) | AI-assisted reverse engineering through MCP/CLI workflows, multiple analysis providers, and retained evidence | Use as the closest architectural benchmark; maintain a compatibility and coverage matrix | Study contracts and workflows; do not copy implementation without license review |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Multi-platform SRE framework with disassembly, decompilation, graphing, scripting, and extension support | Delegate deep native analysis and import normalized results with provider/version metadata | Optional installed provider; headless adapter first |
| [Rizin](https://github.com/rizinorg/rizin) | Portable reverse-engineering framework, debugger, forensic and scripting capabilities, broad architecture/format support | Add a high-value open provider for static analysis and scripted inspection | Optional executable adapter; capability probe and version capture |
| [Cutter](https://github.com/rizinorg/cutter) | GUI built around Rizin with graphing and interactive analysis | Treat as an external analyst UI, not a dependency of the ORIX core | Deep link/export integration where feasible |
| [Binary Ninja](https://binary.ninja/) | Interactive disassembly, decompilation, debugging, automation APIs, graph visualization, plugins and collaboration | Support licensed installations through an adapter; never bundle proprietary components | Optional licensed provider |
| [Frida](https://github.com/frida/frida) | Dynamic instrumentation toolkit for runtime observation and scripting | Add only behind explicit target authorization, scope, lifecycle and audit controls | Optional dynamic provider; isolated lab profiles |
| [JADX](https://github.com/skylot/jadx) | Android DEX/APK decompilation and resource-oriented inspection | Add Android static-analysis provider and map outputs into artifact/evidence identities | Optional local provider |
| [Semgrep](https://github.com/semgrep/semgrep) | Configurable source-code pattern analysis and security rules | Import structured findings and preserve rule IDs, paths, lines and engine versions | External SAST adapter |
| [CodeQL](https://codeql.github.com/docs/) | Semantic code analysis using queryable program representations | Add SARIF ingestion and workflow orchestration; do not claim query equivalence | GitHub/CLI integration subject to licensing and service terms |
| [Syft](https://github.com/anchore/syft) | SBOM generation across filesystems, images and package ecosystems | Compare its inventory with ORIX manifests and lockfile graph; ingest CycloneDX/SPDX | Optional SBOM provider |
| [Trivy](https://github.com/aquasecurity/trivy) | Vulnerability, misconfiguration, secret and artifact scanning | Import structured findings and avoid duplicating its vulnerability database | Optional scanner adapter |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Dependency vulnerability scanning backed by OSV data, including lockfiles and SBOM workflows | Add vulnerability intelligence as a separate enrichment stage with database timestamp and package identity | Optional networked provider; offline mode must be explicit |
| [OpenHands](https://github.com/All-Hands-AI/OpenHands) | Agentic software-engineering workflows with sandboxed execution and integrations | ORIX can provide verified findings/work plans to external coding agents; do not silently grant write access | Agent hand-off / MCP integration |
| [Cline](https://github.com/cline/cline) | Model-flexible coding agent across IDE, terminal and SDK surfaces, with approvals and MCP | Expose ORIX tools through stable MCP contracts and approval metadata | MCP client/server interoperability |
| [Aider](https://github.com/Aider-AI/aider) | Terminal-first AI pair-programming with repository-aware edits | Provide reports, patch context and test evidence to coding workflows | CLI and structured report interoperability |
| [MCP](https://modelcontextprotocol.io/specification/) | Standard protocol for exposing tools and context to AI applications | Keep ORIX MCP schemas versioned, narrow, validated and backed by shared application workflows | First-class protocol boundary |

## 3. What the comparison means for ORIX

### 3.1 Do not compete by duplicating specialist engines

Ghidra, Rizin, Binary Ninja, JADX, Frida, Semgrep, Syft, Trivy and OSV-Scanner solve different technical problems. A shallow in-house imitation would create maintenance cost without matching their domain depth.

ORIX should own:
- Safe artifact intake and identity.
- Cross-provider normalization.
- Evidence lineage and chain-of-custody metadata.
- Multi-stage investigation workflows.
- Cross-domain relationship graphs.
- Provider health, capability, version and limitation reporting.
- Reproducible exports and comparisons.
- A coherent operator experience across CLI and MCP.

### 3.2 Provider contracts are a product boundary

Every provider adapter should declare:
- Stable provider ID and adapter version.
- Executable/package identity and observed version.
- Supported operating systems and architectures.
- Capability IDs and unsupported operations.
- Required permissions and network behavior.
- Input artifact types and size constraints.
- Timeout, cancellation and output limits.
- Whether execution is static, dynamic, networked or state-changing.
- Output schema version and provenance fields.
- License and redistribution notes.

A provider failure must remain visible. ORIX must not silently switch to a different provider and present the result as equivalent.

### 3.3 Findings must retain source provenance

Every imported result should retain:
- Original provider finding ID and rule ID.
- Provider name/version and invocation profile.
- Input artifact SHA-256 or source revision.
- Original path and source location.
- Provider timestamp and ORIX ingestion timestamp.
- Confidence/severity as reported by the provider.
- Any ORIX normalization or mapping applied.
- Raw-result reference or content digest.
- Known limitations and incomplete coverage.

Normalization must not upgrade heuristic findings into confirmed vulnerabilities.

## 4. ORIX current baseline

The current repository branch implements a local-first Node.js CLI/library with bounded static inspection, parsers, source-project inventory, lockfile analysis, reports, evidence ledger, comparison workflows and a local stdio MCP server.

Implemented code must be checked against the current README, tests and release metadata before every release. The following are not implied to exist merely because they appear in the long-term product vision:

- Hosted web dashboard.
- Native desktop application.
- Relational database or multi-user server.
- Distributed execution workers.
- Full Ghidra/IDA/Binary Ninja/Frida provider coverage.
- Complete decompilation for every executable format.
- Cloud AI orchestration.
- Marketplace or third-party plugin sandbox.

## 5. Prioritized engineering roadmap

### P0 — Reliability and contract hardening

- Version every public report and provider contract.
- Add golden fixtures for PE, ELF, Mach-O, ZIP, PDF, WASM, APK/DEX and malformed variants.
- Add differential tests against upstream tools where their output is suitable as an oracle.
- Add fuzzing budgets, corpus retention and crash triage.
- Test Windows, Linux and macOS filesystem semantics.
- Add package tarball and clean-install verification.
- Validate every documented command in CI.

### P1 — Provider foundation

- Provider manifest schema and capability registry.
- Provider discovery without executing untrusted project hooks.
- Version and health probes with strict timeouts.
- Process ownership, cancellation, output caps and cleanup.
- Structured adapter results and stable error taxonomy.
- First adapters: Ghidra headless, Rizin, JADX, Syft, OSV-Scanner and Semgrep.
- Optional proprietary adapters only for user-installed, licensed tools.

### P2 — Evidence and correlation

- Evidence parent/child lineage.
- Content-addressed raw provider output.
- Artifact-to-source and package-to-binary relationships.
- SARIF, CycloneDX and SPDX ingestion validation.
- Comparison across provider versions and analysis profiles.
- Explicit confidence and coverage semantics.

### P3 — Source and supply-chain intelligence

- Additional lockfile ecosystems and workspace resolution.
- Vulnerability enrichment with database snapshot metadata.
- License policy and attribution reports.
- Build provenance and signed attestation ingestion.
- Secret scanning with redaction-preserving evidence.
- IaC/container and image inventory through optional providers.

### P4 — Authorized runtime investigation

- Explicit target authorization record and scope.
- Disposable lab workspace and environment profile.
- Read-only observation mode before instrumentation.
- Provider-specific side-effect declaration.
- Time, memory, process and output limits.
- Cancellation and reliable teardown.
- Audit trail for every dynamic action.

### P5 — Agent and operator experience

- MCP tools backed by the same application services as CLI.
- Human approval for writes, execution, network access and destructive actions.
- Model-provider abstraction with cost, privacy and capability metadata.
- Agent plans, tool-call logs, evidence citations and replayable workflows.
- Web/desktop UI only after stable API and session contracts exist.

## 6. Benchmark protocol

No performance or quality superiority claim is valid without a repeatable protocol.

Each benchmark record must include:
- ORIX commit and release.
- Provider names and exact versions.
- Host OS, CPU, RAM and storage.
- Input corpus digest and license/source.
- Analysis profile and resource ceilings.
- Warm/cold cache state.
- Wall-clock time, CPU time and peak memory where measurable.
- Parse success, coverage and skipped-input counts.
- Finding precision/recall only when a labeled corpus exists.
- Output schema and evidence-integrity validation.
- Repeated runs and statistical summary.

Compare like-for-like tasks. A fast signature scan is not comparable to a full decompilation. Report capability, correctness, performance and usability as separate dimensions.

## 7. Licensing and integration policy

- Keep ORIX-authored code under Apache-2.0 as declared by the repository.
- Verify each dependency and provider license before bundling, redistributing or copying code.
- Prefer process/API adapters for separately installed proprietary tools.
- Preserve required copyright, attribution, NOTICE and source-offer obligations.
- Do not copy vendor assets, proprietary databases or undocumented APIs.
- Record provider version, license family, installation source and redistribution status.
- Re-check terms before each release; license metadata can change.

## 8. Acceptance gates

A new provider or engine is not complete until:
1. Its contract and threat model are documented.
2. Inputs are validated and bounded.
3. Provider version and capabilities are captured.
4. Timeouts, cancellation and cleanup are tested.
5. Errors are normalized without hiding the provider failure.
6. Results retain provenance and limitations.
7. Golden and malformed fixtures pass.
8. CLI/MCP/API exposure is documented consistently.
9. License and redistribution status is reviewed.
10. Clean-environment CI verifies installation and execution.

## 9. Upstream research references

- REA: https://github.com/morluto/rea
- Ghidra: https://github.com/NationalSecurityAgency/ghidra
- Rizin: https://github.com/rizinorg/rizin
- Cutter: https://github.com/rizinorg/cutter
- Binary Ninja: https://binary.ninja/
- Frida: https://github.com/frida/frida
- JADX: https://github.com/skylot/jadx
- Semgrep: https://github.com/semgrep/semgrep
- CodeQL: https://codeql.github.com/docs/
- Syft: https://github.com/anchore/syft
- Trivy: https://github.com/aquasecurity/trivy
- OSV-Scanner: https://github.com/google/osv-scanner
- OpenHands: https://github.com/All-Hands-AI/OpenHands
- Cline: https://github.com/cline/cline
- Aider: https://github.com/Aider-AI/aider
- Model Context Protocol: https://modelcontextprotocol.io/specification/

---

**Research rule:** upstream feature claims are not ORIX implementation claims. Update this matrix when provider versions, capabilities, licenses or ORIX adapters change.
