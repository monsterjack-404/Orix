# Changelog

## Unreleased

### Added
- Local browser report explorer for artifact, directory-scan and project JSON reports, with filters, summaries, record details and CSV export.
- Shared normalized report-view API, loopback-only static server and browser/server boundary tests.

### Security and correctness
- Strict UTF-8 decoding for comparison report files and MCP JSON-RPC frames; malformed byte sequences are rejected instead of silently replaced.
- Viewer finding normalization omits matched credential values and CSV export guards spreadsheet formula prefixes.


## 0.5.0 — 2026-11-02

### Added
- Bounded PDF structural analysis for classic cross-reference tables, trailer metadata, incremental revisions, indirect objects, encryption and active-content markers.
- PE delay-import descriptors/thunks and base-relocation block/entry decoding.
- ELF GNU version requirements/definitions, VERSYM mappings, GNU hash bloom words, buckets and terminal-bit chains.
- Mach-O LC_SYMTAB nlist records and LC_DYSYMTAB symbol groups/indirect-symbol metadata.
- CycloneDX 1.5 SBOM generation and SARIF 2.1.0 report export.
- Baseline/current report comparison with artifact and indicator deltas.
- Append-only SHA-256 chained JSONL evidence ledger with bounded writes, concurrency locking, verification and listing.
- Workspace-confined MCP 2025-03-26 stdio server with eight typed ORIX tools.
- Expanded malformed-input, limit, mutation and integration tests.

### Security and correctness
- Rejects symlinked MCP targets and confines tool paths to configured workspace roots.
- Enforces parser count/range budgets and MCP request/response size ceilings.
- Canonicalizes evidence payloads and rejects accessors, malformed record shapes, broken hash links and partial final records.
- Keeps analysis static and read-only; inspected artifacts and project code are never executed.

### Boundaries
- This release does not provide dynamic execution, decompilation, certificate-chain trust verification, hosted MCP/HTTP transport, remote authentication, a persistent case database or a desktop UI.
- Structural metadata is not a malware verdict or a publisher-trust decision.
