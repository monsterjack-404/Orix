# Changelog

## Unreleased

### Added
- Bounded WebAssembly structure indexing for function types, imports, exports, function/type references, start function metadata, code-body byte ranges and standard module/function names.
- Optional Rizin static import adapter with input SHA-256 provenance, bounded private artifact snapshots, tamper detection, bounded JSON normalization and a versioned report schema.
- Explicit `providers rizin doctor` command and `probe_rizin` API for checking an absolute Rizin executable and recording its version/runtime diagnostics.
- Browser-local report viewer support for Rizin import inventories and provider probe reports, including searchable symbol rows and CSV export.
- Scheduled GitHub CodeQL `security-extended` analysis for JavaScript/TypeScript and weekly Dependabot updates for GitHub Actions.
- Expanded CI with Windows and macOS smoke suites on Node.js 22 alongside the Node.js 20/22/24 Linux matrix.
- Shell-free static provider runner with exact canonical executable and working-directory allowlists, symlink rejection, blocked command-search/loader environment overrides, timeout, cancellation and captured-output ceilings.
- Versioned `orix.provider-execution.v1` process outcome receipts with exit/termination details and effective resource limits.
- `providers list` and `providers rizin imports` CLI commands with JSON and Markdown output.

### Security and correctness
- WebAssembly section boundaries, UTF-8 names, import descriptors, reference indices, vector ceilings and function/code counts receive regression coverage.
- External provider commands require explicit executable configuration and do not execute the inspected target.
- Provider runtime limits are enforced at the process boundary; the runner is not an OS sandbox and cannot enforce provider filesystem/network behavior.
- Rizin input size, digest and before/after file identity are checked; the provider receives a byte-bounded private snapshot rather than the original file, and snapshot content is verified after execution.
- Rizin analysis timeout spans hashing, bounded snapshot creation, version probe and import extraction.
- Rizin adapter and doctor reject execution when the selected manifest excludes the current normalized runtime platform.
- Provider stdout/stderr capture, argument/environment sizes and import result counts are bounded.

### Boundaries
- Rizin is an optional external installation. Automated adapter tests use a deterministic CLI fixture and do not replace testing against each upstream Rizin release.
- The WebAssembly parser is a structural indexer, not a complete validator, instruction decoder or decompiler.
- Windows process-tree teardown is not guaranteed by the current provider runner; OS-level sandboxing and dynamic target execution are not implemented.
- Ghidra, IDA and Hopper adapters, provider installation, automatic discovery and a plugin loader remain unimplemented.

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
- Keeps built-in analysis static and read-only; inspected artifacts and project code are never executed.

### Boundaries
- This release does not provide dynamic execution, decompilation, certificate-chain trust verification, hosted MCP/HTTP transport, remote authentication, a persistent case database or a desktop UI.
- Structural metadata is not a malware verdict or a publisher-trust decision.
