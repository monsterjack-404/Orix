# ORIX Platform Expansion Blueprint

**Purpose:** Grow ORIX from a local static artifact workbench into a modular, evidence-first investigation platform covering native software, managed runtimes, mobile apps, websites, network traces, firmware and reproducible behavior experiments.

**Baseline reviewed:** 2026-11-04, ORIX 0.5.x. This is a delivery plan, not a claim that planned modules already work.

## Design rules

1. **Evidence before conclusions.** Every finding identifies its input artifact or observation, source location, analyzer/provider and version, confidence, coverage and derivation.
2. **Static before dynamic.** Static inspection is the default. Running binaries, opening browsers against targets, attaching to devices, capturing live traffic or replaying actions requires a separately configured provider and explicit scope.
3. **No silent execution.** Never run package scripts, app code, firmware, browser automation or device commands as a side effect of import or analysis.
4. **Bound every input.** File size, archive expansion, entry count, recursion depth, CPU time, subprocess output, graph size, network bytes, device actions and retained observations need ceilings and cancellation.
5. **Preserve originals.** Hash source artifacts and captures. Provider output is derived evidence and must not overwrite the original.
6. **Make uncertainty visible.** Implemented, partial, planned and research-required are distinct states. Parsers, heuristics, decompilers and observation providers disclose what they did not see.
7. **Local-first and privacy-aware.** No sample upload, live network request, telemetry, model call or device operation by default. Secret-bearing values and application payloads require explicit policies.

## Existing foundation

| Domain | Current state in 0.5.x | Verified boundary |
|---|---|---|
| Native formats | Partial | PE, ELF, Mach-O, universal Mach-O and WebAssembly have bounded structural parsers; no bundled general-purpose decompiler or runtime execution engine |
| Optional reverse-engineering tools | Partial | Rizin version probe, imports, bounded function inventory, address-scoped disassembly and opt-in `rz-ghidra` pseudocode; no dedicated Ghidra/JADX/Apktool adapter yet |
| JavaScript and source projects | Partial | Bounded JavaScript/TypeScript lexical import and declaration analysis, project graph and Electron static triage for direct literal webPreferences settings | Full ECMAScript/TypeScript AST, type/data-flow, IPC/preload/renderer runtime observation |
| .NET | Partial | PE/CLI header, CLR runtime flags, entry-point token and bounded metadata stream inventory | Metadata tables/heaps, IL bodies/instructions, PDB/debug data and decompilation |
| Android | Partial | Bounded APK ZIP entry reads with CRC32 validation, binary/plain XML manifest metadata, DEX header/link/data/table validation, class descriptors, native ABI and signer-entry inventory | DEX bytecode/methods, resources.arsc, intent filters, cryptographic signer verification, AAB and device/runtime observations |
| Website and browser | Partial / planned | Offline HTML structure, script/style/link/form/iframe inventory and heuristic review findings; offline HAR 1.2 analysis | Standards-complete DOM/CSS/source-map analysis, live browser observation, console/network trace and screenshots |
| Network traces | Partial | Offline HAR 1.2 metadata analysis; no PCAP/PCAPNG parser or live packet capture |
| Firmware | Planned | No firmware filesystem or firmware-specific parser is shipped |
| Evidence and workflows | Partial | Reports, evidence records, JSONL hash chain, comparisons and MCP/CLI; no relational case store or cross-case evidence graph |
| AI/RL environments | Planned | No behavior-recording format, replay engine, environment adapter or RL training runtime |

## Workstream 1 — Native binary analysis and decompilation

**Goal:** Provide a connected path from file identity to architecture, sections, symbols, imports, relocations, disassembly, control-flow and pseudocode—without confusing metadata parsing with recovered source.

Delivery sequence:
- Finish native parser contracts: distinct file-offset, RVA, virtual-address, slice and architecture address types; extended ELF numbering/notes; PE debug/PDB, load-config and bounded CLR directory metadata; Mach-O chained-fixup and Objective-C metadata as independent modules; richer WebAssembly instruction and control-flow indexing.
- Expand the existing Rizin provider to symbols, sections, strings, functions, references, disassembly and cross-references.
- Add a Ghidra headless adapter after license/distribution review. Capture processor language, tool version, options, scripts, time budget and normalized output.
- Define a provider-neutral function/symbol/xref/decompiler schema before supporting multiple decompilers.
- Label decompiler output as reconstructed pseudocode, not original source. Preserve address and function provenance.

Acceptance: benign PE/ELF/Mach-O fixtures across x86/x64/ARM/AArch64; malformed-offset and resource-budget tests; provider version compatibility; repeatable results; no target execution; explicit distinction among parsing, disassembly and decompilation.

## Workstream 2 — JavaScript, Electron and .NET

**JavaScript / TypeScript**
- Add a parser-backed AST adapter for selected syntax. Record parser/version and unsupported syntax.
- Resolve package exports, import maps, dynamic imports, CommonJS, workers, source maps and generated bundles only where fixtures demonstrate behavior.
- Map definitions, references, call candidates, event handlers, URL construction, storage use and process/child-process APIs to source locations.
- Keep regex findings low-confidence until AST or data-flow evidence supports stronger conclusions.

**Electron**
- Detect Electron projects from dependency and configuration evidence.
- Separate main, preload, renderer and utility-process contexts.
- Review context isolation, node integration, sandbox settings, navigation/window creation, IPC sender validation, preload bridge exposure, remote content and permission handling.
- Treat configuration findings as review leads, not proof of exploitability.
- Dynamic observation requires an explicitly launched disposable profile and bounded permissions.

**.NET**
- Implement bounded PE/CLI header and metadata-root parsing; tables, heaps, assembly/references, methods and signatures; managed-resource and strong-name structure triage.
- Add IL decoding as a separate bounded layer and optional PDB identity/source-link analysis.
- Integrate ILSpy or another compatible decompiler only after license/provider review. Decompiler output remains derived evidence.
- Add NuGet project/lockfile relationships without conflating declared and resolved versions.

Acceptance: versioned .NET fixtures, malformed metadata heap/table indices, overflow/count ceilings, deterministic C#/IL locations, provider provenance and no execution of inspected assemblies.

## Workstream 3 — Android APK, AAB and device observations

**Static package analysis**
- Implemented first slice: bounded ZIP entry extraction with CRC32 checks, AndroidManifest.xml binary/plain XML metadata, DEX header/table/class descriptor inventory, native ABI library inventory and signer-related entry inventory.\n- Remaining: resources.arsc, intent-filter/component correlation, DEX instructions/method bodies, ODEX/VDEX, signer-block parsing and cryptographic certificate verification.
- AAB: bundle metadata and module/split inventory; do not assume an AAB is directly installable.
- DEX/ART: header, string/type/proto/field/method/class tables, code-item framing, annotations and debug metadata with strict index/offset bounds.
- Correlate manifest components and permissions with DEX references, exported components, intent filters, network-security configuration, native libraries and resources.
- Add optional JADX and Apktool adapters using explicit executable paths and the bounded provider runner.

**Device/runtime observations**
- ADB, emulator and Frida integrations are later, separate permissions—not part of APK import.
- Require explicit device serial, app/package identity, action list, duration, capture-byte limit and approval.
- Use an isolated test device/emulator by default. Preserve install state, logs, screenshots, network capture and process/module observations as separate timestamped evidence.
- Do not collect unrelated device data; redact tokens, account identifiers and personal content before export.

Acceptance: benign open-source APK fixtures, malformed ZIP/DEX/AXML corpus, split APK fixtures, signer structure checks, provider timeout/cancellation tests, device-identity confirmation, explicit consent and cleanup/audit receipts.

## Workstream 4 — Website structure, scripts and browser observations

**Offline website inspection**\n- Implemented first slice: bounded HTML/HTM/XHTML page inventory, script/stylesheet/link/form/iframe/image references, selected metadata and heuristic security review findings. No page content is executed or fetched.\n- Remaining: standards-complete DOM, CSS and source-map analysis, richer asset graph and script-to-page relationship analysis.
- Inventory HTML, CSS, JavaScript bundles, service workers, manifests, source maps, WebAssembly assets and static resources.
- Parse HTML structure without executing scripts. Index forms, links, script imports, external origins, security-related meta tags and resource relationships.
- Correlate local source maps with generated bundles only when hashes and mapping ranges validate.
- Add parser-backed JavaScript analysis for dangerous sinks/sources and trust boundaries; heuristic-only results remain provisional.

**Browser observation**
- Add an optional Playwright/CDP adapter after provider threat modeling. Use a disposable profile, explicit target allowlist, navigation/action/time ceilings and download restrictions.
- Capture DOM snapshots, console errors, navigation, resource timings, screenshots, storage metadata and browser version.
- Do not store cookies, local-storage values or form secrets by default.
- Normalize browser network events to the same transaction/evidence schema used by HAR analysis.
- Distinguish observed browser behavior from static predictions and externally verified facts.

Acceptance: deterministic local sites; CSP, redirects, workers, service-workers, SPA and source-map fixtures; no external navigation by default; no persistent login profile; screenshot/DOM hashes and source references.

## Workstream 5 — Network capture and HAR

**Implemented first slice:** offline HAR 1.2 metadata analysis is available through the public parse/file APIs, the har CLI command and the workspace-confined orix.analyze_har MCP tool. It creates SHA-256 provenance, request/host/status/timing summaries and evidence-linked review findings. Request/response bodies, arbitrary header values, cookie values and query values are excluded from report output. URL paths and server IP addresses may still be sensitive. The capture is not independently authenticated and no requests are replayed.

Next:
- Add import/export normalization contracts for browser, proxy, mobile and test-runner captures.
- Add PCAP/PCAPNG parsing for bounded packet metadata and TCP/UDP flow indexes, with explicit snaplen/truncation and timestamp coverage.
- Add optional Wireshark/tshark or other protocol-decoder providers only through reviewed, bounded manifests.
- Keep TLS certificate validation, decryption and key-log use as separate explicit operations. Never imply encrypted payload inspection from flow metadata alone.
- Add DNS, HTTP/1.1, HTTP/2 and QUIC metadata only where tested parsers/providers establish protocol coverage.

Acceptance: golden HAR/PCAP corpus, truncation and malformed-length tests, no payload export by default, byte/entry/packet caps, accurate incomplete-capture labels and stable evidence references.

## Workstream 6 — Firmware and filesystem images

- Detect firmware containers and common filesystem signatures using a source-backed registry.
- Start with metadata-only parsers for recognized container headers and filesystem superblocks; add recursive extraction only after strict total-output, per-entry, ratio, nesting, path, CPU and cancellation budgets exist.
- Candidate families: TAR/GZIP, CPIO, SquashFS, cramfs, ext filesystems, UBI/UBIFS, Android boot/vendor boot images, device-tree blobs and common update containers.
- Add optional Binwalk-style provider integration only after executable provenance, license, process containment and output-directory isolation are reviewed.
- Correlate firmware components, native binaries, package manifests, certificates and SBOMs without asserting that an extracted file is installed or executed on a device.

Acceptance: benign firmware fixtures, malformed superblocks, nested archive bombs, path traversal, symlink/hardlink and duplicate-path tests; extraction disabled by default; explicit partial-coverage records.

## Workstream 7 — Evidence-backed investigation and case workflows

- Normalize evidence across file parsers, source analyzers, network captures, devices and providers: artifact digest, source location, address space, timestamp, engine/version, confidence, coverage and parent evidence IDs.
- Add finding lifecycle states: observed, suspected, validated, dismissed and accepted-risk. Keep these separate from severity.
- Add stable privacy-preserving fingerprints and deduplication. Correlation must explain why two records were linked and how strong the link is.
- Add a SQLite case store with migrations, transaction/recovery tests, artifact references, analysis runs, findings, annotations, timeline and evidence graph.
- Add portable case bundles with manifests/checksums and optional signatures. A hash chain is tamper-evident, not tamper-proof.
- Add repeatable recipes for native triage, APK review, web review, network capture review, firmware triage and before/after comparison.

Acceptance: every derived conclusion links to evidence; analyst assertions are distinct from machine observations; export/import detects missing/changed members; migrations are tested from every supported schema.

## Workstream 8 — Recorded behavior and AI/RL environments

The first deliverable is a **recording and replay contract**, not an unbounded autonomous agent.

A behavior trace should include:
- environment identity/version, host/device/emulator identity class, application/build hash and initial-state fingerprint;
- monotonic and wall-clock timestamps, action type, normalized arguments and approval record;
- observations such as screenshots, DOM snapshots, accessibility tree, console/network events and selected app state;
- transition identifiers, success/failure/timeout state, deterministic seed where applicable and evidence artifact hashes;
- privacy labels, redaction policy, omitted observations and completeness/coverage counters.

Then:
1. Build a deterministic replay runner for a small set of disposable local test environments.
2. Add adapters exposing observations/actions through a constrained Gymnasium-compatible interface or a documented neutral JSON protocol.
3. Keep action spaces allowlisted, rate-limited and resettable. Network, filesystem, device and account actions remain separate permissions.
4. Record each episode as evidence and preserve environment/build identity so results can be reproduced.
5. Only after reliability and containment gates pass, add optional policy-evaluation or RL training adapters. Training is not part of the current baseline.

Acceptance: deterministic local fixtures, replay-equivalence checks, state-reset tests, action-denial tests, wall-clock/action budgets, no self-escalation, and trace export with hashes and coverage limits.

## Delivery order

| Priority | Vertical slice | Required exit evidence |
|---|---|---|
| P0 | HAR analysis and evidence contract | Unit/integration tests, CLI/MCP parity, docs and main CI |
| P1 | Normalized evidence/address/finding contracts | Schemas, migration and provenance tests |
| P1 | Rizin expansion and native parser gaps | Golden fixtures, provider conformance and current CI |
| P2 | JavaScript AST and Electron intelligence | AST fixtures, IPC/preload tests and confidence labels; current lexical/Electron triage is partial |
| P2 | Android APK/DEX/AXML static analysis | Resource, intent-filter, DEX bytecode and signer verification slices; current metadata parser is partial |
| P2 | .NET PE/CLI metadata and IL indexing | Metadata tables/heaps, IL indexing and managed assembly corpus; current header/stream parser is partial |
| P3 | Offline website inspection and browser adapter | Standards-complete DOM/CSS/source-map analysis and separately authorized Playwright/CDP observation |
| P3 | Firmware metadata/filesystem parser slices | Format corpus, extraction safety and adversarial tests |
| P3 | PCAP/PCAPNG metadata analysis | Golden captures, truncation/fuzz tests and payload privacy contract |
| P4 | SQLite case store and evidence graph | Migrations, recovery, portable bundle and tamper tests |
| P5 | Behavior recording and deterministic replay | Replay-equivalence, reset and permission-denial tests |
| P6 | AI/RL adapters and authorized runtime lab | Explicit approvals, isolation, budgets, audit receipts and kill switch |

## Pull request rules

- Keep each PR to one coherent vertical slice; no feature bundle without owning tests.
- Add source, tests, docs, schemas and capability-status evidence together.
- Never add a fake command, empty provider, placeholder button or success-shaped stub.
- External tools must be optional, version-reported, time/output-bounded and license-reviewed.
- Live network, browser, process, device and target execution need independent opt-in and policy boundaries.
- Never label static heuristics as proof of runtime behavior or exploitability.
- Update the capability matrix only when implementation, tests, documentation and CI evidence all exist.
