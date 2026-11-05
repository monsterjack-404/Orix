# ORIX Investigation Cases

ORIX case management stores a durable, local investigation history around the existing artifact analyzers and SHA-256 evidence ledger.

## Storage model

- Cases live under .orix/cases/<case-uuid>/ inside an existing workspace.
- events.jsonl is the authoritative append-only event history. Each event is protected by the existing sequence-checked SHA-256 hash chain.
- Case state is reconstructed from verified events; there is no mutable database snapshot that can silently diverge from the ledger.
- Analysis reports are copied into the case under reports/<run-uuid>.json, with a SHA-256 digest, schema version, tool identity, options digest, coverage and limitations.
- Source artifacts are not copied. The case stores a workspace-relative path, SHA-256, size, parser status and stability observation. Moving or deleting the original file can make that reference unavailable; the recorded digest remains.
- Case/finding state transitions, notes and typed relationships are events, so the timeline is auditable.

The implementation uses Node.js built-ins and remains compatible with the project's Node.js 20.11+ baseline. It deliberately does not require node:sqlite: that module was introduced in Node.js 22.5 and remains experimental in the Node.js 22 line. A future SQLite adapter must preserve the same event/export verification contract rather than becoming the only readable copy.

## CLI

    node src/cli.mjs case create ./workspace "Sample investigation" "Authorized offline review"
    node src/cli.mjs case list ./workspace
    node src/cli.mjs case add-artifact ./workspace <case-uuid> ./workspace/sample.exe
    node src/cli.mjs case analysis ./workspace <case-uuid> ./workspace/report.json orix 0.5.0
    node src/cli.mjs case finding ./workspace <case-uuid> ORIX_RULE "Review candidate" "Why it matters" medium observed
    node src/cli.mjs case note ./workspace <case-uuid> "Needs manual confirmation"
    node src/cli.mjs case finding-status ./workspace <case-uuid> <finding-uuid> triaged "Review started"
    node src/cli.mjs case status ./workspace <case-uuid> in_review "Analyst opened case"
    node src/cli.mjs case show ./workspace <case-uuid> --json
    node src/cli.mjs case verify ./workspace <case-uuid>
    node src/cli.mjs case export ./workspace <case-uuid> ./case-bundle
    node src/cli.mjs case import ./workspace ./case-bundle

Use --json for machine-readable output. Existing report files are never overwritten.

## Programmatic API

The @orix/cli/cases export exposes create_case, list_cases, get_case, verify_case, add_case_artifact, record_case_analysis, add_case_finding, change_case_finding_status, add_case_note, add_case_relationship, change_case_status, export_case_bundle and import_case_bundle.

## Case lifecycle and evidence graph

- Case states: open, in_review, closed.
- Finding states: open, triaged, confirmed, false_positive, accepted_risk, resolved.
- Entity types for links: case, artifact, analysis, finding, note, evidence.
- Relationship direction and confidence are preserved exactly as entered. ORIX does not infer a relationship merely because two records share a path or string.
- Evidence items are scoped to findings and receive stable UUIDs inside the case; the existing process-local create_evidence helper is not used as a persistent identifier.

## Portable bundles

A bundle is a directory containing a manifest, the original event ledger and the analysis reports referenced by events. Import validates each listed file's size and SHA-256, validates the event chain and checks the manifest's case ID, event count and head hash before accepting the case. Existing case IDs are never overwritten.

Source artifact bytes are intentionally excluded. Bundles are unsigned: hashes detect accidental corruption and tampering relative to the manifest, but an attacker able to rewrite both the manifest and event chain can construct a new internally consistent bundle. No publisher identity, digital signature, trusted timestamp, remote transparency log or immutable storage is claimed.

## Limits and security

- Maximum 1,000 cases returned per listing; the ledger itself retains its existing 64 MiB default and 1 MiB per-record limits.
- Analysis report files are capped at 2 MiB; bundle manifests at 2 MiB, 512 members and 64 MiB aggregate member bytes.
- Only regular non-symlink artifact files inside the selected workspace are registered.
- Reports and case data are local and may contain paths or analyst notes; review before sharing.
- Imported reports are data only. No report, artifact or provider output is executed.
- This is a local single-user workspace, not a multi-user database or access-control system.
- Cross-case graph queries, full artifact object storage, signatures, trusted timestamps, retention/deletion policy, database migrations and browser case UI remain future work.

## Provenance alignment

The model follows the useful separation in W3C PROV between entities, activities and agents, while keeping ORIX's own versioned JSON contracts. Analysis reports are entities generated by recorded analysis activities; artifacts are inputs; the tool identity is recorded as the acting software. This is a mapping, not a claim of complete PROV-O serialization.
