// JavaScript, tests/cases.test.mjs, Node.js 20+, persistent case workflow regressions.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  create_case, list_cases, get_case, verify_case, add_case_artifact,
  record_case_analysis, add_case_finding, change_case_finding_status,
  add_case_note, add_case_relationship, change_case_status,
  export_case_bundle, import_case_bundle,
} from '../src/cases/store.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'orix-cases-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('case creation, listing and retrieval create a persistent event-sourced case', async t => {
  const root = await fixture(t);
  const created = await create_case(root, { title: 'Sample investigation', description: 'Authorized offline triage' });
  assert.equal(created.schema_version, 'orix.case.v1');
  assert.equal(created.case.title, 'Sample investigation');
  assert.equal(created.case.status, 'open');
  assert.equal(created.timeline.length, 1);
  const listed = await list_cases(root);
  assert.equal(listed.cases.length, 1);
  assert.equal(listed.cases[0].id, created.case.id);
  const loaded = await get_case(root, created.case.id);
  assert.equal(loaded.integrity.head_hash, created.integrity.head_hash);
});

test('case artifacts are content-addressed, workspace-confined and deduplicated', async t => {
  const root = await fixture(t);
  const file = path.join(root, 'sample.bin');
  await writeFile(file, Buffer.from('case artifact fixture'));
  const created = await create_case(root, { title: 'Artifact case' });
  const first = await add_case_artifact(root, created.case.id, file);
  const second = await add_case_artifact(root, created.case.id, file);
  assert.equal(first.duplicate, false);
  assert.equal(second.duplicate, true);
  assert.match(first.artifact.sha256, /^[a-f0-9]{64}$/);
  assert.equal(first.artifact.artifact_id, 'artifact-' + first.artifact.sha256);
  assert.equal((await get_case(root, created.case.id)).artifacts.length, 1);
  const outside = await mkdtemp(path.join(os.tmpdir(), 'orix-cases-outside-'));
  try {
    const external = path.join(outside, 'external.bin');
    await writeFile(external, 'outside');
    await assert.rejects(add_case_artifact(root, created.case.id, external), error => error.code === 'ORIX_CASE_ARTIFACT_OUTSIDE_WORKSPACE');
  } finally { await rm(outside, { recursive: true, force: true }); }
});

test('case records analysis reports, findings, evidence, relationships, notes and lifecycle transitions', async t => {
  const root = await fixture(t);
  const sample = path.join(root, 'sample.bin');
  await writeFile(sample, 'analysis fixture');
  const created = await create_case(root, { title: 'Workflow case' });
  const artifact = await add_case_artifact(root, created.case.id, sample);
  const report = {
    schema_version: 'orix.artifact.v1',
    artifact: { path: 'sample.bin', size_bytes: 16 },
    integrity: { digest: artifact.artifact.sha256 },
    coverage: { complete: true },
    indicators: [],
  };
  const run = await record_case_analysis(root, created.case.id, { report, tool: 'orix', tool_version: '0.5.0', options: { static_only: true } });
  const finding = await add_case_finding(root, created.case.id, {
    rule_id: 'ORIX_TEST_RULE', title: 'Review candidate', summary: 'Fixture observation',
    severity: 'medium', confidence: 'observed', artifact_id: artifact.artifact.artifact_id,
    run_id: run.analysis.run_id,
    evidence: [{ kind: 'string', summary: 'Observed fixture marker', source: 'orix.inspect', confidence: 'observed' }],
  });
  const evidence_id = finding.finding.evidence[0].evidence_id;
  const note = await add_case_note(root, created.case.id, 'Analyst review pending', { links: [{ type: 'finding', id: finding.finding.finding_id }] });
  const relationship = await add_case_relationship(root, created.case.id, {
    from_type: 'finding', from_id: finding.finding.finding_id,
    to_type: 'evidence', to_id: evidence_id, relation: 'supported_by', confidence: 'observed',
  });
  assert.ok(relationship.relationship.relationship_id);
  assert.ok(note.note.note_id);
  const changed = await change_case_finding_status(root, created.case.id, finding.finding.finding_id, 'triaged', 'Manual review started');
  assert.equal(changed.previous_status, 'open');
  assert.equal(changed.status, 'triaged');
  await change_case_status(root, created.case.id, 'in_review', 'Analyst opened case');
  const loaded = await get_case(root, created.case.id);
  assert.equal(loaded.analyses.length, 1);
  assert.equal(loaded.findings[0].status, 'triaged');
  assert.equal(loaded.findings[0].status_history.length, 2);
  assert.equal(loaded.notes.length, 1);
  assert.equal(loaded.relationships.length, 1);
  assert.equal(loaded.case.status, 'in_review');
  assert.equal((await verify_case(root, created.case.id)).valid, true);
});

test('case bundles export and import reports and event history without embedding source artifacts', async t => {
  const root = await fixture(t);
  const sample = path.join(root, 'sample.bin');
  await writeFile(sample, 'bundle fixture');
  const created = await create_case(root, { title: 'Portable case' });
  const artifact = await add_case_artifact(root, created.case.id, sample);
  await record_case_analysis(root, created.case.id, {
    report: { schema_version: 'orix.artifact.v1', artifact: { path: 'sample.bin' }, integrity: { digest: artifact.artifact.sha256 }, indicators: [] },
  });
  await add_case_note(root, created.case.id, 'Export review note');
  const bundle = path.join(root, 'portable-case');
  const exported = await export_case_bundle(root, created.case.id, bundle);
  assert.equal(exported.signed, false);
  const imported = await import_case_bundle(root, bundle);
  assert.equal(imported.case_id, created.case.id);
  assert.equal(imported.events, (await get_case(root, created.case.id)).timeline.length);
  assert.equal(imported.source_artifacts_embedded, false);
  assert.equal((await verify_case(root, created.case.id)).valid, true);
  await assert.rejects(import_case_bundle(root, bundle), error => error.code === 'ORIX_CASE_ALREADY_EXISTS');
});

test('case bundle import rejects modified members and leaves no partial case', async t => {
  const root = await fixture(t);
  const created = await create_case(root, { title: 'Tamper test' });
  const bundle = path.join(root, 'tamper-bundle');
  await export_case_bundle(root, created.case.id, bundle);
  const events = path.join(bundle, 'events.jsonl');
  const original = await readFile(events, 'utf8');
  await writeFile(events, original.replace('"case.created"', '"case.corrupt"'));
  const other_root = await mkdtemp(path.join(os.tmpdir(), 'orix-cases-import-'));
  try {
    await assert.rejects(import_case_bundle(other_root, bundle), error => error.code === 'ORIX_CASE_BUNDLE_DIGEST');
    assert.equal((await list_cases(other_root)).cases.length, 0);
  } finally { await rm(other_root, { recursive: true, force: true }); }
});

test('case artifact intake rejects symlink paths and invalid state transitions', async t => {
  const root = await fixture(t);
  const sample = path.join(root, 'sample.bin');
  const link = path.join(root, 'link.bin');
  await writeFile(sample, 'symlink fixture');
  await symlink(sample, link);
  const created = await create_case(root, { title: 'Boundary case' });
  await assert.rejects(add_case_artifact(root, created.case.id, link), error => error.code === 'ORIX_CASE_ARTIFACT_UNSAFE');
  await assert.rejects(change_case_status(root, created.case.id, 'unknown'), error => error.code === 'ORIX_CASE_INVALID_STATUS');
  await assert.rejects(add_case_finding(root, created.case.id, { rule_id: 'R', title: 'Finding', severity: 'extreme' }), error => error.code === 'ORIX_CASE_INVALID_FINDING');
});

test('case verification detects modified stored analysis reports', async t => {
  const root = await fixture(t);
  const created = await create_case(root, { title: 'Report integrity case' });
  const recorded = await record_case_analysis(root, created.case.id, {
    report: { schema_version: 'orix.artifact.v1', artifact: { path: 'sample.bin' }, integrity: { digest: 'a'.repeat(64) } },
  });
  const report_path = path.join(root, '.orix', 'cases', created.case.id, recorded.analysis.report_path);
  await writeFile(report_path, JSON.stringify({ schema_version: 'orix.artifact.v1', modified: true }));
  await assert.rejects(verify_case(root, created.case.id), error => error.code === 'ORIX_CASE_REPORT_DIGEST');
  await assert.rejects(export_case_bundle(root, created.case.id, path.join(root, 'bad-export')), error => error.code === 'ORIX_CASE_REPORT_DIGEST');
});

test('case event chain detects tampering and missing report bundle entries', async t => {
  const root = await fixture(t);
  const created = await create_case(root, { title: 'Integrity case' });
  const events = path.join(root, '.orix', 'cases', created.case.id, 'events.jsonl');
  const original = await readFile(events, 'utf8');
  await writeFile(events, original.replace('"Integrity case"', '"Modified case"'));
  await assert.rejects(verify_case(root, created.case.id), error => error.code === 'ORIX_LEDGER_HASH_MISMATCH');
});

test('listing an empty workspace is read-only and does not create case storage', async t => {
  const root = await fixture(t);
  const result = await list_cases(root);
  assert.equal(result.cases.length, 0);
  await assert.rejects(readFile(path.join(root, '.orix', 'cases')), error => error.code === 'ENOENT');
});
