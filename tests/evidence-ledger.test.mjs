// JavaScript, tests/evidence-ledger.test.mjs, Node.js 20+, tamper-evident evidence ledger tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  create_evidence_ledger,
  append_evidence_event,
  verify_evidence_ledger,
  read_evidence_ledger,
} from '../src/core/evidence-ledger.mjs';

async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'orix-ledger-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'evidence.jsonl');
  await create_evidence_ledger(file);
  return { directory, file };
}

test('ledger creates an exclusive file and verifies an empty genesis chain', async t => {
  const { file } = await fixture(t);
  const result = await verify_evidence_ledger(file);
  assert.equal(result.valid, true);
  assert.equal(result.records, 0);
  assert.equal(result.head_hash, '0'.repeat(64));
  await assert.rejects(create_evidence_ledger(file), error => error.code === 'ORIX_LEDGER_ALREADY_EXISTS');
});

test('ledger appends canonical records and links each record to its predecessor', async t => {
  const { file } = await fixture(t);
  const first = await append_evidence_event(file, 'scan.completed', { z: 3, a: { y: 2, x: 1 } });
  const second = await append_evidence_event(file, 'artifact.inspected', { sha256: 'a'.repeat(64), size: 42 });
  assert.equal(first.sequence, 1);
  assert.equal(second.sequence, 2);
  assert.equal(second.previous_hash, first.hash);
  const report = await verify_evidence_ledger(file);
  assert.equal(report.records, 2);
  const loaded = await read_evidence_ledger(file);
  assert.deepEqual(loaded.records[0].payload, { a: { x: 1, y: 2 }, z: 3 });
});

test('ledger detects payload edits, record deletion and partial final writes', async t => {
  const { file } = await fixture(t);
  await append_evidence_event(file, 'scan.completed', { files: 2 });
  const original = await readFile(file, 'utf8');
  const edited = original.replace('"files":2', '"files":3');
  await writeFile(file, edited);
  await assert.rejects(verify_evidence_ledger(file), error => error.code === 'ORIX_LEDGER_HASH_MISMATCH');
  await writeFile(file, original.trimEnd());
  await assert.rejects(verify_evidence_ledger(file), error => error.code === 'ORIX_LEDGER_PARTIAL_TAIL');
});

test('ledger rejects malformed events and unsafe payload values', async t => {
  const { file } = await fixture(t);
  await assert.rejects(append_evidence_event(file, 'Bad Event', {}), error => error.code === 'ORIX_LEDGER_EVENT_INVALID');
  await assert.rejects(append_evidence_event(file, 'scan.completed', { value: Number.NaN }), error => error.code === 'ORIX_LEDGER_NONFINITE_NUMBER');
  const circular = {}; circular.self = circular;
  await assert.rejects(append_evidence_event(file, 'scan.completed', circular), error => error.code === 'ORIX_LEDGER_CIRCULAR_VALUE');
});

test('ledger enforces read, record and lock limits', async t => {
  const { file } = await fixture(t);
  await append_evidence_event(file, 'scan.completed', { note: 'bounded' });
  await assert.rejects(verify_evidence_ledger(file, { max_bytes: 256, max_record_bytes: 256 }), error => error.code === 'ORIX_LEDGER_SIZE_LIMIT');
  await assert.rejects(verify_evidence_ledger(file, { max_bytes: 4096, max_record_bytes: 256 }), error => error.code === 'ORIX_LEDGER_RECORD_LIMIT');
});

test('ledger serializes concurrent appends through an exclusive directory lock', async t => {
  const { file } = await fixture(t);
  await Promise.all(Array.from({ length: 8 }, (_, index) => append_evidence_event(file, 'test.concurrent', { index })));
  const report = await verify_evidence_ledger(file);
  assert.equal(report.records, 8);
  const loaded = await read_evidence_ledger(file);
  assert.deepEqual(loaded.records.map(record => record.sequence), [1,2,3,4,5,6,7,8]);
});


test('ledger rejects accessor payloads and records with unhashed extension fields', async t => {
  const { file } = await fixture(t);
  const payload = {};
  Object.defineProperty(payload, 'secret', { enumerable: true, get() { throw new Error('getter must not run'); } });
  await assert.rejects(append_evidence_event(file, 'scan.completed', payload), error => error.code === 'ORIX_LEDGER_ACCESSOR_VALUE');
  await append_evidence_event(file, 'scan.completed', { safe: true });
  const original = await readFile(file, 'utf8');
  const record = JSON.parse(original);
  record.unhashed_claim = 'must be rejected';
  await writeFile(file, JSON.stringify(record) + '\n');
  await assert.rejects(verify_evidence_ledger(file), error => error.code === 'ORIX_LEDGER_RECORD_SHAPE');
});


test('ledger rejects accessor and sparse array payload elements without invoking getters', async t => {
  const { file } = await fixture(t);
  const accessor_array = [];
  Object.defineProperty(accessor_array, '0', {
    enumerable: true,
    get() { throw new Error('array getter must not run'); },
  });
  accessor_array.length = 1;
  await assert.rejects(
    append_evidence_event(file, 'scan.completed', { values: accessor_array }),
    error => error.code === 'ORIX_LEDGER_ACCESSOR_VALUE',
  );
  await assert.rejects(
    append_evidence_event(file, 'scan.completed', { values: new Array(1) }),
    error => error.code === 'ORIX_LEDGER_SPARSE_ARRAY',
  );
});
