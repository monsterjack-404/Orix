// JavaScript, tests/ledger.test.mjs, Node.js 20+, evidence-ledger integrity and filesystem tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { append_ledger, list_ledger, verify_ledger } from '../src/evidence/ledger.mjs';

async function with_temp_dir(callback) {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-ledger-'));
  try { await callback(directory); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

test('ledger appends deterministic sequence and verifies hash-chain provenance', async () => {
  await with_temp_dir(async directory => {
    const file = path.join(directory, '.orix', 'evidence.jsonl');
    const first = await append_ledger(file, { type: 'artifact.inspected', payload: { sha256: 'a'.repeat(64), path: 'sample.bin' } });
    const second = await append_ledger(file, { type: 'scan.completed', payload: { files: 4 } });
    assert.equal(first.sequence, 1);
    assert.equal(second.sequence, 2);
    assert.equal(second.previous_hash, first.record_hash);
    const verified = await verify_ledger(file);
    assert.equal(verified.valid, true);
    assert.equal(verified.records_verified, 2);
    assert.equal(verified.head_hash, second.record_hash);
    const listed = await list_ledger(file);
    assert.equal(listed.records[1].type, 'scan.completed');
  });
});

test('ledger detects content tampering and refuses incomplete trailing records', async () => {
  await with_temp_dir(async directory => {
    const file = path.join(directory, 'ledger.jsonl');
    await append_ledger(file, { type: 'artifact.inspected', payload: { count: 1 } });
    const original = await readFile(file, 'utf8');
    await writeFile(file, original.replace('"count":1', '"count":2'));
    await assert.rejects(verify_ledger(file), error => error.code === 'ORIX_LEDGER_HASH_MISMATCH');
    await writeFile(file, original.trimEnd());
    await assert.rejects(verify_ledger(file), error => error.code === 'ORIX_LEDGER_PARTIAL_TAIL');
  });
});

test('ledger rejects symlinks and malformed record sizes', async () => {
  await with_temp_dir(async directory => {
    const target = path.join(directory, 'real.jsonl');
    const link = path.join(directory, 'link.jsonl');
    await writeFile(target, '');
    await symlink(target, link);
    await assert.rejects(verify_ledger(link), error => error.code === 'ORIX_LEDGER_NOT_REGULAR_FILE');
    await assert.rejects(append_ledger(path.join(directory, 'small.jsonl'), { type: 'test', payload: { data: 'x'.repeat(400) } }, { max_record_bytes: 256 }), error => error.code === 'ORIX_LEDGER_RECORD_LIMIT');
  });
});

test('ledger rejects concurrent writer lock rather than interleaving records', async () => {
  await with_temp_dir(async directory => {
    const file = path.join(directory, 'locked.jsonl');
    await import('node:fs/promises').then(({ mkdir }) => mkdir(file + '.lock'));
    await assert.rejects(append_ledger(file, { type: 'test', payload: { ok: true } }, { lock_wait_ms: 0 }), error => error.code === 'ORIX_LEDGER_LOCK_TIMEOUT');
  });
});
