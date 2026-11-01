// JavaScript, tests/core.test.mjs, Node.js 20+, core primitive and evidence semantics.

import test from 'node:test';
import assert from 'node:assert/strict';
import { calculate_entropy } from '../src/core/entropy.mjs';
import { extract_strings } from '../src/core/strings.mjs';
import { hash_buffer } from '../src/core/hash.mjs';
import { resolve_limits } from '../src/core/limits.mjs';
import { create_evidence, reset_evidence_sequence_for_tests } from '../src/core/evidence.mjs';
import { BinaryReader } from '../src/core/binary-reader.mjs';

test('SHA-256 hashes exact bytes', () => {
  assert.equal(hash_buffer(Buffer.from('abc')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('entropy distinguishes uniform and constant byte distributions', () => {
  assert.equal(calculate_entropy(Buffer.alloc(100, 0)).bits_per_byte, 0);
  assert.equal(calculate_entropy(Buffer.from([0,1,2,3])).bits_per_byte, 2);
  assert.equal(calculate_entropy(Buffer.alloc(0)).sample_size, 0);
});

test('string extraction returns offsets and supports UTF-16LE', () => {
  const buffer = Buffer.concat([Buffer.from('prefix\0HELLO_WORLD\0suffix\0'), Buffer.from('WIDE_TEXT', 'utf16le')]);
  const strings = extract_strings(buffer, { minimum: 5, limit: 20 });
  assert.ok(strings.some(item => item.value === 'HELLO_WORLD' && item.encoding === 'ascii'));
  assert.ok(strings.some(item => item.value === 'WIDE_TEXT' && item.encoding === 'utf16le'));
  assert.ok(strings.every(item => Number.isSafeInteger(item.offset) && item.offset >= 0));
});

test('resource limits enforce cross-field invariants', () => {
  assert.throws(() => resolve_limits({ max_read_bytes: 100, max_file_bytes: 50 }), /cannot exceed/);
  assert.equal(resolve_limits({ max_scan_concurrency: 2 }).max_scan_concurrency, 2);
});

test('evidence requires provenance and retains structured details', () => {
  reset_evidence_sequence_for_tests();
  const item = create_evidence({ kind: 'signature', summary: 'MZ header observed', source: 'sample.exe', offset: 0, length: 2, details: { bytes: '4d5a' } });
  assert.equal(item.id, 'ev-000001');
  assert.equal(item.confidence, 'observed');
  assert.equal(item.details.bytes, '4d5a');
  assert.throws(() => create_evidence({ kind: 'x', summary: 'y' }), /requires/);
});

test('binary reader rejects out-of-range access with a typed error', () => {
  const reader = new BinaryReader(Buffer.from([1,2,3]));
  assert.equal(reader.u16(0, true), 0x0201);
  assert.throws(() => reader.u32(0), error => error.code === 'ORIX_TRUNCATED_INPUT');
});
