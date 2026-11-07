// JavaScript, tests/read-report.test.mjs, Node.js 20+, strict report acquisition tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { read_json_report } from '../src/core/read-report.mjs';

test('rejects malformed UTF-8 rather than decoding replacement characters', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-report-utf8-'));
  const file = path.join(directory, 'report.json');
  try {
    await writeFile(file, Buffer.concat([Buffer.from('{"value":"'), Buffer.from([0xc3, 0x28]), Buffer.from('"}')]));
    await assert.rejects(read_json_report(file), error => error.code === 'ORIX_COMPARE_INVALID_UTF8');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('accepts valid UTF-8 JSON', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-report-valid-'));
  const file = path.join(directory, 'report.json');
  try {
    await writeFile(file, Buffer.from('{"message":"café"}', 'utf8'));
    assert.deepEqual(await read_json_report(file), { message: 'café' });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
