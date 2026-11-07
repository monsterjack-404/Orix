// JavaScript, tests/inspect.test.mjs, Node.js 20+, artifact inspector regression suite.

import test from 'node:test';
import assert from 'node:assert/strict';
import { link, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { inspect_file } from '../src/core/inspect.mjs';
import { create_zip_entries } from './helpers.mjs';

test('inspection hashes the complete file while parsing a bounded prefix', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-inspect-'));
  const file_path = path.join(directory, 'sample.pdf');
  const bytes = Buffer.concat([Buffer.from('%PDF-1.7\n'), Buffer.alloc(512, 0x41)]);
  try {
    await writeFile(file_path, bytes);
    const result = await inspect_file(file_path, { limits: { max_read_bytes: 64, max_file_bytes: 1024 } });
    assert.equal(result.detection.format, 'PDF');
    assert.equal(result.integrity.digest, createHash('sha256').update(bytes).digest('hex'));
    assert.equal(result.artifact.readable_bytes, 64);
    assert.equal(result.artifact.analysis_complete_for_file, false);
    assert.equal(result.metrics.hex_preview_bytes, 64);
    assert.match(result.warnings.join(' '), /Only the first 64 bytes/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('empty files produce an explicit unknown-format report', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-empty-'));
  const file_path = path.join(directory, 'empty.bin');
  try {
    await writeFile(file_path, Buffer.alloc(0));
    const result = await inspect_file(file_path);
    assert.equal(result.detection.format, 'Unknown');
    assert.equal(result.integrity.digest, createHash('sha256').update(Buffer.alloc(0)).digest('hex'));
    assert.equal(result.metrics.hex_preview, '');
    assert.equal(result.metrics.entropy.sample_size, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('inspection labels APK detection as structural evidence rather than a leading signature', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-apk-'));
  const file_path = path.join(directory, 'sample.apk');
  const apk = create_zip_entries([{ name: 'AndroidManifest.xml', contents: Buffer.from('<manifest package="com.example.evidence"/>') }]);
  try {
    await writeFile(file_path, apk);
    const result = await inspect_file(file_path);
    const detection = result.evidence.find(item => item.kind === 'format-detection');
    assert.equal(result.detection.format, 'Android APK');
    assert.equal(detection.confidence, 'derived');
    assert.equal(detection.details.detection_confidence, 'structural');
    assert.match(detection.summary, /validated container structure/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('inspection rejects hard-linked inputs when the workspace boundary requests it', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-inspect-hardlink-'));
  const original = path.join(directory, 'original.bin');
  const alias = path.join(directory, 'workspace-alias.bin');
  try {
    await writeFile(original, 'external content');
    await link(original, alias);
    await assert.rejects(
      inspect_file(alias, { reject_hardlinks: true }),
      error => error.code === 'ORIX_HARDLINK_REJECTED',
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
