// JavaScript, tests/android-cli.test.mjs, Node.js 20+, Android CLI integration.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'src', 'cli.mjs');

function minimal_apk() {
  const name = Buffer.from('AndroidManifest.xml');
  const data = Buffer.from([3, 0, 8, 0, 8, 0, 0, 0]);
  const local = Buffer.alloc(30 + name.length + data.length);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(0, 8);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(name.length, 26);
  name.copy(local, 30);
  data.copy(local, 30 + name.length);
  const central = Buffer.alloc(46 + name.length);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(name.length, 28);
  central.writeUInt32LE(0, 42);
  name.copy(central, 46);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(central.length, 12);
  eocd.writeUInt32LE(local.length, 16);
  return Buffer.concat([local, central, eocd]);
}

test('android CLI emits an offline APK inventory in JSON', async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'orix-android-cli-'));
  try {
    const apk = path.join(temp, 'fixture.apk');
    await writeFile(apk, minimal_apk());
    const result = spawnSync(process.execPath, [cli, 'android', apk, '--json'], {
      cwd: root, encoding: 'utf8', timeout: 15000,
    });
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.format, 'APK');
    assert.equal(report.detected, true);
    assert.equal(report.summary.manifest_entries, 1);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test('android CLI rejects unsupported report formats and excessive file limits', async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'orix-android-cli-'));
  try {
    const apk = path.join(temp, 'fixture.apk');
    await writeFile(apk, minimal_apk());
    const bad_format = spawnSync(process.execPath, [cli, 'android', apk, '--format', 'sarif'], {
      cwd: root, encoding: 'utf8', timeout: 15000,
    });
    assert.equal(bad_format.status, 1);
    assert.match(bad_format.stderr, /android output supports JSON or Markdown only/);
    const bad_limit = spawnSync(process.execPath, [cli, 'android', apk, '--max-file-mib', '2048'], {
      cwd: root, encoding: 'utf8', timeout: 15000,
    });
    assert.equal(bad_limit.status, 1);
    assert.match(bad_limit.stderr, /cannot exceed 1024 MiB/);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});
