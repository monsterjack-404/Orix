import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ORIX_MCP_TOOLS, call_orix_tool } from '../src/mcp/server.mjs';
import { create_zip_fixture } from './helpers.mjs';

test('MCP Android package tool is read-only and workspace-confined', async () => {
  const tool = ORIX_MCP_TOOLS.find(item => item.name === 'orix.analyze_android_package');
  assert.ok(tool);
  assert.equal(tool.annotations.readOnlyHint, true);
  assert.equal(tool.annotations.destructiveHint, false);
  assert.equal(tool.annotations.openWorldHint, false);

  const directory = await mkdtemp(path.join(os.tmpdir(), 'orix-android-mcp-'));
  try {
    const file = path.join(directory, 'sample.apk');
    const manifest = Buffer.alloc(8);
    manifest.writeUInt16LE(0x0003, 0);
    manifest.writeUInt16LE(8, 2);
    manifest.writeUInt32LE(8, 4);
    await writeFile(file, create_zip_fixture('AndroidManifest.xml', manifest), { flag: 'wx', mode: 0o600 });

    const report = await call_orix_tool(
      'orix.analyze_android_package',
      { path: file, max_archive_entries: 1 },
      { roots: [directory] },
    );
    assert.equal(report.schema_version, 'orix.android-package.v1');
    assert.equal(report.format, 'APK');
    assert.equal(report.detected, true);
    assert.equal(report.summary.manifest_entries, 1);
    assert.equal(report.archive.entries_reported, 1);
    assert.equal(report.manifests[0].status, 'malformed-binary-xml');

    const outside = fileURLToPath(new URL('../README.md', import.meta.url));
    await assert.rejects(
      call_orix_tool('orix.analyze_android_package', { path: outside }, { roots: [directory] }),
      /workspace|outside|root/i,
    );
    await assert.rejects(
      call_orix_tool('orix.analyze_android_package', { path: file, max_archive_entries: 0 }, { roots: [directory] }),
      /integer between 1 and 50000/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
