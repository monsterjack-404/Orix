// JavaScript, tests/android-package.test.mjs, Node.js 20+, APK/AAB inventory contracts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { analyze_android_package, analyze_android_package_file, render_android_package_markdown } from '../src/android/package.mjs';

function dex_header() {
  const dex = Buffer.alloc(112);
  dex.set([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0], 0);
  dex.writeUInt32LE(112, 32);
  dex.writeUInt32LE(112, 36);
  dex.writeUInt32LE(0x12345678, 40);
  return dex;
}

function zip_fixture(entries) {
  const local = [];
  const central = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const data = Buffer.from(entry.data ?? []);
    const local_name = Buffer.from(entry.local_name ?? entry.name, 'utf8');
    const method = entry.method ?? 0;
    const local_header = Buffer.alloc(30 + local_name.length + data.length);
    local_header.writeUInt32LE(0x04034b50, 0);
    local_header.writeUInt16LE(20, 4);
    local_header.writeUInt16LE(0, 6);
    local_header.writeUInt16LE(method, 8);
    local_header.writeUInt32LE(data.length, 18);
    local_header.writeUInt32LE(data.length, 22);
    local_header.writeUInt16LE(local_name.length, 26);
    local_header.writeUInt16LE(0, 28);
    local_name.copy(local_header, 30);
    data.copy(local_header, 30 + local_name.length);
    local.push(local_header);

    const header = Buffer.alloc(46 + name.length);
    header.writeUInt32LE(0x02014b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(20, 6);
    header.writeUInt16LE(0, 8);
    header.writeUInt16LE(method, 10);
    header.writeUInt32LE(data.length, 20);
    header.writeUInt32LE(data.length, 24);
    header.writeUInt16LE(name.length, 28);
    header.writeUInt16LE(0, 30);
    header.writeUInt16LE(0, 32);
    header.writeUInt16LE(0, 34);
    header.writeUInt32LE(0, 38);
    header.writeUInt32LE(offset, 42);
    name.copy(header, 46);
    central.push(header);
    offset += local_header.length;
  }
  const central_bytes = Buffer.concat(central);
  const central_offset = offset;
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(central_bytes.length, 12);
  eocd.writeUInt32LE(central_offset, 16);
  return Buffer.concat([...local, central_bytes, eocd]);
}

test('identifies APK structure and inspects stored DEX headers without exporting payloads', () => {
  const manifest = Buffer.from([3, 0, 8, 0, 8, 0, 0, 0]);
  const report = analyze_android_package(zip_fixture([
    { name: 'AndroidManifest.xml', data: manifest },
    { name: 'classes.dex', data: dex_header() },
    { name: 'lib/arm64-v8a/libsample.so', data: [1, 2, 3] },
    { name: 'META-INF/CERT.RSA', data: [1, 2] },
  ]));
  assert.equal(report.format, 'APK');
  assert.equal(report.detected, true);
  assert.equal(report.summary.dex_headers_parsed, 1);
  assert.equal(report.dex[0].version, '035');
  assert.equal(report.manifests[0].status, 'binary-xml-header');
  assert.equal(report.summary.native_libraries, 1);
  assert.equal(report.summary.v1_signature_files, 1);
  assert.equal(Object.hasOwn(report.dex[0], 'payload'), false);
});

test('identifies Android App Bundles and skips compressed DEX entries', () => {
  const report = analyze_android_package(zip_fixture([
    { name: 'BundleConfig.pb', data: [1] },
    { name: 'base/manifest/AndroidManifest.xml', data: [3, 0, 8, 0, 8, 0, 0, 0] },
    { name: 'base/dex/classes.dex', data: dex_header(), method: 8 },
    { name: 'base/lib/arm64-v8a/libbundle.so', data: [1, 2, 3] },
  ]));
  assert.equal(report.format, 'AAB');
  assert.equal(report.summary.dex_entries_not_inspected, 1);
  assert.equal(report.summary.native_libraries, 1);
  assert.equal(report.dex[0].status, 'compressed');
});

test('rejects mismatched local entry names before inspecting DEX data', () => {
  const report = analyze_android_package(zip_fixture([
    { name: 'AndroidManifest.xml', data: [3, 0, 8, 0, 8, 0, 0, 0] },
    { name: 'classes.dex', local_name: 'other.dex', data: dex_header() },
  ]));
  assert.equal(report.dex[0].status, 'local-header-mismatch');
});

test('ignores unsafe archive paths when inventorying DEX entries', () => {
  const report = analyze_android_package(zip_fixture([
    { name: 'AndroidManifest.xml', data: [3, 0, 8, 0, 8, 0, 0, 0] },
    { name: '../classes.dex', data: dex_header() },
  ]));
  assert.equal(report.summary.dex_entries, 0);
  assert.equal(report.archive.unsafe_or_symlink_entries, 1);
});

test('safe file acquisition rejects symlinks and Markdown renderer emits real line breaks', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'orix-android-'));
  try {
    const file = path.join(root, 'sample.apk');
    await writeFile(file, zip_fixture([
      { name: 'AndroidManifest.xml', data: [3, 0, 8, 0, 8, 0, 0, 0] },
      { name: 'classes.dex', data: dex_header() },
    ]));
    const report = await analyze_android_package_file(file);
    const markdown = render_android_package_markdown(report);
    assert.match(markdown, /^# ORIX Android Package Report/m);
    assert.match(markdown, /## DEX inventory/);
    assert.ok(markdown.includes(String.fromCharCode(10)));
    const link = path.join(root, 'linked.apk');
    const { symlink } = await import('node:fs/promises');
    await symlink(file, link);
    await assert.rejects(analyze_android_package_file(link), /regular non-symlink file/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
