// JavaScript, tests/android-package.test.mjs, Node.js 20+, APK/AAB inventory contracts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  analyze_android_package,
  analyze_android_package_file,
  render_android_package_markdown,
} from '../src/android/package.mjs';
import * as public_api from '../src/index.mjs';
import { parse_android_binary_xml } from '../src/android/binary-xml.mjs';

const repository_root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli_path = path.join(repository_root, 'src', 'cli.mjs');

function create_dex_fixture() {
  const buffer = Buffer.alloc(140);
  buffer.write('dex\n035\0', 0, 'ascii');
  buffer.writeUInt32LE(buffer.length, 32);
  buffer.writeUInt32LE(112, 36);
  buffer.writeUInt32LE(0x12345678, 40);
  buffer.writeUInt32LE(112, 52);
  buffer.writeUInt32LE(28, 104);
  buffer.writeUInt32LE(112, 108);
  buffer.writeUInt32LE(2, 112);
  buffer.writeUInt16LE(0, 116);
  buffer.writeUInt32LE(1, 120);
  buffer.writeUInt32LE(0, 124);
  buffer.writeUInt16LE(0x1000, 128);
  buffer.writeUInt32LE(1, 132);
  buffer.writeUInt32LE(112, 136);
  return buffer;
}

function create_zip(entries) {
  const local_records = [];
  const central_records = [];
  let local_offset = 0;

  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const contents = Buffer.isBuffer(entry.contents) ? entry.contents : Buffer.from(entry.contents ?? '');
    const method = entry.method ?? 0;
    const compressed = method === 8 ? deflateRawSync(contents) : contents;
    const flags = entry.flags ?? 0;
    const local = Buffer.alloc(30 + name.length + compressed.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(0, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(contents.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    name.copy(local, 30);
    compressed.copy(local, 30 + name.length);
    local_records.push(local);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x0314, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(0, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(contents.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt32LE(entry.unix_mode === undefined ? 0 : (entry.unix_mode << 16) >>> 0, 38);
    central.writeUInt32LE(local_offset, 42);
    name.copy(central, 46);
    central_records.push(central);
    local_offset += local.length;
  }

  const central_data = Buffer.concat(central_records);
  const local_data = Buffer.concat(local_records);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(central_data.length, 12);
  eocd.writeUInt32LE(local_data.length, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([local_data, central_data, eocd]);
}

function binary_manifest() { return Buffer.from('AwAIAO4CAAABABwATgEAAA8AAAAAAAAAAAEAAFgAAAAAAAAAAAAAAAsAAAAVAAAAKAAAADoAAABBAAAASwAAAHgAAACWAAAApAAAALEAAAC8AAAA1wAAAOIAAADwAAAACAhtYW5pZmVzdAAHB3BhY2thZ2UAEBBjb20uZXhhbXBsZS5vcml4AA8PdXNlcy1wZXJtaXNzaW9uAAQEbmFtZQAHB2FuZHJvaWQAKipodHRwOi8vc2NoZW1hcy5hbmRyb2lkLmNvbS9hcGsvcmVzL2FuZHJvaWQAGxthbmRyb2lkLnBlcm1pc3Npb24uSU5URVJORVQACwthcHBsaWNhdGlvbgAKCmRlYnVnZ2FibGUACAhhY3Rpdml0eQAYGGNvbS5leGFtcGxlLk1haW5BY3Rpdml0eQAICGV4cG9ydGVkAAsLdmVyc2lvbk5hbWUAAwMxLjAAAAEQABgAAAAAAAAAAAAAAAUAAAAGAAAAAgEQAEwAAAAAAAAAAAAAAP////8AAAAAFAAUAAIAAAAAAAAA/////wEAAAACAAAACAAAAwIAAAAGAAAADQAAAA4AAAAIAAADDgAAAAIBEAA4AAAAAAAAAAAAAAD/////AwAAABQAFAABAAAAAAAAAAYAAAAEAAAABwAAAAgAAAMHAAAAAwEQABgAAAAAAAAAAAAAAP////8DAAAAAgEQADgAAAAAAAAAAAAAAP////8IAAAAFAAUAAEAAAAAAAAABgAAAAkAAAD/////CAAAEgEAAAACARAATAAAAAAAAAAAAAAA/////woAAAAUABQAAgAAAAAAAAAGAAAABAAAAAsAAAAIAAADCwAAAAYAAAAMAAAA/////wgAABIBAAAAAwEQABgAAAAAAAAAAAAAAP////8KAAAAAwEQABgAAAAAAAAAAAAAAP////8IAAAAAwEQABgAAAAAAAAAAAAAAP////8AAAAAAQEQABgAAAAAAAAAAAAAAAUAAAAGAAAA', 'base64'); }


test('APK manifest attributes resolve by namespace URI even with a nonstandard prefix', () => {
  const manifest = binary_manifest();
  const prefix = Buffer.from('android', 'ascii');
  const offset = manifest.indexOf(prefix);
  assert.notEqual(offset, -1);
  manifest.write('droidxx', offset, 'ascii');
  const decoded = parse_android_binary_xml(manifest);
  assert.equal(decoded.package_name, 'com.example.orix');
  assert.deepEqual(decoded.permissions.map(item => item.name), ['android.permission.INTERNET']);
  assert.equal(decoded.application.debuggable, true);
  assert.equal(decoded.components[0].exported, true);
});

function find_binary_xml_chunk(buffer, expected_type) {
  const end = buffer.readUInt32LE(4);
  let offset = buffer.readUInt16LE(2);
  while (offset < end) {
    const type = buffer.readUInt16LE(offset);
    const size = buffer.readUInt32LE(offset + 4);
    if (type === expected_type) return offset;
    if (size < 8 || size > end - offset) throw new Error('Invalid test AXML chunk framing');
    offset += size;
  }
  return -1;
}

function make_apk() {
  return create_zip([
    { name: 'AndroidManifest.xml', contents: binary_manifest() },
    { name: 'classes.dex', contents: create_dex_fixture() },
    { name: 'lib/arm64-v8a/libsample.so', contents: Buffer.from([0x7f, 0x45, 0x4c, 0x46]) },
    { name: 'resources.arsc', contents: Buffer.from([1, 2, 3, 4]) },
    { name: 'META-INF/CERT.RSA', contents: Buffer.from('signature-placeholder') },
  ]);
}

test('APK inventory identifies manifest, multidomain assets and valid stored DEX metadata', () => {
  const report = analyze_android_package(make_apk());
  assert.equal(report.schema_version, 'orix.android-package.v1');
  assert.equal(report.format, 'APK');
  assert.equal(report.detected, true);
  assert.equal(report.summary.dex_entries, 1);
  assert.equal(report.summary.dex_metadata_parsed, 1);
  assert.equal(report.summary.dex_entries_not_inspected, 0);
  assert.equal(report.summary.manifest_entries, 1);
  assert.equal(report.summary.native_libraries, 1);
  assert.equal(report.summary.resources_table_present, true);
  assert.equal(report.summary.v1_signature_files, 1);
  assert.equal(report.archive.entry_count, 5);
  assert.equal(report.archive.safe_entry_count, 5);
  assert.equal(report.archive.entries_reported, 5);
  assert.equal(report.archive.entries_omitted, 0);
  assert.ok(report.archive_entries.some(entry => entry.path === 'classes.dex'));
  assert.equal(report.dex[0].status, 'metadata-parsed');
  assert.equal(report.warnings.length, 0);
  assert.equal(report.manifests[0].status, 'decoded');
  assert.equal(report.manifests[0].binary_xml, true);
  assert.equal(report.manifests[0].package_name, 'com.example.orix');
  assert.equal(report.manifests[0].version_name, '1.0');
  assert.deepEqual(report.manifests[0].permissions.map(item => item.name), ['android.permission.INTERNET']);
  assert.deepEqual(report.manifests[0].components.map(item => item.type), ['activity']);
  assert.equal(report.manifests[0].components[0].exported, true);
  assert.equal(report.manifests[0].application.debuggable, true);
  assert.equal(report.manifests[0].path_truncated, false);
});


test('APK manifest decoder rejects mismatched end-element names', () => {
  const manifest = Buffer.from(binary_manifest());
  const end_element = find_binary_xml_chunk(manifest, 0x0103);
  assert.notEqual(end_element, -1);
  manifest.writeUInt32LE(0xffffffff, end_element + 20);
  const report = analyze_android_package(create_zip([{ name: 'AndroidManifest.xml', contents: manifest }]));
  assert.equal(report.manifests[0].status, 'malformed-binary-xml');
  assert.equal(report.manifests[0].error.code, 'ORIX_AXML_MISMATCHED_END_TAG');
});

test('APK manifest decoder rejects attribute arrays overlapping the element extension', () => {
  const manifest = Buffer.from(binary_manifest());
  const start_element = find_binary_xml_chunk(manifest, 0x0102);
  assert.notEqual(start_element, -1);
  manifest.writeUInt16LE(0, start_element + 24);
  const report = analyze_android_package(create_zip([{ name: 'AndroidManifest.xml', contents: manifest }]));
  assert.equal(report.manifests[0].status, 'malformed-binary-xml');
  assert.equal(report.manifests[0].error.code, 'ORIX_AXML_ATTRIBUTE_START');
});

test('APK manifest decoder rejects trailing bytes beyond the root chunk', () => {
  const manifest = Buffer.concat([binary_manifest(), Buffer.from([0])]);
  const report = analyze_android_package(create_zip([{ name: 'AndroidManifest.xml', contents: manifest }]));
  assert.equal(report.manifests[0].status, 'unknown-or-invalid-header');
});

test('AAB inventory recognizes bundle layout without mislabeling protobuf manifest as binary XML', () => {
  const report = analyze_android_package(create_zip([
    { name: 'BundleConfig.pb', contents: Buffer.from([0x0a, 0x00]) },
    { name: 'base/manifest/AndroidManifest.xml', contents: Buffer.from([0x0a, 0x02, 0x08, 0x01, 0x12, 0x02, 0x08, 0x01]) },
    { name: 'base/dex/classes.dex', contents: create_dex_fixture() },
  ]));
  assert.equal(report.schema_version, 'orix.android-package.v1');
  assert.equal(report.format, 'AAB');
  assert.equal(report.detected, true);
  assert.equal(report.summary.dex_entries, 1);
  assert.equal(report.summary.dex_metadata_parsed, 1);
  assert.equal(report.manifests[0].binary_xml, false);
  assert.equal(report.manifests[0].status, 'unknown-or-invalid-header');
});

test('compressed DEX entries are inventoried but are not decompressed or parsed', () => {
  const report = analyze_android_package(create_zip([
    { name: 'AndroidManifest.xml', contents: binary_manifest() },
    { name: 'classes.dex', contents: create_dex_fixture(), method: 8 },
  ]));
  assert.equal(report.dex[0].status, 'compressed');
  assert.equal(report.summary.dex_metadata_parsed, 0);
  assert.deepEqual(report.warnings, [{ path: 'classes.dex', reason: 'compressed' }]);
});

test('archive entry inventory is bounded and reports omitted coverage', () => {
  const report = analyze_android_package(make_apk(), { max_archive_entries: 1 });
  assert.equal(report.archive.entry_count, 5);
  assert.equal(report.archive.entries_reported, 1);
  assert.equal(report.archive.entries_omitted, 4);
  assert.equal(report.archive_entries.length, 1);
  assert.equal(report.archive_entries[0].path, 'AndroidManifest.xml');
});

test('nested DEX inventory is bounded and reports omitted entries explicitly', () => {
  const report = analyze_android_package(create_zip([
    { name: 'AndroidManifest.xml', contents: binary_manifest() },
    { name: 'classes.dex', contents: create_dex_fixture() },
    { name: 'classes2.dex', contents: create_dex_fixture() },
    { name: 'classes3.dex', contents: create_dex_fixture() },
  ]), { max_archive_entries: 2 });
  assert.equal(report.summary.dex_entries, 3);
  assert.equal(report.summary.dex_entries_reported, 2);
  assert.equal(report.summary.dex_entries_omitted, 1);
  assert.equal(report.summary.dex_entries_not_inspected, 1);
  assert.equal(report.dex.length, 2);
  assert.equal(report.dex[0].path, 'classes.dex');
  assert.equal(report.dex[1].path, 'classes2.dex');
});

test('archive entry names are length-bounded with an explicit truncation marker', () => {
  const long_name = 'a'.repeat(520) + '.bin';
  const report = analyze_android_package(create_zip([
    { name: 'AndroidManifest.xml', contents: binary_manifest() },
    { name: long_name, contents: Buffer.from('bounded path') },
  ]));
  const item = report.archive_entries.find(entry => entry.path_truncated);
  assert.ok(item);
  assert.equal(item.path.length, 512);
  assert.equal(item.path_original_length, long_name.length);
});

test('encrypted DEX entries are not inspected', () => {
  const report = analyze_android_package(create_zip([
    { name: 'AndroidManifest.xml', contents: binary_manifest() },
    { name: 'classes.dex', contents: create_dex_fixture(), flags: 1 },
  ]));
  assert.equal(report.dex[0].status, 'encrypted');
  assert.equal(report.summary.dex_metadata_parsed, 0);
});

test('DEX entries are not trusted when the local filename differs from the central directory', () => {
  const buffer = make_apk();
  const local_name = Buffer.from('classes.dex');
  const offset = buffer.indexOf(local_name);
  assert.notEqual(offset, -1);
  buffer[offset] = 'X'.charCodeAt(0);
  const report = analyze_android_package(buffer);
  assert.equal(report.dex[0].status, 'local-header-mismatch');
  assert.equal(report.summary.dex_metadata_parsed, 0);
});

test('stored DEX entries with mismatched content CRC32 are excluded from metadata parsing', () => {
  const buffer = make_apk();
  const signature = Buffer.from('dex\\n035\\0', 'ascii');
  const offset = buffer.indexOf(signature);
  assert.notEqual(offset, -1);
  buffer[offset + 12] ^= 0xff;
  const report = analyze_android_package(buffer);
  assert.equal(report.dex[0].status, 'crc-mismatch');
  assert.equal(report.summary.dex_metadata_parsed, 0);
});

test('DEX entries whose local data overlaps the central directory are not parsed', () => {
  const buffer = make_apk();
  const eocd_offset = buffer.length - 22;
  const central_offset = buffer.readUInt32LE(eocd_offset + 16);
  const central_name = Buffer.from('classes.dex');
  const name_offset = buffer.indexOf(central_name, central_offset);
  assert.notEqual(name_offset, -1);
  const central_entry = name_offset - 46;
  const fake_local_offset = central_offset - 30 - central_name.length;
  buffer.writeUInt32LE(0x04034b50, fake_local_offset);
  buffer.writeUInt16LE(20, fake_local_offset + 4);
  buffer.writeUInt16LE(0, fake_local_offset + 6);
  buffer.writeUInt16LE(0, fake_local_offset + 8);
  buffer.writeUInt32LE(0, fake_local_offset + 14);
  buffer.writeUInt32LE(create_dex_fixture().length, fake_local_offset + 18);
  buffer.writeUInt32LE(create_dex_fixture().length, fake_local_offset + 22);
  buffer.writeUInt16LE(central_name.length, fake_local_offset + 26);
  buffer.writeUInt16LE(0, fake_local_offset + 28);
  central_name.copy(buffer, fake_local_offset + 30);
  buffer.writeUInt32LE(fake_local_offset, central_entry + 42);

  const report = analyze_android_package(buffer);
  assert.equal(report.dex[0].status, 'invalid-local-range');
  assert.equal(report.summary.dex_metadata_parsed, 0);
});

test('ordinary ZIP archives are not falsely identified as Android packages', () => {
  const report = analyze_android_package(create_zip([{ name: 'readme.txt', contents: 'ordinary archive' }]));
  assert.equal(report.detected, false);
  assert.equal(report.format, 'Android package candidate');
  assert.equal(report.summary.dex_entries, 0);
});

test('unsafe archive paths and Unix symlink entries are excluded from Android package evidence', () => {
  const report = analyze_android_package(create_zip([
    { name: '../AndroidManifest.xml', contents: binary_manifest() },
    { name: '../classes.dex', contents: create_dex_fixture() },
    { name: 'classes2.dex', contents: create_dex_fixture(), unix_mode: 0o120777 },
  ]));
  assert.equal(report.detected, false);
  assert.equal(report.summary.manifest_entries, 0);
  assert.equal(report.summary.dex_entries, 0);
  assert.equal(report.archive.unsafe_or_symlink_entries, 3);
  assert.equal(report.archive_entries.length, 0);
});

test('Android package parser rejects invalid options and malformed ZIP input', () => {
  assert.throws(() => analyze_android_package(Buffer.from('not a ZIP')), error => error.code === 'ORIX_ZIP_EOCD_MISSING');
  assert.throws(() => analyze_android_package(make_apk(), { max_dex_entries: 0 }), /max_dex_entries must be/);
  assert.throws(() => analyze_android_package(make_apk(), { max_dex_entry_bytes: 1 }), /max_dex_entry_bytes must be/);
  assert.throws(() => analyze_android_package(make_apk(), { max_dex_total_bytes: 1 }), /max_dex_total_bytes must be/);
  assert.throws(() => analyze_android_package(make_apk(), { max_dex_output_items: 0 }), /max_dex_output_items must be/);
  assert.throws(() => analyze_android_package(make_apk(), { max_archive_entries: 0 }), /max_archive_entries must be/);
  assert.throws(() => analyze_android_package(make_apk(), { max_archive_entry_path_length: 1 }), /max_archive_entry_path_length must be/);
});

test('Android package API is exported from the package root and dedicated subpath', async () => {
  assert.equal(public_api.analyze_android_package, analyze_android_package);
  assert.equal(public_api.analyze_android_package_file, analyze_android_package_file);
  assert.equal(public_api.render_android_package_markdown, render_android_package_markdown);
  const exported = await import('@orix/cli/android/package');
  assert.equal(exported.analyze_android_package, analyze_android_package);
});

test('Android package file analyzer reads a stable regular file within its size limit', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'orix-android-file-'));
  try {
    const file = path.join(directory, 'sample.apk');
    await writeFile(file, make_apk(), { flag: 'wx', mode: 0o600 });
    const report = await analyze_android_package_file(file);
    assert.equal(report.format, 'APK');
    assert.equal(report.summary.dex_metadata_parsed, 1);
    assert.equal(report.source.name, 'sample.apk');
    assert.equal(report.source.size_bytes > 0, true);
    assert.match(report.source.sha256, /^[a-f0-9]{64}$/);
    assert.equal(report.source.stable_during_read, true);
    await assert.rejects(analyze_android_package_file(file, { max_file_bytes: 1 }), RangeError);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Android package file analyzer rejects symlink targets', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'orix-android-symlink-'));
  try {
    const file = path.join(directory, 'real.apk');
    const link = path.join(directory, 'linked.apk');
    await writeFile(file, make_apk(), { flag: 'wx', mode: 0o600 });
    await symlink(file, link, process.platform === 'win32' ? 'file' : undefined);
    await assert.rejects(
      analyze_android_package_file(link),
      error => ['ELOOP', 'ORIX_ANDROID_PACKAGE_SYMLINK', 'ERR_FS_EISDIR'].includes(error.code) ||
        error.message.includes('changed before acquisition'),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Android package Markdown renderer reports parser boundaries', () => {
  const markdown = render_android_package_markdown(analyze_android_package(make_apk()));
  assert.match(markdown, /ORIX Android Package Report/);
  assert.match(markdown, /APK/);
  assert.match(markdown, /DEX inventory/);
  assert.match(markdown, /not decoded/);
});

test('Android Markdown renderer escapes hostile archive entry names', () => {
  const hostile_name = '[preview](javascript:alert(1))&lt;script&gt;/manifest/AndroidManifest.xml';
  const markdown = render_android_package_markdown(analyze_android_package(create_zip([
    { name: 'BundleConfig.pb', contents: Buffer.from([0x0a]) },
    { name: hostile_name, contents: Buffer.from([0x0a, 0x00]) },
  ])));
  assert.equal(markdown.includes('[preview]('), false);
  assert.ok(markdown.includes('\\[preview\\]'));
  assert.ok(markdown.includes('&amp;lt;script&amp;gt;'));
});

test('android CLI writes a JSON APK report and refuses to overwrite output', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'orix-android-cli-'));
  try {
    const input = path.join(directory, 'sample.apk');
    const output = path.join(directory, 'android-report.json');
    await writeFile(input, make_apk(), { flag: 'wx', mode: 0o600 });
    const result = spawnSync(process.execPath, [cli_path, 'android', input, '--json', '--max-archive-entries', '1', '--out', output], {
      cwd: repository_root, encoding: 'utf8', timeout: 15000,
    });
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(await readFile(output, 'utf8'));
    assert.equal(report.format, 'APK');
    assert.equal(report.summary.dex_metadata_parsed, 1);
    assert.equal(report.archive.entries_reported, 1);
    assert.equal(report.archive.entries_omitted, 4);

    const second = spawnSync(process.execPath, [cli_path, 'android', input, '--json', '--out', output], {
      cwd: repository_root, encoding: 'utf8', timeout: 15000,
    });
    assert.equal(second.status, 1);
    assert.match(second.stderr, /Refusing to overwrite existing report/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});


test('AAB inventory recognizes BundleConfig and module manifest/DEX paths without protobuf claims', () => {
  const manifest = Buffer.alloc(8);
  manifest.writeUInt16LE(0x0003, 0);
  manifest.writeUInt16LE(8, 2);
  manifest.writeUInt32LE(8, 4);
  const report = analyze_android_package(create_zip([
    { name: 'BundleConfig.pb', contents: Buffer.from([0x0a, 0x00]) },
    { name: 'base/manifest/AndroidManifest.xml', contents: manifest },
    { name: 'base/dex/classes.dex', contents: create_dex_fixture() },
  ]));
  assert.equal(report.format, 'AAB');
  assert.equal(report.detected, true);
  assert.equal(report.summary.manifest_entries, 1);
  assert.equal(report.manifests[0].path, 'base/manifest/AndroidManifest.xml');
  assert.equal(report.manifests[0].status, 'malformed-binary-xml');
  assert.equal(report.summary.dex_entries, 1);
  assert.equal(report.dex[0].status, 'metadata-parsed');
  assert.ok(report.limitations.some(note => note.includes('AAB protobuf manifests')));
});
