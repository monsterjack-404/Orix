// JavaScript, tests/android-apk.test.mjs, Node.js 20+, bounded APK/DEX parser contracts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_apk } from '../src/formats/apk.mjs';
import { analyze_known_format } from '../src/formats/index.mjs';
import { create_minimal_dex_fixture, create_dex_class_fixture, create_zip_entries } from './helpers.mjs';

function apk_fixture({ manifest = '<manifest package="com.example.demo"><uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/><uses-permission android:name="android.permission.INTERNET"/></manifest>', dex = null } = {}) {
  const entries = [{ name: 'AndroidManifest.xml', contents: Buffer.from(manifest) }];
  if (dex) entries.push({ name: 'classes.dex', contents: dex });
  return create_zip_entries(entries);
}

test('APK parser inventories plain XML manifest metadata without executing content', () => {
  const parsed = parse_apk(apk_fixture());
  assert.equal(parsed.format, 'Android APK');
  assert.equal(parsed.manifest.encoding, 'plain-xml');
  assert.equal(parsed.manifest.package_name, 'com.example.demo');
  assert.equal(parsed.manifest.sdk.min_sdk, '23');
  assert.equal(parsed.manifest.sdk.target_sdk, '35');
  assert.deepEqual(parsed.manifest.permissions, ['android.permission.INTERNET']);
  assert.equal(parsed.extraction.content_executed, false);
  assert.equal(parsed.signing_metadata.signature_verified, false);
});

test('APK parser reads bounded DEX header and reports class inventory counts', () => {
  const parsed = parse_apk(apk_fixture({ dex: create_minimal_dex_fixture() }));
  assert.equal(parsed.dex_file_count, 1);
  assert.equal(parsed.dex[0].version, '039');
  assert.equal(parsed.dex[0].file_size, 0x70);
  assert.equal(parsed.dex[0].tables.classes.count, 0);
  assert.equal(parsed.class_count, 0);
});

test('APK parser rejects archives without AndroidManifest.xml', () => {
  const archive = create_zip_entries([{ name: 'classes.dex', contents: create_minimal_dex_fixture() }]);
  assert.throws(() => parse_apk(archive), error => error.code === 'ORIX_ANDROID_MANIFEST_MISSING');
});

test('APK parser rejects malformed DEX headers instead of accepting magic alone', () => {
  const dex = create_minimal_dex_fixture();
  dex.writeUInt32LE(0x1234, 0x24);
  assert.throws(() => parse_apk(apk_fixture({ dex })), error => error.code === 'ORIX_ANDROID_BAD_DEX_HEADER');
});

test('APK parser does not accept a traversal-named entry as its manifest', () => {
  const archive = create_zip_entries([{ name: '../AndroidManifest.xml', contents: Buffer.from('<manifest/>') }]);
  assert.throws(() => parse_apk(archive), error => error.code === 'ORIX_ANDROID_MANIFEST_MISSING');
});

test('APK parser validates direct resource limits before parsing', () => {
  const archive = apk_fixture();
  for (const max_entry_bytes of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 64 * 1024 * 1024 + 1]) {
    assert.throws(() => parse_apk(archive, { max_entry_bytes }), /max_entry_bytes must be a positive integer/);
  }
});

test('format dispatcher identifies APK from its validated ZIP manifest entry', () => {
  const result = analyze_known_format(apk_fixture());
  assert.equal(result.detection.format, 'Android APK');
  assert.equal(result.detection.confidence, 'structural');
  assert.equal(result.parser_status, 'parsed');
  assert.equal(result.parsed.manifest.package_name, 'com.example.demo');
});

function binary_manifest_fixture() {
  const strings = ['manifest', 'package', 'com.example.binary', 'uses-permission', 'name', 'android.permission.INTERNET'];
  const data_parts = [];
  const offsets = [];
  let data_length = 0;
  for (const value of strings) {
    const bytes = Buffer.from(value, 'utf8');
    offsets.push(data_length);
    const record = Buffer.concat([Buffer.from([bytes.length, bytes.length]), bytes, Buffer.from([0])]);
    data_parts.push(record);
    data_length += record.length;
  }
  const string_data = Buffer.concat(data_parts);
  const pool_size = 28 + offsets.length * 4 + string_data.length;
  const pool = Buffer.alloc(pool_size);
  pool.writeUInt16LE(1, 0);
  pool.writeUInt16LE(28, 2);
  pool.writeUInt32LE(pool_size, 4);
  pool.writeUInt32LE(strings.length, 8);
  pool.writeUInt32LE(0, 12);
  pool.writeUInt32LE(0x100, 16);
  pool.writeUInt32LE(28 + strings.length * 4, 20);
  pool.writeUInt32LE(0, 24);
  offsets.forEach((offset, index) => pool.writeUInt32LE(offset, 28 + index * 4));
  string_data.copy(pool, 28 + offsets.length * 4);
  function start_element(name_index, attribute_name, value_index) {
    const chunk = Buffer.alloc(56);
    chunk.writeUInt16LE(0x0102, 0);
    chunk.writeUInt16LE(16, 2);
    chunk.writeUInt32LE(56, 4);
    chunk.writeUInt32LE(0xffffffff, 12);
    chunk.writeUInt32LE(0xffffffff, 16);
    chunk.writeUInt32LE(name_index, 20);
    chunk.writeUInt16LE(20, 24);
    chunk.writeUInt16LE(20, 26);
    chunk.writeUInt16LE(1, 28);
    chunk.writeUInt32LE(0xffffffff, 36);
    chunk.writeUInt32LE(attribute_name, 40);
    chunk.writeUInt32LE(value_index, 44);
    chunk.writeUInt16LE(8, 48);
    chunk.writeUInt16LE(0, 50);
    chunk.writeUInt8(3, 51);
    chunk.writeUInt32LE(value_index, 52);
    return chunk;
  }
  const elements = Buffer.concat([start_element(0, 1, 2), start_element(3, 4, 5)]);
  const size = 8 + pool.length + elements.length;
  const root = Buffer.alloc(8);
  root.writeUInt16LE(3, 0);
  root.writeUInt16LE(8, 2);
  root.writeUInt32LE(size, 4);
  return Buffer.concat([root, pool, elements]);
}

test('APK parser decodes Android binary XML string pools and manifest attributes', () => {
  const parsed = parse_apk(apk_fixture({ manifest: binary_manifest_fixture() }));
  assert.equal(parsed.manifest.encoding, 'android-binary-xml');
  assert.equal(parsed.manifest.package_name, 'com.example.binary');
  assert.deepEqual(parsed.manifest.permissions, ['android.permission.INTERNET']);
});

test('APK parser reads raw-DEFLATE manifest entries within the output budget', () => {
  const archive = create_zip_entries([{ name: 'AndroidManifest.xml', contents: Buffer.from('<manifest package="com.example.deflated"/>'), method: 8 }]);
  const parsed = parse_apk(archive);
  assert.equal(parsed.manifest.package_name, 'com.example.deflated');
  assert.ok(parsed.extraction.decompressed_bytes > 0);
});

test('APK parser resolves a DEX class definition through type and string tables', () => {
  const parsed = parse_apk(apk_fixture({ dex: create_dex_class_fixture() }));
  assert.equal(parsed.class_count, 1);
  assert.deepEqual(parsed.dex[0].classes, [{ descriptor: 'Lcom/example/App;', access_flags: 1 }]);
});

test('APK parser rejects local-header names that disagree with central-directory entries', () => {
  const archive = apk_fixture();
  archive[30] = 0x58;
  assert.throws(() => parse_apk(archive), error => error.code === 'ORIX_ANDROID_LOCAL_NAME_MISMATCH');
});

test('APK parser rejects local-header flags that disagree with central-directory metadata', () => {
  const archive = apk_fixture();
  archive.writeUInt16LE(1, 6);
  assert.throws(() => parse_apk(archive), error => error.code === 'ORIX_ANDROID_LOCAL_FLAGS_MISMATCH');
});

test('APK parser rejects duplicate AndroidManifest.xml entries', () => {
  const manifest = Buffer.from('<manifest package="com.example.duplicate"/>');
  const archive = create_zip_entries([
    { name: 'AndroidManifest.xml', contents: manifest },
    { name: 'AndroidManifest.xml', contents: manifest },
  ]);
  assert.throws(() => parse_apk(archive), error => error.code === 'ORIX_ANDROID_DUPLICATE_MANIFEST');
});

test('APK parser rejects local entry data that overlaps the central directory', () => {
  const archive = apk_fixture();
  const eocd = archive.length - 22;
  const central_offset = archive.readUInt32LE(eocd + 16);
  const data_offset = 30 + archive.readUInt16LE(26) + archive.readUInt16LE(28);
  const overlapping_size = central_offset - data_offset + 1;
  archive.writeUInt32LE(overlapping_size, 18);
  archive.writeUInt32LE(overlapping_size, central_offset + 20);
  assert.throws(() => parse_apk(archive), error => error.code === 'ORIX_ANDROID_ENTRY_OVERLAPS_DIRECTORY');
});

test('APK parser rejects an entry whose decompressed CRC32 differs from central metadata', () => {
  const archive = apk_fixture();
  const eocd = archive.length - 22;
  const central_offset = archive.readUInt32LE(eocd + 16);
  archive.writeUInt32LE(0x12345678, central_offset + 16);
  assert.throws(() => parse_apk(archive), error => error.code === 'ORIX_ANDROID_ENTRY_CRC_MISMATCH');
});

test('APK parser rejects local-header CRC and size metadata mismatches', () => {
  const archive = apk_fixture();
  archive.writeUInt32LE(0x12345678, 14);
  assert.throws(() => parse_apk(archive), error => error.code === 'ORIX_ANDROID_LOCAL_METADATA_MISMATCH');
});
