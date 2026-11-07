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
import { parse_zip } from '../src/formats/zip.mjs';

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

function zip_crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
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
    const checksum = zip_crc32(contents);
    const local = Buffer.alloc(30 + name.length + compressed.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(checksum, 14);
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
    central.writeUInt32LE(checksum, 16);
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

function encode_utf8_length8(length) {
  if (length < 0x80) return Buffer.from([length]);
  return Buffer.from([0x80 | (length >>> 8), length & 0xff]);
}

function binary_manifest_with_long_utf8_package(package_name) {
  const values = ['manifest', 'package', package_name];
  const encoded = values.map(value => {
    const bytes = Buffer.from(value, 'utf8');
    const utf16_length = Buffer.byteLength(value, 'utf16le') / 2;
    return Buffer.concat([
      encode_utf8_length8(utf16_length),
      encode_utf8_length8(bytes.length),
      bytes,
      Buffer.from([0]),
    ]);
  });
  const strings_start = 28 + values.length * 4;
  const strings_data = Buffer.concat(encoded);
  const pool_size = (strings_start + strings_data.length + 3) & ~3;
  const pool = Buffer.alloc(pool_size);
  pool.writeUInt16LE(0x0001, 0);
  pool.writeUInt16LE(28, 2);
  pool.writeUInt32LE(pool_size, 4);
  pool.writeUInt32LE(values.length, 8);
  pool.writeUInt32LE(0, 12);
  pool.writeUInt32LE(0x00000100, 16);
  pool.writeUInt32LE(strings_start, 20);
  pool.writeUInt32LE(0, 24);
  let relative = 0;
  for (let i = 0; i < encoded.length; i++) {
    pool.writeUInt32LE(relative, 28 + i * 4);
    encoded[i].copy(pool, strings_start + relative);
    relative += encoded[i].length;
  }

  const start = Buffer.alloc(56);
  start.writeUInt16LE(0x0102, 0);
  start.writeUInt16LE(16, 2);
  start.writeUInt32LE(start.length, 4);
  start.writeUInt32LE(1, 8);
  start.writeUInt32LE(0xffffffff, 12);
  start.writeUInt32LE(0xffffffff, 16);
  start.writeUInt32LE(0, 20);
  start.writeUInt16LE(20, 24);
  start.writeUInt16LE(20, 26);
  start.writeUInt16LE(1, 28);
  start.writeUInt32LE(0xffffffff, 36);
  start.writeUInt32LE(1, 40);
  start.writeUInt32LE(2, 44);
  start.writeUInt16LE(8, 48);
  start[51] = 0x03;
  start.writeUInt32LE(2, 52);

  const end = Buffer.alloc(24);
  end.writeUInt16LE(0x0103, 0);
  end.writeUInt16LE(16, 2);
  end.writeUInt32LE(end.length, 4);
  end.writeUInt32LE(1, 8);
  end.writeUInt32LE(0xffffffff, 12);
  end.writeUInt32LE(0xffffffff, 16);
  end.writeUInt32LE(0, 20);

  const total = 8 + pool.length + start.length + end.length;
  const document = Buffer.alloc(total);
  document.writeUInt16LE(0x0003, 0);
  document.writeUInt16LE(8, 2);
  document.writeUInt32LE(total, 4);
  pool.copy(document, 8);
  start.copy(document, 8 + pool.length);
  end.copy(document, 8 + pool.length + start.length);
  return document;
}

test('APK binary XML decoder reads two-byte UTF-8 lengths without consuming string bytes', () => {
  const package_name = 'x'.repeat(130);
  const decoded = parse_android_binary_xml(binary_manifest_with_long_utf8_package(package_name));
  assert.equal(decoded.package_name, package_name);
});

test('APK binary XML decoder rejects missing UTF-8 string terminators', () => {
  const package_name = 'com.example.orix';
  const manifest = binary_manifest_with_long_utf8_package(package_name);
  const string_start = manifest.indexOf(Buffer.from(package_name, 'utf8'));
  assert.notEqual(string_start, -1);
  manifest[string_start + Buffer.byteLength(package_name, 'utf8')] = 0x01;
  assert.throws(
    () => parse_android_binary_xml(manifest),
    error => error.code === 'ORIX_AXML_STRING_TERMINATOR',
  );
});

test('APK binary XML decoder rejects UTF-8 UTF-16-length mismatches', () => {
  const package_name = 'x'.repeat(130);
  const manifest = binary_manifest_with_long_utf8_package(package_name);
  const string_start = manifest.indexOf(Buffer.from(package_name, 'utf8'));
  assert.notEqual(string_start, -1);
  // The long UTF-8 character-length field immediately precedes the byte-length field.
  manifest[string_start - 3] = 0x81;
  assert.throws(
    () => parse_android_binary_xml(manifest),
    error => error.code === 'ORIX_AXML_STRING_LENGTH',
  );
});

test('APK binary XML decoder enforces file, chunk, string, element and attribute budgets', () => {
  const manifest = binary_manifest();
  assert.throws(
    () => parse_android_binary_xml(manifest, { max_file_bytes: 8 }),
    error => error.code === 'ORIX_AXML_FILE_LIMIT',
  );
  assert.throws(
    () => parse_android_binary_xml(manifest, { max_chunks: 1 }),
    error => error.code === 'ORIX_AXML_CHUNK_LIMIT',
  );
  assert.throws(
    () => parse_android_binary_xml(manifest, { max_strings: 1 }),
    error => error.code === 'ORIX_AXML_STRING_POOL_LIMIT',
  );
  assert.throws(
    () => parse_android_binary_xml(manifest, { max_elements: 1 }),
    error => error.code === 'ORIX_AXML_ELEMENT_LIMIT',
  );
  assert.throws(
    () => parse_android_binary_xml(manifest, { max_attributes: 1 }),
    error => error.code === 'ORIX_AXML_ATTRIBUTE_LIMIT',
  );
  const limited = parse_android_binary_xml(manifest, { max_output_items: 1 });
  assert.ok(limited.permissions.length <= 1);
  assert.ok(limited.components.length <= 1);
  assert.ok(limited.counts.attributes <= 100_000);
});

test('APK binary XML decoder rejects string-pool offsets outside the chunk', () => {
  const manifest = Buffer.from(binary_manifest());
  let offset = 8;
  while (offset < manifest.length) {
    const type = manifest.readUInt16LE(offset);
    const size = manifest.readUInt32LE(offset + 4);
    if (type === 0x0001) {
      const header_size = manifest.readUInt16LE(offset + 2);
      manifest.writeUInt32LE(0xffffffff, offset + header_size);
      break;
    }
    if (size < 8 || size > manifest.length - offset) throw new Error('Invalid test AXML chunk framing');
    offset += size;
  }
  assert.notEqual(offset, manifest.length);
  assert.throws(
    () => parse_android_binary_xml(manifest),
    error => error.code === 'ORIX_AXML_STRING_OFFSET',
  );
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


function add_apk_signing_block(apk, pairs) {
  const archive = parse_zip(apk);
  const encoded_pairs = pairs.map(({ id, value = Buffer.alloc(0) }) => {
    const pair = Buffer.alloc(12 + value.length);
    pair.writeBigUInt64LE(BigInt(4 + value.length), 0);
    pair.writeUInt32LE(id >>> 0, 8);
    value.copy(pair, 12);
    return pair;
  });
  const pair_bytes = Buffer.concat(encoded_pairs);
  const size_of_block = BigInt(pair_bytes.length + 24);
  const block = Buffer.alloc(8 + pair_bytes.length + 24);
  block.writeBigUInt64LE(size_of_block, 0);
  pair_bytes.copy(block, 8);
  block.writeBigUInt64LE(size_of_block, 8 + pair_bytes.length);
  Buffer.from('APK Sig Block 42', 'ascii').copy(block, 16 + pair_bytes.length);
  const central_directory_offset = archive.archive.central_directory_offset;
  const eocd_offset = archive.archive.eocd_offset;
  const result = Buffer.concat([
    apk.subarray(0, central_directory_offset),
    block,
    apk.subarray(central_directory_offset),
  ]);
  result.writeUInt32LE(central_directory_offset + block.length, eocd_offset + block.length + 16);
  return result;
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


test('APK binary XML node extensions honor headerSize and reject truncated node headers', () => {
  const malformed = Buffer.from(binary_manifest());
  const malformedStart = find_binary_xml_chunk(malformed, 0x0102);
  assert.notEqual(malformedStart, -1);
  malformed.writeUInt16LE(8, malformedStart + 2);
  assert.throws(
    () => parse_android_binary_xml(malformed),
    error => error.code === 'ORIX_AXML_NODE_HEADER',
  );

  const extended = Buffer.from(binary_manifest());
  const startElement = find_binary_xml_chunk(extended, 0x0102);
  assert.notEqual(startElement, -1);
  const oldChunkSize = extended.readUInt32LE(startElement + 4);
  const oldRootSize = extended.readUInt32LE(4);
  const withExtendedNodeHeader = Buffer.concat([
    extended.subarray(0, startElement + 16),
    Buffer.alloc(4),
    extended.subarray(startElement + 16),
  ]);
  withExtendedNodeHeader.writeUInt16LE(20, startElement + 2);
  withExtendedNodeHeader.writeUInt32LE(oldChunkSize + 4, startElement + 4);
  withExtendedNodeHeader.writeUInt32LE(oldRootSize + 4, 4);

  const decoded = parse_android_binary_xml(withExtendedNodeHeader);
  assert.equal(decoded.package_name, 'com.example.orix');
  assert.deepEqual(decoded.permissions.map(item => item.name), ['android.permission.INTERNET']);
  assert.equal(decoded.components[0].exported, true);
});

test('APK manifest decoder rejects mismatched end-element names', () => {
  const manifest = Buffer.from(binary_manifest());
  const end_element = find_binary_xml_chunk(manifest, 0x0103);
  assert.notEqual(end_element, -1);
  manifest.writeUInt32LE(0xffffffff, end_element + 20);
  const report = analyze_android_package(create_zip([{ name: 'AndroidManifest.xml', contents: manifest }]));
  assert.equal(report.manifests[0].status, 'malformed-proto-xml');
  assert.equal(report.manifests[0].error.code, 'ORIX_AXML_MISMATCHED_END_TAG');
});

test('APK manifest decoder rejects attribute arrays overlapping the element extension', () => {
  const manifest = Buffer.from(binary_manifest());
  const start_element = find_binary_xml_chunk(manifest, 0x0102);
  assert.notEqual(start_element, -1);
  manifest.writeUInt16LE(0, start_element + 24);
  const report = analyze_android_package(create_zip([{ name: 'AndroidManifest.xml', contents: manifest }]));
  assert.equal(report.manifests[0].status, 'malformed-proto-xml');
  assert.equal(report.manifests[0].error.code, 'ORIX_AXML_ATTRIBUTE_START');
});

test('APK manifest decoder rejects trailing bytes beyond the root chunk', () => {
  const manifest = Buffer.concat([binary_manifest(), Buffer.from([0])]);
  const report = analyze_android_package(create_zip([{ name: 'AndroidManifest.xml', contents: manifest }]));
  assert.equal(report.manifests[0].status, 'malformed-proto-xml');
});

test('AAB inventory routes module manifests through protobuf decoding, never APK binary XML', () => {
  const report = analyze_android_package(create_zip([
    { name: 'BundleConfig.pb', contents: Buffer.from([0x0a, 0x00]) },
    { name: 'base/manifest/AndroidManifest.xml', contents: Buffer.from([0x0a, 0x02, 0x08, 0x01, 0x12, 0x02, 0x08, 0x01]) },
    { name: 'base/dex/classes.dex', contents: create_dex_fixture() },
    { name: 'base/assets/classes2.dex', contents: create_dex_fixture() },
    { name: 'feature/classes.dex', contents: create_dex_fixture() },
  ]));
  assert.equal(report.schema_version, 'orix.android-package.v1');
  assert.equal(report.format, 'AAB');
  assert.equal(report.detected, true);
  assert.equal(report.summary.dex_entries, 1);
  assert.equal(report.summary.dex_metadata_parsed, 1);
  assert.equal(report.manifests[0].binary_xml, false);
  assert.equal(report.manifests[0].status, 'malformed-proto-xml');
  assert.equal(report.manifests[0].proto_xml, true);
});

test('raw-DEFLATE DEX entries are bounded, expanded in memory and parsed', () => {
  const report = analyze_android_package(create_zip([
    { name: 'AndroidManifest.xml', contents: binary_manifest() },
    { name: 'classes.dex', contents: create_dex_fixture(), method: 8 },
  ]));
  assert.equal(report.dex[0].status, 'metadata-parsed');
  assert.equal(report.summary.dex_metadata_parsed, 1);
  assert.deepEqual(report.warnings, []);
  assert.ok(report.dex[0].uncompressed_size > 0);
});

test('raw-DEFLATE APK binary XML manifests are decoded after CRC validation', () => {
  const report = analyze_android_package(create_zip([
    { name: 'AndroidManifest.xml', contents: binary_manifest(), method: 8 },
  ]));
  assert.equal(report.manifests[0].status, 'decoded');
  assert.equal(report.manifests[0].package_name, 'com.example.orix');
});

test('raw-DEFLATE entries cannot exceed declared output bounds', () => {
  const archive = create_zip([
    { name: 'classes.dex', contents: create_dex_fixture(), method: 8 },
  ]);
  const central = parse_zip(archive).archive.central_directory_offset;
  archive.writeUInt32LE(112, 22);
  archive.writeUInt32LE(112, central + 24);
  const report = analyze_android_package(archive);
  assert.equal(report.dex[0].status, 'decompression-failed');
  assert.equal(report.summary.dex_metadata_parsed, 0);
});

test('raw-DEFLATE manifest entries with mismatched CRC metadata are not decoded', () => {
  const archive = create_zip([
    { name: 'AndroidManifest.xml', contents: binary_manifest(), method: 8 },
  ]);
  const central = parse_zip(archive).archive.central_directory_offset;
  archive.writeUInt32LE(0x12345678, 14);
  archive.writeUInt32LE(0x12345678, central + 16);
  const report = analyze_android_package(archive);
  assert.equal(report.manifests[0].status, 'crc-mismatch');
});

test('manifest decompression shares an aggregate budget across AAB modules', () => {
  const manifest = Buffer.concat([Buffer.from([0x0a, 0x0a, 0x1a, 0x08]), Buffer.from('manifest')]);
  const report = analyze_android_package(create_zip([
    { name: 'BundleConfig.pb', contents: Buffer.from([0x0a, 0x00]) },
    { name: 'base/manifest/AndroidManifest.xml', contents: manifest, method: 8 },
    { name: 'feature/manifest/AndroidManifest.xml', contents: manifest, method: 8 },
  ]), { max_manifest_total_bytes: manifest.length + 8 });
  assert.equal(report.manifests[0].status, 'decoded-proto-xml');
  assert.equal(report.manifests[1].status, 'aggregate-size-limit');
});

test('DEX decompression shares an aggregate budget across multidex entries', () => {
  const dex = create_dex_fixture();
  const report = analyze_android_package(create_zip([
    { name: 'classes.dex', contents: dex, method: 8 },
    { name: 'classes2.dex', contents: dex, method: 8 },
  ]), { max_dex_total_bytes: dex.length });
  assert.equal(report.dex[0].status, 'metadata-parsed');
  assert.equal(report.dex[1].status, 'aggregate-size-limit');
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

test('duplicate Android manifest and DEX paths are reported and never parsed', () => {
  const report = analyze_android_package(create_zip([
    { name: 'AndroidManifest.xml', contents: binary_manifest() },
    { name: 'AndroidManifest.xml', contents: binary_manifest() },
    { name: 'classes.dex', contents: create_dex_fixture() },
    { name: 'classes.dex', contents: create_dex_fixture() },
    { name: 'classes2.dex', contents: create_dex_fixture() },
  ]));
  assert.equal(report.format, 'APK');
  assert.equal(report.archive.duplicate_path_names, 2);
  assert.equal(report.archive.duplicate_path_entries, 2);
  assert.equal(report.summary.duplicate_manifest_paths, 1);
  assert.equal(report.summary.duplicate_dex_paths, 1);
  assert.deepEqual(report.manifests.map(item => item.status), ['duplicate-path', 'duplicate-path']);
  assert.deepEqual(report.dex.map(item => item.status), ['duplicate-path', 'duplicate-path', 'metadata-parsed']);
  assert.equal(report.summary.dex_metadata_parsed, 1);
  assert.equal(report.warnings.filter(item => item.reason === 'duplicate-path').length, 4);
});

test('multidex names accept canonical ordinals and reject noncanonical ordinals', () => {
  const report = analyze_android_package(create_zip([
    { name: 'AndroidManifest.xml', contents: binary_manifest() },
    { name: 'classes0.dex', contents: create_dex_fixture() },
    { name: 'classes1.dex', contents: create_dex_fixture() },
    { name: 'classes02.dex', contents: create_dex_fixture() },
    { name: 'classes.dex', contents: create_dex_fixture() },
    { name: 'classes2.dex', contents: create_dex_fixture() },
    { name: 'classes10.dex', contents: create_dex_fixture() },
    { name: 'assets/classes3.dex', contents: create_dex_fixture() },
    { name: 'res/raw/classes4.dex', contents: create_dex_fixture() },
  ]));
  assert.equal(report.summary.dex_entries, 3);
  assert.deepEqual(report.dex.map(item => item.path), ['classes.dex', 'classes2.dex', 'classes10.dex']);
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
  const signature = Buffer.from([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00]);
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
  buffer.writeUInt32LE(buffer.readUInt32LE(central_entry + 16), fake_local_offset + 14);
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

test('Android package Buffer API enforces a bounded input size before ZIP parsing', () => {
  const archive = make_apk();
  assert.throws(
    () => analyze_android_package(archive, { max_file_bytes: archive.length - 1 }),
    error => error instanceof RangeError && /file-size limit/.test(error.message),
  );
  assert.throws(() => analyze_android_package(archive, { max_file_bytes: 0 }), TypeError);
  assert.throws(() => analyze_android_package(new Uint8Array(archive)), TypeError);
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


test('AAB inventory recognizes BundleConfig and reports malformed protobuf module manifests', () => {
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
  assert.equal(report.manifests[0].status, 'malformed-proto-xml');
  assert.equal(report.manifests[0].proto_xml, true);
  assert.equal(report.summary.dex_entries, 1);
  assert.equal(report.dex[0].status, 'metadata-parsed');
  assert.ok(report.limitations.some(note => note.includes('BundleConfig.pb, resources.pb, dependency graph and split/install relationships remain unsupported')));
  assert.ok(report.limitations.some(note => note.includes('raw-DEFLATE, unencrypted entries')));
  assert.ok(report.limitations.some(note => note.includes('instruction opcodes')));
});



test('AAB module inventory separates base and feature paths and decodes each bounded manifest', () => {
  const manifest = Buffer.concat([Buffer.from([0x0a, 0x0a, 0x1a, 0x08]), Buffer.from('manifest')]);
  const report = analyze_android_package(create_zip([
    { name: 'BundleConfig.pb', contents: Buffer.from([0x0a, 0x00]) },
    { name: 'base/manifest/AndroidManifest.xml', contents: manifest },
    { name: 'base/dex/classes.dex', contents: create_dex_fixture() },
    { name: 'base/resources.pb', contents: Buffer.from([0x0a, 0x00]) },
    { name: 'base/res/drawable/icon.png', contents: Buffer.from([1]) },
    { name: 'base/assets/config.json', contents: Buffer.from('{}') },
    { name: 'base/root/etc/config.ini', contents: Buffer.from('safe=true') },
    { name: 'base/lib/arm64-v8a/libbase.so', contents: Buffer.from([1]) },
    { name: 'feature_camera/manifest/AndroidManifest.xml', contents: manifest },
    { name: 'feature_camera/dex/classes2.dex', contents: create_dex_fixture() },
    { name: 'feature_camera/res/drawable/camera.png', contents: Buffer.from([2]) },
  ]));
  assert.equal(report.bundle.status, 'recognized');
  assert.equal(report.bundle.bundle_config_present, true);
  assert.equal(report.bundle.module_count, 2);
  assert.deepEqual(report.bundle.modules.map(module => module.name), ['base', 'feature_camera']);
  assert.equal(report.bundle.modules[0].manifest_present, true);
  assert.equal(report.bundle.modules[0].dex_entries, 1);
  assert.equal(report.bundle.modules[0].native_libraries, 1);
  assert.equal(report.bundle.modules[0].resources_pb_present, true);
  assert.equal(report.bundle.modules[0].resource_paths, 1);
  assert.equal(report.bundle.modules[0].asset_paths, 1);
  assert.equal(report.bundle.modules[0].root_paths, 1);
  assert.equal(report.bundle.modules[1].manifest_present, true);
  assert.deepEqual(report.manifests.map(item => item.status), ['decoded-proto-xml', 'decoded-proto-xml']);
  assert.equal(report.bundle.modules[1].dex_entries, 1);
  assert.equal(report.bundle.modules[1].resource_paths, 1);
  assert.ok(report.limitations.some(note => note.includes('bounded module manifest metadata is decoded')));
});

test('AAB module inventory reports omitted modules under a configured output ceiling', () => {
  const report = analyze_android_package(create_zip([
    { name: 'BundleConfig.pb', contents: Buffer.from([0x0a, 0x00]) },
    { name: 'base/manifest/AndroidManifest.xml', contents: Buffer.alloc(8) },
    { name: 'feature_a/manifest/AndroidManifest.xml', contents: Buffer.alloc(8) },
    { name: 'feature_b/manifest/AndroidManifest.xml', contents: Buffer.alloc(8) },
  ]), { max_aab_modules: 2 });
  assert.equal(report.bundle.module_count, 3);
  assert.equal(report.bundle.modules_reported, 2);
  assert.equal(report.bundle.modules_omitted, 1);
});

test('APK Signing Block inventory recognizes v2/v3/v3.1 IDs and retains unknown IDs without claiming verification', () => {
  const apk = add_apk_signing_block(make_apk(), [
    { id: 0x7109871a, value: Buffer.from([1, 2, 3]) },
    { id: 0xf05368c0, value: Buffer.from([4, 5]) },
    { id: 0x1b93ad61, value: Buffer.from([6]) },
    { id: 0xdeadbeef, value: Buffer.from([7, 8, 9]) },
    { id: 0x7109871a, value: Buffer.from([10]) },
  ]);
  const report = analyze_android_package(apk);
  assert.equal(report.signing_block.status, 'present');
  assert.equal(report.signing_block.pair_count, 5);
  assert.deepEqual(report.signing_block.schemes.map(item => item.name), [
    'APK Signature Scheme v2',
    'APK Signature Scheme v3',
    'APK Signature Scheme v3.1',
  ]);
  assert.deepEqual(report.signing_block.unknown_ids, ['0xdeadbeef']);
  assert.deepEqual(report.signing_block.duplicate_ids, [{ id: '0x7109871a', count: 2 }]);
  assert.equal(report.summary.apk_signing_block_present, true);
  assert.ok(report.limitations.some(note => note.includes('cryptographic signatures')));
});

test('APK Signing Block inventory rejects mismatched size fields and reports the malformed block', () => {
  const apk = add_apk_signing_block(make_apk(), [
    { id: 0x7109871a, value: Buffer.from([1]) },
  ]);
  const central_directory_offset = parse_zip(apk).archive.central_directory_offset;
  const footer_size = apk.readBigUInt64LE(central_directory_offset - 24);
  const signing_block_offset = central_directory_offset - Number(footer_size + 8n);
  apk.writeBigUInt64LE(footer_size - 1n, signing_block_offset);
  const report = analyze_android_package(apk);
  assert.equal(report.signing_block.status, 'malformed');
  assert.equal(report.signing_block.error.code, 'ORIX_APK_SIGNING_BLOCK_SIZE_MISMATCH');
  assert.ok(report.warnings.some(item => item.reason === 'ORIX_APK_SIGNING_BLOCK_SIZE_MISMATCH'));
});

test('APK Signing Block parser enforces configured size and pair-count budgets', () => {
  const apk = add_apk_signing_block(make_apk(), [
    { id: 0x7109871a, value: Buffer.alloc(8) },
    { id: 0xf05368c0, value: Buffer.alloc(8) },
  ]);
  const size_limited = analyze_android_package(apk, { max_signing_block_bytes: 32 });
  assert.equal(size_limited.signing_block.status, 'malformed');
  assert.equal(size_limited.signing_block.error.code, 'ORIX_APK_SIGNING_BLOCK_LIMIT');
  const pair_limited = analyze_android_package(apk, { max_signing_block_pairs: 1 });
  assert.equal(pair_limited.signing_block.status, 'malformed');
  assert.equal(pair_limited.signing_block.error.code, 'ORIX_APK_SIGNING_BLOCK_PAIR_LIMIT');
});

test('APK without a signing block and AAB package report distinguish not-applicable signing metadata', () => {
  assert.equal(analyze_android_package(make_apk()).signing_block.status, 'absent');
  const aab = create_zip([
    { name: 'BundleConfig.pb', contents: Buffer.from([0x0a, 0x00]) },
    { name: 'base/manifest/AndroidManifest.xml', contents: Buffer.alloc(8) },
  ]);
  assert.equal(analyze_android_package(aab).signing_block.status, 'not-applicable');
});
