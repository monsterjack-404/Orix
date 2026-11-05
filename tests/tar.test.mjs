// JavaScript, tests/tar.test.mjs, Node.js 20+, bounded USTAR/PAX/GNU TAR parser contracts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze_known_format, parse_tar, parse_gzip } from '../src/formats/index.mjs';
import { create_tar_fixture, create_pax_record } from './helpers.mjs';
import { deflateRawSync } from 'node:zlib';

function gzip_member(payload) {
  const data = Buffer.from(payload);
  const deflated = deflateRawSync(data);
  const header = Buffer.from([0x1f,0x8b,8,0,0,0,0,0,0,3]);
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  const trailer = Buffer.alloc(8);
  trailer.writeUInt32LE((crc ^ 0xffffffff) >>> 0, 0);
  trailer.writeUInt32LE(data.length >>> 0, 4);
  return Buffer.concat([header, deflated, trailer]);
}

test('TAR parser inventories USTAR entry metadata, ownership, offsets and checksums', () => {
  const archive = create_tar_fixture([{ name: 'boot/init', contents: 'firmware', mode: 0o100755, uid: 0, gid: 0 }]);
  const report = parse_tar(archive);
  assert.equal(report.format, 'TAR');
  assert.equal(report.variant, 'ustar-compatible');
  assert.equal(report.complete, true);
  assert.equal(report.summary.entries, 1);
  assert.equal(report.entries[0].name, 'boot/init');
  assert.equal(report.entries[0].type, 'regular');
  assert.equal(report.entries[0].permissions, '0755');
  assert.equal(report.entries[0].uid, 0);
  assert.equal(report.entries[0].header_checksum.verified, true);
  assert.equal(report.entries[0].data_bytes_indexed_only, true);
});

test('TAR parser marks traversal paths unsafe and reports duplicate names', () => {
  const archive = create_tar_fixture([
    { name: '../escape', contents: 'x' },
    { name: '../escape', contents: 'y' },
    { name: '/absolute', contents: 'z' },
  ]);
  const report = parse_tar(archive);
  assert.equal(report.summary.unsafe_paths, 3);
  assert.deepEqual(report.duplicates, ['../escape']);
  assert.equal(report.entries[0].unsafe_reason, 'path-traversal-or-absolute');
});

test('TAR parser applies PAX path and size metadata to the following entry', () => {
  const pax = Buffer.concat([create_pax_record('path', 'rootfs/' + 'a'.repeat(120)), create_pax_record('size', '3')]);
  const archive = create_tar_fixture([
    { name: 'PaxHeaders/file', typeflag: 'x', contents: pax },
    { name: 'short', contents: 'abc', size_override: 3 },
  ]);
  const report = parse_tar(archive);
  assert.equal(report.extension_headers, 1);
  assert.equal(report.pax_records, 2);
  assert.equal(report.entries[0].name, 'rootfs/' + 'a'.repeat(120));
  assert.equal(report.entries[0].size_bytes, 3);
});

test('TAR parser applies GNU long-name metadata without extracting its payload', () => {
  const long_name = 'usr/lib/' + 'module-'.repeat(20) + 'kernel.ko';
  const archive = create_tar_fixture([
    { name: '././@LongLink', typeflag: 'L', contents: Buffer.from(long_name + '\0') },
    { name: 'short-name', contents: 'x' },
  ]);
  const report = parse_tar(archive);
  assert.equal(report.extension_headers, 1);
  assert.equal(report.entries[0].name, long_name);
});

test('TAR parser rejects invalid header checksums and malformed octal fields', () => {
  const checksum = create_tar_fixture([{ name: 'file', contents: 'x' }]);
  checksum[0] ^= 1;
  assert.throws(() => parse_tar(checksum), error => error.code === 'ORIX_TAR_CHECKSUM_MISMATCH');
  const octal = create_tar_fixture([{ name: 'file', contents: 'x' }]);
  octal.write('zzzzzzzz', 100, 8, 'ascii');
  rewrite_tar_checksum(octal);
  assert.throws(() => parse_tar(octal), error => error.code === 'ORIX_TAR_BAD_OCTAL');
});

test('TAR parser rejects truncated entry data and enforces configured limits', () => {
  const archive = create_tar_fixture([{ name: 'file', contents: 'long-payload' }]);
  assert.throws(() => parse_tar(archive.subarray(0, 514)), error => error.code === 'ORIX_TAR_ENTRY_RANGE');
  assert.throws(() => parse_tar(archive, { max_entry_bytes: 2 }), error => error.code === 'ORIX_TAR_ENTRY_LIMIT');
  assert.throws(() => parse_tar(archive, { max_input_bytes: 8 }), error => error.code === 'ORIX_TAR_INPUT_LIMIT');
});

test('TAR parser reports an incomplete archive without two zero end blocks', () => {
  const archive = create_tar_fixture([{ name: 'file', contents: 'x' }]).subarray(0, 1024);
  const report = parse_tar(archive);
  assert.equal(report.complete, false);
  assert.equal(report.trailer_found, false);
});

test('TAR parser is selected by format dispatch and package subpath', async () => {
  const archive = create_tar_fixture([{ name: 'etc/config', contents: 'ok' }]);
  const result = analyze_known_format(archive);
  assert.equal(result.detection.format, 'TAR');
  assert.equal(result.parser_status, 'parsed');
  const api = await import('@orix/cli/formats/tar');
  assert.equal(typeof api.parse_tar, 'function');
  const root_api = await import('../src/index.mjs');
  assert.equal(typeof root_api.parse_tar, 'function');
});

test('GZIP parser identifies and structurally parses a nested USTAR archive', () => {
  const archive = gzip_member(create_tar_fixture([{ name: 'rootfs/init', contents: 'boot' }]));
  const report = parse_gzip(archive);
  assert.equal(report.nested_format, 'TAR');
  assert.equal(report.nested_parser_status, 'parsed');
  assert.equal(report.nested.entries[0].name, 'rootfs/init');
});

function rewrite_tar_checksum(archive, signed = false) {
  archive.fill(0x20, 148, 156);
  let sum = 0;
  for (let i = 0; i < 512; i += 1) {
    const value = archive[i];
    sum += signed && value > 127 ? value - 256 : value;
  }
  archive.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
}

test('TAR parser accepts positive base-256 numeric fields and rejects negative values', () => {
  const positive = create_tar_fixture([{ name: 'file', contents: 'abc' }]);
  positive.fill(0, 124, 136);
  positive[124] = 0x80;
  positive[135] = 3;
  rewrite_tar_checksum(positive);
  assert.equal(parse_tar(positive).entries[0].size_bytes, 3);
  const negative = create_tar_fixture([{ name: 'file', contents: 'abc' }]);
  negative.fill(0, 124, 136);
  negative[124] = 0xc0;
  rewrite_tar_checksum(negative);
  assert.throws(() => parse_tar(negative), error => error.code === 'ORIX_TAR_NEGATIVE_NUMBER');
});

test('TAR parser accepts signed checksum variant and marks non-UTF8 paths unsafe', () => {
  const archive = create_tar_fixture([{ name: 'file', contents: 'x' }]);
  archive[0] = 0xff;
  rewrite_tar_checksum(archive, true);
  const report = parse_tar(archive);
  assert.equal(report.entries[0].header_checksum.variant, 'signed');
  assert.equal(report.entries[0].safe_path, false);
  assert.equal(report.entries[0].unsafe_reason, 'non-utf8-path');
});

test('TAR parser rejects invalid UTF-8 in PAX metadata', () => {
  const prefix = Buffer.from('9 path=', 'ascii');
  const payload = Buffer.concat([prefix, Buffer.from([0xff]), Buffer.from('\n')]);
  const archive = create_tar_fixture([{ name: 'PaxHeaders/file', typeflag: 'x', contents: payload }]);
  assert.throws(() => parse_tar(archive), error => error.code === 'ORIX_TAR_BAD_PAX_RECORD' || error.code === 'ORIX_TAR_INVALID_UTF8');
});

test('TAR parser enforces path and link-name byte ceilings', () => {
  const archive = create_tar_fixture([{ name: 'long-name', contents: 'x' }]);
  assert.throws(() => parse_tar(archive, { max_name_bytes: 4 }), error => error.code === 'ORIX_TAR_NAME_LIMIT');
});

test('TAR parser inventories directory, symlink and hardlink types without resolving them', () => {
  const archive = create_tar_fixture([
    { name: 'rootfs/etc', typeflag: '5', contents: '' },
    { name: 'rootfs/config-link', typeflag: '2', linkname: 'etc/config', contents: '' },
    { name: 'rootfs/config-hardlink', typeflag: '1', linkname: 'rootfs/etc/config', contents: '' },
  ]);
  const report = parse_tar(archive);
  assert.deepEqual(report.entries.map(entry => entry.type), ['directory', 'symlink', 'hardlink']);
  assert.equal(report.entries[1].safe_link_target, true);
  assert.equal(report.entries[2].safe_link_target, true);
  assert.equal(report.summary.links, 2);
});

test('TAR parser separately flags unsafe symlink and hardlink targets', () => {
  const archive = create_tar_fixture([
    { name: 'safe-name', typeflag: '2', linkname: '../../outside', contents: '' },
    { name: 'absolute-link', typeflag: '1', linkname: '/etc/passwd', contents: '' },
  ]);
  const report = parse_tar(archive);
  assert.equal(report.summary.unsafe_paths, 0);
  assert.equal(report.summary.unsafe_link_targets, 2);
  assert.equal(report.entries[0].safe_path, true);
  assert.equal(report.entries[0].safe_link_target, false);
});

test('TAR parser applies global PAX metadata and reports trailing bytes', () => {
  const pax = create_pax_record('uname', 'firmware-builder');
  const archive = Buffer.concat([
    create_tar_fixture([
      { name: 'GlobalHead', typeflag: 'g', contents: pax },
      { name: 'first', contents: 'a' },
      { name: 'second', contents: 'b' },
    ]),
    Buffer.from('TRAILER'),
  ]);
  const report = parse_tar(archive);
  assert.equal(report.entries[0].uname, 'firmware-builder');
  assert.equal(report.entries[1].uname, 'firmware-builder');
  assert.equal(report.complete, true);
  assert.equal(report.trailing_bytes, 7);
});

test('TAR parser rejects malformed PAX lengths and bounds extension metadata', () => {
  const malformed = create_tar_fixture([
    { name: 'PaxHeaders/file', typeflag: 'x', contents: Buffer.from('999 path=x\\n') },
  ]);
  assert.throws(() => parse_tar(malformed), error => error.code === 'ORIX_TAR_BAD_PAX_RECORD');
  const large_metadata = create_tar_fixture([
    { name: 'PaxHeaders/file', typeflag: 'x', contents: Buffer.alloc(32, 0x41) },
  ]);
  assert.throws(() => parse_tar(large_metadata, { max_metadata_bytes: 8 }), error => error.code === 'ORIX_TAR_METADATA_LIMIT');
});

test('TAR parser enforces aggregate data, entry count and metadata record ceilings', () => {
  const archive = create_tar_fixture([
    { name: 'one', contents: '1234' },
    { name: 'two', contents: '5678' },
  ]);
  assert.throws(() => parse_tar(archive, { max_total_data_bytes: 6 }), error => error.code === 'ORIX_TAR_ENTRY_LIMIT');
  assert.throws(() => parse_tar(archive, { max_entries: 1 }), error => error.code === 'ORIX_TAR_ENTRY_COUNT_LIMIT');
  const pax = Buffer.concat([create_pax_record('uname', 'a'), create_pax_record('gname', 'b')]);
  const with_pax = create_tar_fixture([{ name: 'PaxHeaders/file', typeflag: 'x', contents: pax }]);
  assert.throws(() => parse_tar(with_pax, { max_pax_records: 1 }), error => error.code === 'ORIX_TAR_PAX_RECORD_LIMIT');
});

test('TAR parser rejects truncated headers and missing entry padding', () => {
  assert.throws(() => parse_tar(Buffer.alloc(511)), error => error.code === 'ORIX_TAR_HEADER_TRUNCATED');
  const archive = create_tar_fixture([{ name: 'file', contents: 'x' }]);
  assert.throws(() => parse_tar(archive.subarray(0, 513)), error => error.code === 'ORIX_TAR_ENTRY_PADDING_TRUNCATED');
});

test('TAR parser treats backslash traversal and drive-prefixed paths as unsafe', () => {
  const archive = create_tar_fixture([
    { name: '..\\\\outside', contents: 'x' },
    { name: 'C:/Windows/system.ini', contents: 'y' },
  ]);
  const report = parse_tar(archive);
  assert.equal(report.summary.unsafe_paths, 2);
});
