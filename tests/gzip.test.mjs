// JavaScript, tests/gzip.test.mjs, Node.js 20+, deterministic GZIP and nested CPIO fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { analyze_known_format, parse_gzip } from '../src/formats/index.mjs';

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function gzip_member(payload, options = {}) {
  const data = Buffer.from(payload);
  let flags = 0;
  if (options.extra) flags |= 0x04;
  if (options.filename) flags |= 0x08;
  if (options.comment) flags |= 0x10;
  if (options.header_crc) flags |= 0x02;
  const header = Buffer.alloc(10);
  header[0] = 0x1f;
  header[1] = 0x8b;
  header[2] = 8;
  header[3] = flags;
  header.writeUInt32LE(options.mtime ?? 1234, 4);
  header[8] = options.xfl ?? 2;
  header[9] = options.os ?? 3;
  const parts = [header];
  if (options.extra) {
    const length = Buffer.alloc(2);
    length.writeUInt16LE(options.extra.length);
    parts.push(length, options.extra);
  }
  if (options.filename) parts.push(Buffer.from(options.filename + '\0'));
  if (options.comment) parts.push(Buffer.from(options.comment + '\0'));
  let head = Buffer.concat(parts);
  if (options.header_crc) {
    const checksum = Buffer.alloc(2);
    checksum.writeUInt16LE(crc32(head) & 0xffff);
    head = Buffer.concat([head, checksum]);
  }
  const deflated = deflateRawSync(data);
  const trailer = Buffer.alloc(8);
  trailer.writeUInt32LE(crc32(data), 0);
  trailer.writeUInt32LE(data.length >>> 0, 4);
  if (options.bad_crc) trailer.writeUInt32LE((crc32(data) ^ 1) >>> 0, 0);
  if (options.bad_size) trailer.writeUInt32LE((data.length + 1) >>> 0, 4);
  return Buffer.concat([head, deflated, trailer]);
}

function cpio_entry(name, data, ino = 1) {
  const payload = Buffer.from(data);
  const filename = Buffer.from(name + '\0');
  const header = Buffer.alloc(110);
  header.write('070701', 0, 6, 'ascii');
  const fields = [ino, 0o100644, 0, 0, 1, 1, payload.length, 0, 0, 0, 0, filename.length, 0];
  fields.forEach((value, index) => header.write(value.toString(16).padStart(8, '0'), 6 + index * 8, 8, 'ascii'));
  const name_pad = Buffer.alloc((4 - ((110 + filename.length) % 4)) % 4);
  const data_pad = Buffer.alloc((4 - (payload.length % 4)) % 4);
  return Buffer.concat([header, filename, name_pad, payload, data_pad]);
}

function cpio_archive() {
  const trailer = cpio_entry('TRAILER!!!', Buffer.alloc(0), 0);
  return Buffer.concat([cpio_entry('init', Buffer.from('rootfs')), trailer]);
}

test('GZIP parser validates optional header fields, CRC16, CRC32 and ISIZE', () => {
  const payload = Buffer.from('firmware image metadata');
  const archive = gzip_member(payload, { extra: Buffer.from([1, 2, 3]), filename: 'rootfs.cpio', comment: 'test image', header_crc: true });
  const report = parse_gzip(archive);
  assert.equal(report.format, 'GZIP');
  assert.equal(report.complete, true);
  assert.equal(report.members.length, 1);
  assert.equal(report.members[0].flags.extra, true);
  assert.equal(report.members[0].flags.filename, true);
  assert.equal(report.members[0].flags.comment, true);
  assert.equal(report.members[0].flags.header_crc, true);
  assert.equal(report.members[0].extra_bytes, 3);
  assert.equal(report.members[0].crc32.verified, true);
  assert.equal(report.members[0].isize.verified, true);
  assert.equal(report.summary.decompressed_bytes, payload.length);
  assert.equal(report.nested_format, 'Unknown');
});

test('GZIP parser supports concatenated members and hashes combined output', () => {
  const first = gzip_member(Buffer.from('hello '));
  const second = gzip_member(Buffer.from('world'));
  const report = parse_gzip(Buffer.concat([first, second]));
  assert.equal(report.members.length, 2);
  assert.equal(report.summary.decompressed_bytes, 11);
  assert.equal(report.complete, true);
  assert.match(report.decompressed_sha256, /^[a-f0-9]{64}$/);
});

test('GZIP parser identifies and structurally parses a nested CPIO newc archive', () => {
  const report = parse_gzip(gzip_member(cpio_archive()));
  assert.equal(report.nested_format, 'CPIO newc');
  assert.equal(report.nested_parser_status, 'parsed');
  assert.equal(report.nested.summary.entries, 1);
  assert.equal(report.nested.entries[0].name, 'init');
});

test('GZIP parser rejects data CRC, ISIZE and optional header CRC mismatches', () => {
  assert.throws(() => parse_gzip(gzip_member(Buffer.from('crc'), { bad_crc: true })), error => error.code === 'ORIX_GZIP_DATA_CRC_MISMATCH');
  assert.throws(() => parse_gzip(gzip_member(Buffer.from('size'), { bad_size: true })), error => error.code === 'ORIX_GZIP_SIZE_MISMATCH');
  const bad_header = gzip_member(Buffer.from('header'), { header_crc: true });
  bad_header[10] ^= 1;
  assert.throws(() => parse_gzip(bad_header), error => error.code === 'ORIX_GZIP_HEADER_CRC_MISMATCH');
});

test('GZIP parser rejects reserved flags, unsupported methods and malformed optional fields', () => {
  const reserved = gzip_member(Buffer.from('x'));
  reserved[3] |= 0x20;
  assert.throws(() => parse_gzip(reserved), error => error.code === 'ORIX_GZIP_RESERVED_FLAGS');
  const method = gzip_member(Buffer.from('x'));
  method[2] = 0;
  assert.throws(() => parse_gzip(method), error => error.code === 'ORIX_GZIP_UNSUPPORTED_METHOD');
  const no_filename_terminator = Buffer.concat([Buffer.from([0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 3]), Buffer.from('unterminated')]);
  assert.throws(() => parse_gzip(no_filename_terminator), error => error.code === 'ORIX_GZIP_HEADER_FIELD_LIMIT');
});

test('GZIP parser reports trailing bytes and enforces input and output limits', () => {
  const archive = gzip_member(Buffer.from('firmware-data'));
  const trailing = parse_gzip(Buffer.concat([archive, Buffer.from('junk')]));
  assert.equal(trailing.complete, false);
  assert.equal(trailing.summary.trailing_bytes, 4);
  assert.throws(() => parse_gzip(archive, { max_input_bytes: 8 }), error => error.code === 'ORIX_GZIP_INPUT_LIMIT');
  assert.throws(() => parse_gzip(archive, { max_total_output_bytes: 2 }), error => error.code === 'ORIX_GZIP_OUTPUT_LIMIT');
});

test('GZIP parser is selected by format dispatch and exposed by package subpath', async () => {
  const archive = gzip_member(Buffer.from('plain text'));
  const result = analyze_known_format(archive);
  assert.equal(result.detection.format, 'GZIP');
  assert.equal(result.parser_status, 'parsed');
  const public_api = await import('@orix/cli/formats/gzip');
  assert.equal(typeof public_api.parse_gzip, 'function');
});
