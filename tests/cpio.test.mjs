// JavaScript, tests/cpio.test.mjs, Node.js 20+, deterministic CPIO newc fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze_known_format, parse_cpio } from '../src/formats/index.mjs';

function cpio_entry(name, data = Buffer.alloc(0), { magic = '070701', mode = 0o100644, uid = 1000, gid = 1000, nlink = 1, ino = 1, mtime = 1, check_override = null } = {}) {
  const payload = Buffer.from(data);
  const filename = Buffer.from(name + '\0', 'utf8');
  let check = 0;
  for (const byte of payload) check = (check + byte) >>> 0;
  if (check_override !== null) check = check_override >>> 0;
  const fields = [ino, mode, uid, gid, nlink, mtime, payload.length, 0, 0, 0, 0, filename.length, check];
  const header = Buffer.alloc(110);
  header.write(magic, 0, 6, 'ascii');
  fields.forEach((value, index) => header.write(value.toString(16).padStart(8, '0'), 6 + index * 8, 8, 'ascii'));
  const name_padding = Buffer.alloc((4 - ((110 + filename.length) % 4)) % 4);
  const data_padding = Buffer.alloc((4 - (payload.length % 4)) % 4);
  return Buffer.concat([header, filename, name_padding, payload, data_padding]);
}

function cpio_archive(entries, magic = '070701', include_trailer = true) {
  const trailer = include_trailer ? cpio_entry('TRAILER!!!', Buffer.alloc(0), { magic, mode: 0, nlink: 1, ino: 0 }) : Buffer.alloc(0);
  return Buffer.concat([...entries, trailer]);
}

test('CPIO newc parser inventories entry metadata and detects unsafe or duplicate paths', () => {
  const archive = cpio_archive([
    cpio_entry('.', Buffer.alloc(0), { mode: 0o040755, ino: 1 }),
    cpio_entry('etc/passwd', Buffer.from('root:x:0:0\n'), { ino: 2 }),
    cpio_entry('../escape', Buffer.from('x'), { ino: 3 }),
    cpio_entry('etc/passwd', Buffer.from('shadow'), { ino: 4 }),
    cpio_entry('bin/tool', Buffer.from('x'), { mode: 0o100755, nlink: 2, ino: 5 }),
  ]);
  const report = parse_cpio(archive);
  assert.equal(report.format, 'CPIO newc');
  assert.equal(report.variant, 'newc');
  assert.equal(report.complete, true);
  assert.equal(report.trailer_found, true);
  assert.equal(report.summary.entries, 5);
  assert.equal(report.summary.regular_files, 4);
  assert.equal(report.summary.directories, 1);
  assert.equal(report.summary.unsafe_paths, 1);
  assert.equal(report.summary.duplicate_paths, 1);
  assert.equal(report.entries[1].safe_path, true);
  assert.equal(report.entries[2].unsafe_reason, 'path-traversal-or-absolute');
  assert.equal(report.entries[4].hardlink_candidate, true);
});

test('CPIO CRC-newc verifies the byte-sum check field', () => {
  const archive = cpio_archive([cpio_entry('etc/config', Buffer.from('hello'), { magic: '070702' })], '070702');
  const report = parse_cpio(archive);
  assert.equal(report.variant, 'newc-crc');
  assert.equal(report.entries[0].checksum.verified, true);
  archive[report.entries[0].data_offset] ^= 1;
  assert.throws(() => parse_cpio(archive), error => error.code === 'ORIX_CPIO_CHECKSUM_MISMATCH');
});

test('CPIO parser rejects unsupported magic and malformed hexadecimal fields', () => {
  assert.throws(() => parse_cpio(Buffer.from('070703' + '0'.repeat(104))), error => error.code === 'ORIX_CPIO_BAD_MAGIC');
  const archive = cpio_archive([cpio_entry('a', Buffer.from('x'))]);
  archive.write('zzzzzzzz', 6, 8, 'ascii');
  assert.throws(() => parse_cpio(archive), error => error.code === 'ORIX_CPIO_BAD_HEX_FIELD');
});

test('CPIO parser rejects invalid filename terminators and truncated entry data', () => {
  const bad_name = cpio_archive([cpio_entry('file', Buffer.from('x'))]);
  const name_size = Number.parseInt(bad_name.toString('ascii', 94, 102), 16);
  bad_name[110 + name_size - 1] = 0x41;
  assert.throws(() => parse_cpio(bad_name), error => error.code === 'ORIX_CPIO_BAD_NAME_TERMINATOR');
  const truncated = cpio_archive([cpio_entry('file', Buffer.from('long-data'))]).subarray(0, 120);
  assert.throws(() => parse_cpio(truncated), error => error.code === 'ORIX_TRUNCATED_INPUT');
});

test('CPIO parser reports a missing trailer as incomplete and enforces limits', () => {
  const archive = cpio_archive([cpio_entry('file', Buffer.from('data')), cpio_entry('second', Buffer.from('x'), { ino: 2 })], '070701', false);
  assert.equal(parse_cpio(archive).complete, false);
  assert.throws(() => parse_cpio(archive, { max_entries: 1 }), error => error.code === 'ORIX_CPIO_ENTRY_COUNT_LIMIT');
  assert.throws(() => parse_cpio(archive, { max_entry_bytes: 2 }), error => error.code === 'ORIX_CPIO_ENTRY_LIMIT');
  assert.throws(() => parse_cpio(archive, { max_input_bytes: 8 }), error => error.code === 'ORIX_CPIO_INPUT_LIMIT');
});

test('format dispatcher recognizes and parses CPIO newc', () => {
  const archive = cpio_archive([cpio_entry('init', Buffer.from('x'))]);
  const result = analyze_known_format(archive);
  assert.equal(result.detection.format, 'CPIO newc');
  assert.equal(result.parser_status, 'parsed');
  assert.equal(result.parsed.summary.entries, 1);
});

test('CPIO parser is exported through the package subpath', async () => {
  const public_api = await import('@orix/cli/formats/cpio');
  assert.equal(typeof public_api.parse_cpio, 'function');
});
