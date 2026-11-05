// JavaScript, tests/ubi.test.mjs, Node.js 20+, UBI EC/VID header validation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_ubi } from '../src/formats/ubi.mjs';
import { analyze_known_format } from '../src/formats/index.mjs';

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) { crc ^= byte; for (let i = 0; i < 8; i += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0); }
  return crc >>> 0;
}
function image({ pebSize = 4096, includeVid = true } = {}) {
  const b = Buffer.alloc(pebSize, 0xff);
  b.write('UBI#', 0, 'ascii'); b[4] = 1;
  b.writeBigUInt64BE(7n, 8); b.writeUInt32BE(64, 16); b.writeUInt32BE(128, 20); b.writeUInt32BE(0x12345678, 24);
  b.writeUInt32BE(crc32(b.subarray(0, 60)), 60);
  if (includeVid) {
    b.write('UBI!', 64, 'ascii'); b[68] = 1; b[69] = 1; b[70] = 0; b[71] = 0;
    b.writeUInt32BE(3, 72); b.writeUInt32BE(2, 76);
    b.writeUInt32BE(0, 84); b.writeUInt32BE(0, 88); b.writeUInt32BE(0, 92); b.writeUInt32BE(0, 96);
    b.writeBigUInt64BE(9n, 104);
    b.writeUInt32BE(crc32(b.subarray(64, 124)), 124);
  }
  return b;
}

test('UBI parses EC and VID headers and validates CRCs', () => {
  const parsed = parse_ubi(image());
  assert.equal(parsed.format, 'UBI');
  assert.equal(parsed.first_peb.erase_counter_header.erase_counter, 7);
  assert.equal(parsed.first_peb.volume_identifier_header.volume_type, 'dynamic');
  assert.equal(parsed.first_peb.volume_identifier_header.volume_id, 3);
  assert.equal(parsed.validation.first_ec_header_crc_valid, true);
});

test('UBI supports first-PEB inspection without guessing flash geometry', () => {
  const parsed = parse_ubi(image());
  assert.equal(parsed.geometry.physical_eraseblock_size, null);
  assert.equal(parsed.scan, null);
});

test('UBI scans PEBs only when explicit geometry is supplied', () => {
  const first = image();
  const second = Buffer.alloc(4096, 0xff);
  const parsed = parse_ubi(Buffer.concat([first, second]), { peb_size: 4096 });
  assert.equal(parsed.scan.scanned_pebs, 2);
  assert.equal(parsed.scan.erased_pebs, 1);
});

test('UBI rejects truncated, invalid magic and corrupt CRC headers', () => {
  assert.throws(() => parse_ubi(Buffer.alloc(63)), e => e.code === 'ORIX_UBI_TRUNCATED_EC_HEADER');
  assert.throws(() => parse_ubi(Buffer.alloc(64)), e => e.code === 'ORIX_UBI_BAD_EC_MAGIC');
  const bad = image(); bad[8] ^= 1;
  assert.throws(() => parse_ubi(bad), e => e.code === 'ORIX_UBI_EC_CRC_MISMATCH');
});

test('UBI rejects inconsistent offsets, unsupported versions and bad VID CRC', () => {
  const offsets = image(); offsets.writeUInt32BE(16, 16); offsets.writeUInt32BE(crc32(offsets.subarray(0, 60)), 60);
  assert.throws(() => parse_ubi(offsets), e => e.code === 'ORIX_UBI_INVALID_OFFSETS');
  const version = image(); version[4] = 2; version.writeUInt32BE(crc32(version.subarray(0, 60)), 60);
  assert.throws(() => parse_ubi(version), e => e.code === 'ORIX_UBI_UNSUPPORTED_VERSION');
  const vid = image(); vid[70] = 2;
  assert.throws(() => parse_ubi(vid), e => e.code === 'ORIX_UBI_VID_CRC_MISMATCH');
});

test('UBI enforces explicit PEB geometry and bounded input', () => {
  assert.throws(() => parse_ubi(image(), { peb_size: 1024 }), TypeError);
  assert.throws(() => parse_ubi(image(), { max_input_bytes: 64 }), e => e.code === 'ORIX_UBI_INPUT_LIMIT');
  const result = analyze_known_format(image());
  assert.equal(result.detection.format, 'UBI');
  assert.equal(result.parser_status, 'parsed');
});
