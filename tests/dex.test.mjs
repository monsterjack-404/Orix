// JavaScript, tests/dex.test.mjs, Node.js 20+, DEX header parser contracts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_dex } from '../src/formats/dex.mjs';

function dex_fixture({ version = '035', file_size = 112, endian = 'little', string_count = 0, string_offset = 0 } = {}) {
  const buffer = Buffer.alloc(112);
  buffer.write('dex\\n' + version + '\\0', 0, 'ascii');
  const write16 = endian === 'little' ? 'writeUInt16LE' : 'writeUInt16BE';
  const write32 = endian === 'little' ? 'writeUInt32LE' : 'writeUInt32BE';
  buffer[write32](file_size, 32);
  buffer[write32](112, 36);
  buffer[write32](0x12345678, 40);
  buffer[write32](string_count, 56);
  buffer[write32](string_offset, 60);
  return buffer;
}

test('parses a valid little-endian DEX 035 header and empty tables', () => {
  const report = parse_dex(dex_fixture());
  assert.equal(report.format, 'DEX');
  assert.equal(report.version, '035');
  assert.equal(report.header.file_size, 112);
  assert.equal(report.header.byte_order, 'little-endian');
  assert.equal(report.header.tables.string_ids.count, 0);
});

test('parses reverse-endian DEX header fields', () => {
  const report = parse_dex(dex_fixture({ endian: 'big' }));
  assert.equal(report.header.byte_order, 'reverse-endian');
  assert.equal(report.header.header_size, 112);
});

test('supports header-only inspection with a trusted containing-entry size', () => {
  const report = parse_dex(dex_fixture({ file_size: 4096 }), { header_only: true, declared_size: 4096 });
  assert.equal(report.header.file_size, 4096);
  assert.throws(() => parse_dex(dex_fixture({ file_size: 4096 })), error => error.code === 'ORIX_DEX_TRUNCATED_FILE');
  assert.throws(() => parse_dex(dex_fixture({ file_size: 4096 }), { header_only: true, declared_size: 4097 }), error => error.code === 'ORIX_DEX_SIZE_MISMATCH');
});

test('rejects malformed magic, unsupported version and out-of-file table ranges', () => {
  const bad_magic = dex_fixture();
  bad_magic[0] = 0;
  assert.throws(() => parse_dex(bad_magic), error => error.code === 'ORIX_DEX_BAD_MAGIC');
  assert.throws(() => parse_dex(dex_fixture({ version: '041' })), error => error.code === 'ORIX_DEX_UNSUPPORTED_VERSION');
  assert.throws(() => parse_dex(dex_fixture({ file_size: 112, string_count: 1, string_offset: 112 })), error => error.code === 'ORIX_DEX_TABLE_RANGE');
});
