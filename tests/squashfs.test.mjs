// JavaScript, tests/squashfs.test.mjs, Node.js 20+, SquashFS superblock validation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_squashfs } from '../src/formats/squashfs.mjs';
import { analyze_known_format } from '../src/formats/index.mjs';

function fixture({ little = true, blockSize = 131072, blockLog = 17, bytesUsed = 256, compression = 4 } = {}) {
  const b = Buffer.alloc(256);
  b.write(little ? 'hsqs' : 'sqsh', 0, 'ascii');
  const w16 = (o, v) => little ? b.writeUInt16LE(v, o) : b.writeUInt16BE(v, o);
  const w32 = (o, v) => little ? b.writeUInt32LE(v, o) : b.writeUInt32BE(v, o);
  const w64 = (o, v) => little ? b.writeBigUInt64LE(BigInt(v), o) : b.writeBigUInt64BE(BigInt(v), o);
  w32(4, 10); w32(8, 1700000000); w32(12, blockSize); w32(16, 0);
  w16(20, compression); w16(22, blockLog); w16(24, 0x0008); w16(26, 1);
  w16(28, 4); w16(30, 0); w64(32, 0n); w64(40, bytesUsed);
  for (const o of [48,56,80,88]) w64(o, 0xffffffffffffffffn);
  w64(64, 128); w64(72, 160);
  return b;
}

test('SquashFS parses little-endian v4.0 superblock and bounded table offsets', () => {
  const parsed = parse_squashfs(fixture());
  assert.equal(parsed.format, 'SquashFS');
  assert.equal(parsed.byte_order, 'little-endian');
  assert.equal(parsed.superblock.block_size, 131072);
  assert.equal(parsed.superblock.compression, 'xz');
  assert.equal(parsed.tables.inode_table.offset, 128);
  assert.equal(parsed.tables.directory_table.offset, 160);
  assert.equal(parsed.validation.declared_filesystem_within_input, true);
});

test('SquashFS parses big-endian v4.0 superblock', () => {
  const parsed = parse_squashfs(fixture({ little: false }));
  assert.equal(parsed.byte_order, 'big-endian');
  assert.equal(parsed.superblock.inode_count, 10);
});

test('SquashFS rejects short input and bad magic', () => {
  assert.throws(() => parse_squashfs(Buffer.alloc(95)), e => e.code === 'ORIX_SQUASHFS_TRUNCATED_SUPERBLOCK');
  assert.throws(() => parse_squashfs(Buffer.alloc(96)), e => e.code === 'ORIX_SQUASHFS_BAD_MAGIC');
});

test('SquashFS rejects unsupported version, block geometry and declared size', () => {
  const version = fixture(); version.writeUInt16LE(1, 30);
  assert.throws(() => parse_squashfs(version), e => e.code === 'ORIX_SQUASHFS_UNSUPPORTED_VERSION');
  const block = fixture(); block.writeUInt32LE(1000, 12);
  assert.throws(() => parse_squashfs(block), e => e.code === 'ORIX_SQUASHFS_INVALID_BLOCK_SIZE');
  const size = fixture(); size.writeBigUInt64LE(999n, 40);
  assert.throws(() => parse_squashfs(size), e => e.code === 'ORIX_SQUASHFS_BYTES_USED_RANGE');
});

test('SquashFS rejects mismatched block log and out-of-range table offsets', () => {
  const log = fixture(); log.writeUInt16LE(16, 22);
  assert.throws(() => parse_squashfs(log), e => e.code === 'ORIX_SQUASHFS_BLOCK_LOG_MISMATCH');
  const table = fixture(); table.writeBigUInt64LE(300n, 64);
  assert.throws(() => parse_squashfs(table), e => e.code === 'ORIX_SQUASHFS_TABLE_RANGE');
});

test('SquashFS validates ID count and no_ids flag consistency', () => {
  const noIds = fixture(); noIds.writeUInt16LE(0, 26);
  assert.throws(() => parse_squashfs(noIds), e => e.code === 'ORIX_SQUASHFS_INVALID_ID_COUNT');
  const mismatch = fixture(); mismatch.writeUInt16LE(0x0408, 24);
  assert.throws(() => parse_squashfs(mismatch), e => e.code === 'ORIX_SQUASHFS_ID_FLAG_MISMATCH');
});

test('SquashFS reports unknown compression IDs and duplicate table offsets without overclaiming', () => {
  const unknown = fixture({ compression: 99 });
  const parsed = parse_squashfs(unknown);
  assert.equal(parsed.superblock.compression, 'unknown');
  assert.equal(parsed.superblock.compression_supported_by_metadata_parser, false);
  const duplicate = fixture(); duplicate.writeBigUInt64LE(128n, 72);
  assert.equal(parse_squashfs(duplicate).duplicate_table_offsets.length, 1);
  assert.equal(parsed.validation.metadata_tables_decompressed, false);
});

test('SquashFS enforces input ceiling and format dispatch', () => {
  assert.throws(() => parse_squashfs(fixture(), { max_input_bytes: 96 }), e => e.code === 'ORIX_SQUASHFS_INPUT_LIMIT');
  const result = analyze_known_format(fixture());
  assert.equal(result.detection.format, 'SquashFS');
  assert.equal(result.parser_status, 'parsed');
  assert.equal(result.parsed.analysis_scope, 'superblock-and-table-offsets-only');
});
