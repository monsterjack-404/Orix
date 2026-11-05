// JavaScript, tests/cramfs.test.mjs, Node.js 20+, cramfs superblock validation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_cramfs } from '../src/formats/cramfs.mjs';
import { analyze_known_format } from '../src/formats/index.mjs';

function fixture({ little = true, size = 4096, flags = 0x0002, rootMode = 0x41ed, rootOffset = 0 } = {}) {
  const b = Buffer.alloc(size);
  const w16 = (o, v) => little ? b.writeUInt16LE(v, o) : b.writeUInt16BE(v, o);
  const w32 = (o, v) => little ? b.writeUInt32LE(v, o) : b.writeUInt32BE(v, o);
  w32(0, 0x28cd3d45);
  w32(4, size); w32(8, flags); w32(12, 0);
  b.write('Compressed ROMFS', 16, 'ascii');
  w32(32, 0x12345678); w32(36, 1); w32(40, 1); w32(44, 1);
  b.write('test-root', 48, 'ascii');
  w16(64, rootMode); w16(66, 0);
  w32(68, (0 << 24) | 0);
  w32(72, (rootOffset >>> 2) << 6);
  return b;
}

test('cramfs parses little-endian superblock and root inode', () => {
  const parsed = parse_cramfs(fixture());
  assert.equal(parsed.format, 'cramfs');
  assert.equal(parsed.byte_order, 'little-endian');
  assert.equal(parsed.superblock.signature, 'Compressed ROMFS');
  assert.equal(parsed.root_inode.file_type, 'directory');
  assert.equal(parsed.root_inode.offset_in_declared_filesystem, true);
});

test('cramfs parses big-endian image', () => {
  const parsed = parse_cramfs(fixture({ little: false }));
  assert.equal(parsed.byte_order, 'big-endian');
  assert.equal(parsed.superblock.block_count, 1);
});

test('cramfs rejects short input, invalid magic and bad signature', () => {
  assert.throws(() => parse_cramfs(Buffer.alloc(75)), e => e.code === 'ORIX_CRAMFS_TRUNCATED_SUPERBLOCK');
  assert.throws(() => parse_cramfs(Buffer.alloc(76)), e => e.code === 'ORIX_CRAMFS_BAD_MAGIC');
  const bad = fixture(); bad.write('Not a cramfs file', 16, 'ascii');
  assert.throws(() => parse_cramfs(bad), e => e.code === 'ORIX_CRAMFS_BAD_SIGNATURE');
});

test('cramfs rejects declared sizes outside the supplied image', () => {
  const bad = fixture(); bad.writeUInt32LE(5000, 4);
  assert.throws(() => parse_cramfs(bad), e => e.code === 'ORIX_CRAMFS_SIZE_RANGE');
});

test('cramfs rejects non-directory root inode and out-of-range root offset', () => {
  assert.throws(() => parse_cramfs(fixture({ rootMode: 0x81a4 })), e => e.code === 'ORIX_CRAMFS_ROOT_NOT_DIRECTORY');
  assert.throws(() => parse_cramfs(fixture({ rootOffset: 8192 })), e => e.code === 'ORIX_CRAMFS_ROOT_OFFSET_RANGE');
});

test('cramfs reports flags and unknown bits without overclaiming', () => {
  const parsed = parse_cramfs(fixture({ flags: 0x80000002 }));
  assert.deepEqual(parsed.superblock.flags.enabled, ['sorted_directories']);
  assert.equal(parsed.superblock.flags.unknown_bits, 0x80000000);
  assert.equal(parsed.validation.compressed_blocks_decoded, false);
});

test('cramfs enforces input ceiling and is dispatched by format registry', () => {
  assert.throws(() => parse_cramfs(fixture(), { max_input_bytes: 76 }), e => e.code === 'ORIX_CRAMFS_INPUT_LIMIT');
  const result = analyze_known_format(fixture());
  assert.equal(result.detection.format, 'cramfs');
  assert.equal(result.parser_status, 'parsed');
  assert.equal(result.parsed.analysis_scope, 'superblock-and-root-inode-only');
});
