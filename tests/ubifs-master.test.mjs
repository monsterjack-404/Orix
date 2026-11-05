// JavaScript, tests/ubifs-master.test.mjs, Node.js 20+, UBIFS master-node validation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_ubifs_master } from '../src/formats/ubifs-master.mjs';
import { analyze_known_format } from '../src/formats/index.mjs';

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let i = 0; i < 8; i += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return crc >>> 0;
}
function geometry() {
  return { leb_size: 126976, leb_count: 64, max_leb_count: 128, log_lebs: 2, lpt_lebs: 2, orphan_lebs: 1, min_io_size: 512 };
}
function master() {
  const b = Buffer.alloc(512);
  b.writeUInt32LE(0x06101831, 0);
  b.writeBigUInt64LE(100n, 8);
  b.writeUInt32LE(512, 16);
  b[20] = 7; b[21] = 0;
  b.writeBigUInt64LE(99n, 24); // highest inode
  b.writeBigUInt64LE(50n, 32); // commit number
  b.writeUInt32LE(2, 40); // no_orphans
  b.writeUInt32LE(3, 44); // log LEB
  b.writeUInt32LE(8, 48); // root LEB
  b.writeUInt32LE(0, 52); // root offset
  b.writeUInt32LE(32, 56); // root index length
  b.writeUInt32LE(9, 60); // GC LEB
  b.writeUInt32LE(10, 64); // index head LEB
  b.writeUInt32LE(512, 68); // index head offset
  b.writeBigUInt64LE(1024n, 72); // index size
  b.writeBigUInt64LE(2048n, 80); // total free
  b.writeBigUInt64LE(1024n, 88); // total dirty
  b.writeBigUInt64LE(1024n, 96); // total used
  b.writeBigUInt64LE(512n, 104); // total dead
  b.writeBigUInt64LE(256n, 112); // total dark
  b.writeUInt32LE(5, 120); // LPT root LEB
  b.writeUInt32LE(0, 124);
  b.writeUInt32LE(5, 128); // LPT head LEB
  b.writeUInt32LE(512, 132);
  b.writeUInt32LE(5, 136); // LPT table LEB
  b.writeUInt32LE(1024, 140);
  b.writeUInt32LE(0, 144); // LPT save LEB, unused
  b.writeUInt32LE(0, 148);
  b.writeUInt32LE(8, 152); // last LPT scan LEB
  b.writeUInt32LE(2, 156); // empty LEBs
  b.writeUInt32LE(3, 160); // index LEBs
  b.writeUInt32LE(64, 164); // master LEB count
  b.writeUInt32LE(crc32(b.subarray(8)), 4);
  return b;
}

test('UBIFS master parser decodes master metadata and CRC', () => {
  const parsed = parse_ubifs_master(master(), { superblock: geometry() });
  assert.equal(parsed.format, 'UBIFS');
  assert.equal(parsed.variant, 'master-node');
  assert.equal(parsed.node.type_name, 'master');
  assert.equal(parsed.node.length, 512);
  assert.equal(parsed.node.crc_valid, true);
  assert.equal(parsed.master.highest_inode_number, '99');
  assert.equal(parsed.master.commit_number, '50');
  assert.equal(parsed.master.root_lnum, 8);
  assert.equal(parsed.master.total_free, 2048);
  assert.equal(parsed.master.flags.enabled.includes('no_orphans'), true);
  assert.equal(parsed.validation.superblock_geometry_validated, true);
});

test('UBIFS master parser accepts an aligned node offset and reports geometry scope', () => {
  const b = Buffer.concat([Buffer.alloc(8), master()]);
  const parsed = parse_ubifs_master(b, { offset: 8 });
  assert.equal(parsed.node.offset, 8);
  assert.equal(parsed.validation.superblock_geometry_validated, false);
});

test('UBIFS master parser rejects bad magic, type, length, padding and CRC', () => {
  assert.throws(() => parse_ubifs_master(Buffer.alloc(511)), e => e.code === 'ORIX_UBIFS_MASTER_TRUNCATED');
  const magic = master(); magic[0] = 0;
  assert.throws(() => parse_ubifs_master(magic), e => e.code === 'ORIX_UBIFS_MASTER_BAD_MAGIC');
  const type = master(); type[20] = 6;
  assert.throws(() => parse_ubifs_master(type), e => e.code === 'ORIX_UBIFS_MASTER_WRONG_TYPE');
  const length = master(); length.writeUInt32LE(511, 16);
  assert.throws(() => parse_ubifs_master(length), e => e.code === 'ORIX_UBIFS_MASTER_INVALID_LENGTH');
  const padding = master(); padding[400] = 1; padding.writeUInt32LE(crc32(padding.subarray(8)), 4);
  assert.throws(() => parse_ubifs_master(padding), e => e.code === 'ORIX_UBIFS_MASTER_PADDING');
  const crc = master(); crc[80] ^= 1;
  assert.throws(() => parse_ubifs_master(crc), e => e.code === 'ORIX_UBIFS_MASTER_CRC_MISMATCH');
});

test('UBIFS master parser validates commit order, offsets and geometry', () => {
  const badLeb = master(); badLeb.writeUInt32LE(99, 48); badLeb.writeUInt32LE(crc32(badLeb.subarray(8)), 4);
  assert.throws(() => parse_ubifs_master(badLeb), e => e.code === 'ORIX_UBIFS_MASTER_LEB_BOUNDS');
  const commit = master(); commit.writeBigUInt64LE(100n, 32); commit.writeUInt32LE(crc32(commit.subarray(8)), 4);
  assert.throws(() => parse_ubifs_master(commit), e => e.code === 'ORIX_UBIFS_MASTER_COMMIT_SEQUENCE');
  const root = master(); root.writeUInt32LE(1, 52); root.writeUInt32LE(crc32(root.subarray(8)), 4);
  assert.throws(() => parse_ubifs_master(root, { superblock: geometry() }), e => e.code === 'ORIX_UBIFS_MASTER_LAYOUT');
  const outside = master(); outside.writeUInt32LE(70, 48); outside.writeUInt32LE(crc32(outside.subarray(8)), 4);
  assert.throws(() => parse_ubifs_master(outside, { superblock: geometry() }), e => e.code === 'ORIX_UBIFS_MASTER_LEB_RANGE');
});

test('UBIFS dispatch selects the master parser by node type', () => {
  const result = analyze_known_format(master());
  assert.equal(result.detection.format, 'UBIFS');
  assert.equal(result.parser_status, 'parsed');
  assert.equal(result.parsed.variant, 'master-node');
});
