// JavaScript, tests/ubifs.test.mjs, Node.js 20+, UBIFS superblock-node validation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_ubifs } from '../src/formats/ubifs.mjs';
import { analyze_known_format } from '../src/formats/index.mjs';

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return crc >>> 0;
}

function image({ formatVersion = 5 } = {}) {
  const b = Buffer.alloc(4096);
  b.writeUInt32LE(0x06101831, 0);
  b.writeBigUInt64LE(12n, 8);
  b.writeUInt32LE(4096, 16);
  b[20] = 6;
  b[21] = 0;
  // Superblock body begins after the 24-byte common header.
  b.writeUInt8(0, 26); // R5 key hash
  b.writeUInt8(0, 27); // simple key format
  b.writeUInt32LE(0, 28); // flags
  b.writeUInt32LE(512, 32); // minimum I/O size
  b.writeUInt32LE(126976, 36); // LEB size
  b.writeUInt32LE(64, 40); // LEB count
  b.writeUInt32LE(128, 44); // maximum LEB count
  b.writeBigUInt64LE(1024n * 1024n, 48); // max bud bytes
  b.writeUInt32LE(2, 56); // log LEBs
  b.writeUInt32LE(2, 60); // LPT LEBs
  b.writeUInt32LE(1, 64); // orphan LEBs
  b.writeUInt32LE(3, 68); // journal heads
  b.writeUInt32LE(8, 72); // fanout
  b.writeUInt32LE(0, 76); // lsave count
  b.writeUInt32LE(formatVersion, 80);
  b.writeUInt16LE(1, 84); // LZO
  b.writeUInt32LE(1000, 104); // time granularity
  Buffer.from('00112233445566778899aabbccddeeff', 'hex').copy(b, 108);
  b.writeUInt32LE(0, 124); // read-only compatibility version
  b.writeUInt16LE(0, 256); // hash algorithm
  b.writeUInt32LE(crc32(b.subarray(8)), 4);
  return b;
}

test('UBIFS parses a superblock node and validates its CRC', () => {
  const parsed = parse_ubifs(image());
  assert.equal(parsed.format, 'UBIFS');
  assert.equal(parsed.node.type_name, 'superblock');
  assert.equal(parsed.node.length, 4096);
  assert.equal(parsed.node.crc_valid, true);
  assert.equal(parsed.superblock.leb_size, 126976);
  assert.equal(parsed.superblock.default_compression, 'lzo');
  assert.equal(parsed.superblock.uuid, '00112233445566778899aabbccddeeff');
});

test('UBIFS accepts a node at an explicit aligned offset', () => {
  const node = image();
  const input = Buffer.concat([Buffer.alloc(16), node]);
  const parsed = parse_ubifs(input, { offset: 16 });
  assert.equal(parsed.node.offset, 16);
});

test('UBIFS rejects short input, bad magic, wrong node type and corrupt CRC', () => {
  assert.throws(() => parse_ubifs(Buffer.alloc(23)), TypeError);
  assert.throws(() => parse_ubifs(Buffer.alloc(4096)), e => e.code === 'ORIX_UBIFS_BAD_MAGIC');
  const wrongType = image(); wrongType[20] = 7; wrongType.writeUInt32LE(crc32(wrongType.subarray(8)), 4);
  assert.throws(() => parse_ubifs(wrongType), e => e.code === 'ORIX_UBIFS_NOT_SUPERBLOCK');
  const badCrc = image(); badCrc[300] ^= 1;
  assert.throws(() => parse_ubifs(badCrc), e => e.code === 'ORIX_UBIFS_CRC_MISMATCH');
});

test('UBIFS rejects invalid node length, group type, and nonzero reserved padding', () => {
  const length = image(); length.writeUInt32LE(4095, 16);
  assert.throws(() => parse_ubifs(length), e => e.code === 'ORIX_UBIFS_INVALID_NODE_LENGTH');
  const group = image(); group[21] = 3;
  assert.throws(() => parse_ubifs(group), e => e.code === 'ORIX_UBIFS_INVALID_GROUP_TYPE');
  const padding = image(); padding[22] = 1;
  assert.throws(() => parse_ubifs(padding), e => e.code === 'ORIX_UBIFS_NONZERO_COMMON_PADDING');
});

test('UBIFS validates geometry, counts, versions and compression IDs', () => {
  const leb = image(); leb.writeUInt32LE(1024, 36); leb.writeUInt32LE(crc32(leb.subarray(8)), 4);
  assert.throws(() => parse_ubifs(leb), e => e.code === 'ORIX_UBIFS_INVALID_LEB_SIZE');
  const count = image(); count.writeUInt32LE(1, 40); count.writeUInt32LE(crc32(count.subarray(8)), 4);
  assert.throws(() => parse_ubifs(count), e => e.code === 'ORIX_UBIFS_INVALID_LEB_COUNT');
  const version = image({ formatVersion: 6 });
  assert.throws(() => parse_ubifs(version), e => e.code === 'ORIX_UBIFS_UNSUPPORTED_FORMAT_VERSION');
  const compression = image(); compression.writeUInt16LE(9, 84); compression.writeUInt32LE(crc32(compression.subarray(8)), 4);
  assert.throws(() => parse_ubifs(compression), e => e.code === 'ORIX_UBIFS_UNKNOWN_COMPRESSION');
});

test('UBIFS enforces input ceilings and bounded offsets', () => {
  assert.throws(() => parse_ubifs(image(), { max_input_bytes: 4096 - 1 }), TypeError);
  assert.throws(() => parse_ubifs(image(), { offset: 1 }), TypeError);
  assert.throws(() => parse_ubifs(image(), { offset: 4096 }), TypeError);
  const result = analyze_known_format(image());
  assert.equal(result.detection.format, 'UBIFS');
  assert.equal(result.parser_status, 'parsed');
});
