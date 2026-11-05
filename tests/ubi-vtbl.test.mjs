// JavaScript, tests/ubi-vtbl.test.mjs, Node.js 20+, UBI layout volume-table metadata.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_ubi } from '../src/formats/ubi.mjs';

const PEB_SIZE = 32768;
const DATA_OFFSET = 128;
const LAYOUT_ID = 0x7fffffff - 4096;

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let i = 0; i < 8; i += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return crc >>> 0;
}
function record({ reserved = 0, alignment = 0, dataPad = 0, type = 0, update = 0, name = '', flags = 0 } = {}) {
  const b = Buffer.alloc(172);
  b.writeUInt32BE(reserved, 0); b.writeUInt32BE(alignment, 4); b.writeUInt32BE(dataPad, 8);
  b[12] = type; b[13] = update;
  b.writeUInt16BE(Buffer.byteLength(name), 14);
  Buffer.from(name, 'utf8').copy(b, 16);
  b[144] = flags;
  b.writeUInt32BE(crc32(b.subarray(0, 168)), 168);
  return b;
}
function table({ secondName = 'data' } = {}) {
  const records = [];
  records.push(record({ reserved: 10, alignment: 1, type: 1, name: 'root', flags: 1 }));
  records.push(record({ reserved: 5, alignment: 1, type: 2, name: secondName, flags: 2 }));
  for (let i = 2; i < 128; i += 1) records.push(record());
  return Buffer.concat(records);
}
function layoutPeb(lnum, tableBytes, { compat = 5 } = {}) {
  const b = Buffer.alloc(PEB_SIZE, 0xff);
  b.write('UBI#', 0, 'ascii'); b[4] = 1;
  b.writeBigUInt64BE(5n + BigInt(lnum), 8);
  b.writeUInt32BE(64, 16); b.writeUInt32BE(DATA_OFFSET, 20); b.writeUInt32BE(0x12345678, 24);
  b.writeUInt32BE(crc32(b.subarray(0, 60)), 60);
  b.write('UBI!', 64, 'ascii'); b[68] = 1; b[69] = 1; b[70] = 0; b[71] = compat;
  b.writeUInt32BE(LAYOUT_ID, 72); b.writeUInt32BE(lnum, 76);
  b.writeUInt32BE(0, 84); b.writeUInt32BE(2, 88); b.writeUInt32BE(0, 92); b.writeUInt32BE(0, 96);
  b.writeBigUInt64BE(20n + BigInt(lnum), 104);
  b.writeUInt32BE(crc32(b.subarray(64, 124)), 124);
  tableBytes.copy(b, DATA_OFFSET);
  return b;
}
function layoutImage(options = {}) {
  const t = table(options);
  return Buffer.concat([layoutPeb(0, t), layoutPeb(1, t)]);
}

test('UBI decodes duplicate layout volume-table copies and active records', () => {
  const parsed = parse_ubi(layoutImage(), { peb_size: PEB_SIZE, decode_volume_table: true });
  assert.equal(parsed.volume_table.layout_volume_id, LAYOUT_ID);
  assert.equal(parsed.volume_table.copies_found, 2);
  assert.equal(parsed.volume_table.copies_identical, true);
  assert.equal(parsed.volume_table.redundancy_complete, true);
  assert.equal(parsed.volume_table.record_size, 172);
  assert.equal(parsed.volume_table.record_count, 128);
  assert.equal(parsed.volume_table.active_records, 2);
  assert.equal(parsed.volume_table.empty_records, 126);
  assert.equal(parsed.volume_table.records[0].name, 'root');
  assert.equal(parsed.volume_table.records[1].volume_type, 'static');
  assert.equal(parsed.validation.volume_table_decoded, true);
});

test('UBI volume-table decoding requires explicit PEB geometry and layout PEBs', () => {
  assert.throws(() => parse_ubi(layoutImage(), { decode_volume_table: true }), TypeError);
  assert.throws(() => parse_ubi(image({ pebSize: PEB_SIZE }), { peb_size: PEB_SIZE, decode_volume_table: true }), e => e.code === 'ORIX_UBI_LAYOUT_VOLUME_MISSING');
});

test('UBI volume-table decoder rejects bad record CRC and invalid layout-volume VID metadata', () => {
  const badRecord = layoutImage();
  badRecord[DATA_OFFSET + 16] ^= 1;
  assert.throws(() => parse_ubi(badRecord, { peb_size: PEB_SIZE, decode_volume_table: true }), e => e.code === 'ORIX_UBI_VTBL_RECORD_CRC');
  const badCompat = Buffer.concat([layoutPeb(0, table(), { compat: 0 }), layoutPeb(1, table(), { compat: 0 })]);
  assert.throws(() => parse_ubi(badCompat, { peb_size: PEB_SIZE, decode_volume_table: true }), e => e.code === 'ORIX_UBI_INVALID_LAYOUT_VOLUME');
});

test('UBI reports inconsistent copies without silently choosing a second copy', () => {
  const first = table();
  const second = table({ secondName: 'boot' });
  const image = Buffer.concat([layoutPeb(0, first), layoutPeb(1, second)]);
  const parsed = parse_ubi(image, { peb_size: PEB_SIZE, decode_volume_table: true });
  assert.equal(parsed.volume_table.copies_identical, false);
  assert.equal(parsed.volume_table.records[1].name, 'data');
});

test('UBI rejects ambiguous physical candidates for the same layout LEB', () => {
  const t = table();
  const image = Buffer.concat([layoutPeb(0, t), layoutPeb(0, t)]);
  assert.throws(() => parse_ubi(image, { peb_size: PEB_SIZE, decode_volume_table: true }), e => e.code === 'ORIX_UBI_LAYOUT_VOLUME_AMBIGUOUS');
});
