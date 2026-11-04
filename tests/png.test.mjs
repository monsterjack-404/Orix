// JavaScript, tests/png.test.mjs, Node.js 20+, PNG parser regression tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_png } from '../src/formats/png.mjs';
import { analyze_known_format, list_format_capabilities } from '../src/formats/index.mjs';

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc & 1) ? (0xedb88320 ^ (crc >>> 1)) : (crc >>> 1);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data = Buffer.alloc(0)) {
  const type_bytes = Buffer.from(type, 'ascii');
  const body = Buffer.concat([type_bytes, data]);
  const output = Buffer.alloc(12 + data.length);
  output.writeUInt32BE(data.length, 0);
  type_bytes.copy(output, 4);
  data.copy(output, 8);
  output.writeUInt32BE(crc32(body), 8 + data.length);
  return output;
}

function header({ width = 1, height = 1, bit_depth = 8, color_type = 6, interlace = 0 } = {}) {
  const value = Buffer.alloc(13);
  value.writeUInt32BE(width, 0);
  value.writeUInt32BE(height, 4);
  value[8] = bit_depth;
  value[9] = color_type;
  value[10] = 0;
  value[11] = 0;
  value[12] = interlace;
  return value;
}

function png(chunks) {
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), ...chunks]);
}

const IDAT = Buffer.from([0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]);

test('PNG parser is available through the documented package subpath', async () => {
  const public_api = await import('@orix/cli/formats/png');
  assert.equal(typeof public_api.parse_png, 'function');
});

test('PNG parser indexes image metadata, chunks and CRCs without decoding pixels', () => {
  const input = png([chunk('IHDR', header({ width: 640, height: 480, color_type: 6 })), chunk('IDAT', IDAT), chunk('IEND')]);
  const result = parse_png(input);
  assert.equal(result.header.width, 640);
  assert.equal(result.header.height, 480);
  assert.equal(result.header.color_type_name, 'truecolor-with-alpha');
  assert.equal(result.summary.chunk_count, 3);
  assert.equal(result.summary.idat_chunk_count, 1);
  assert.equal(result.summary.idat_compressed_bytes, IDAT.length);
  assert.equal(result.summary.crc_validation_complete, true);
  assert.ok(result.chunks.every(item => item.crc_valid === true));
  assert.equal(result.coverage.image_data_inflated, false);
  assert.equal(analyze_known_format(input).parser_status, 'parsed');
  assert.equal(list_format_capabilities().find(item => item.format === 'PNG').parser_status, 'available');
});

test('PNG parser accepts valid indexed-color palette and transparency ordering', () => {
  const input = png([
    chunk('IHDR', header({ bit_depth: 2, color_type: 3 })),
    chunk('PLTE', Buffer.from([255, 0, 0, 0, 255, 0, 0, 0, 255])),
    chunk('tRNS', Buffer.from([255, 128])),
    chunk('IDAT', IDAT),
    chunk('IEND'),
  ]);
  const result = parse_png(input);
  assert.equal(result.summary.palette_entries, 3);
  assert.equal(result.chunks.find(item => item.type === 'PLTE').length, 9);
});

test('PNG parser rejects CRC mismatches and malformed chunk boundaries', () => {
  const valid = png([chunk('IHDR', header()), chunk('IDAT', IDAT), chunk('IEND')]);
  const bad_crc = Buffer.from(valid);
  bad_crc[bad_crc.length - 1] ^= 0x01;
  assert.throws(() => parse_png(bad_crc), error => error.code === 'ORIX_PNG_CRC_MISMATCH');
  assert.throws(() => parse_png(valid.subarray(0, valid.length - 4)), error => error.code === 'ORIX_PNG_TRUNCATED_CHUNK');
});

test('PNG parser validates header combinations, palette requirements and ordering', () => {
  const invalid_depth = header({ bit_depth: 3, color_type: 2 });
  assert.throws(() => parse_png(png([chunk('IHDR', invalid_depth), chunk('IDAT', IDAT), chunk('IEND')])),
    error => error.code === 'ORIX_PNG_INVALID_BIT_DEPTH');
  assert.throws(() => parse_png(png([chunk('IHDR', header({ color_type: 3, bit_depth: 1 })), chunk('IDAT', IDAT), chunk('IEND')])),
    error => error.code === 'ORIX_PNG_MISSING_PLTE');
  assert.throws(() => parse_png(png([
    chunk('IHDR', header()), chunk('IDAT', IDAT), chunk('tEXt', Buffer.from([0x6b, 0, 0x76])),
    chunk('IDAT', IDAT), chunk('IEND'),
  ])), error => error.code === 'ORIX_PNG_NONCONTIGUOUS_IDAT');
});

test('PNG parser enforces chunk limits and reports skipped CRC checks honestly', () => {
  const input = png([chunk('IHDR', header()), chunk('IDAT', IDAT), chunk('IEND')]);
  assert.throws(() => parse_png(input, { max_chunks: 2 }), error => error.code === 'ORIX_PNG_CHUNK_LIMIT');
  const result = parse_png(input, { max_crc_bytes: 0 });
  assert.equal(result.summary.crc_checked_chunks, 0);
  assert.equal(result.summary.crc_skipped_chunks, 3);
  assert.equal(result.summary.crc_validation_complete, false);
  assert.ok(result.notes.some(value => value.includes('CRC verification was skipped')));
});

test('PNG parser requires IEND and rejects trailing bytes and invalid reserved chunk bits', () => {
  assert.throws(() => parse_png(png([chunk('IHDR', header()), chunk('IDAT', IDAT)])),
    error => error.code === 'ORIX_PNG_MISSING_IEND');
  const valid = png([chunk('IHDR', header()), chunk('IDAT', IDAT), chunk('IEND')]);
  assert.throws(() => parse_png(Buffer.concat([valid, Buffer.from([0])])), error => error.code === 'ORIX_PNG_TRAILING_DATA');
  assert.throws(() => parse_png(png([chunk('IHdR', header()), chunk('IDAT', IDAT), chunk('IEND')])),
    error => error.code === 'ORIX_PNG_RESERVED_CHUNK_BIT');
});
