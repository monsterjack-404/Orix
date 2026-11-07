import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_dex } from '../src/formats/dex.mjs';

function encode_uleb(value) {
  const bytes = [];
  do {
    let byte = value & 0x7f;
    value >>>= 7;
    if (value !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (value !== 0);
  return Buffer.from(bytes);
}

function create_dex_with_string(encoded, utf16_length) {
  const string_data = Buffer.concat([encode_uleb(utf16_length), encoded, Buffer.from([0])]);
  const data_offset = 120; // DEX data_off must be four-byte aligned.
  const map_offset = (data_offset + string_data.length + 3) & ~3;
  const map_size = 4 + 4 * 12;
  const buffer = Buffer.alloc(map_offset + map_size);
  buffer.write('dex\n035\0', 0, 'ascii');
  buffer.writeUInt32LE(buffer.length, 32);
  buffer.writeUInt32LE(112, 36);
  buffer.writeUInt32LE(0x12345678, 40);
  buffer.writeUInt32LE(map_offset, 52);
  buffer.writeUInt32LE(1, 56);
  buffer.writeUInt32LE(112, 60);
  buffer.writeUInt32LE(buffer.length - data_offset, 104);
  buffer.writeUInt32LE(data_offset, 108);
  buffer.writeUInt32LE(data_offset, 112);
  string_data.copy(buffer, data_offset);
  buffer.writeUInt32LE(4, map_offset);
  const items = [
    [0x0000, 1, 0],
    [0x0001, 1, 112],
    [0x2002, 1, data_offset],
    [0x1000, 1, map_offset],
  ];
  items.forEach(([type, size, offset], index) => {
    const p = map_offset + 4 + index * 12;
    buffer.writeUInt16LE(type, p);
    buffer.writeUInt32LE(size, p + 4);
    buffer.writeUInt32LE(offset, p + 8);
  });
  return buffer;
}

test('DEX MUTF-8 decoder returns regular ASCII strings', () => {
  const parsed = parse_dex(create_dex_with_string(Buffer.from('Lx;', 'ascii'), 3));
  assert.equal(parsed.strings[0].value, 'Lx;');
});

test('DEX MUTF-8 decoder supports encoded NUL and supplementary Unicode characters', () => {
  const nul = parse_dex(create_dex_with_string(Buffer.from([0xc0, 0x80]), 1));
  assert.equal(nul.strings[0].value, '\0');

  // U+1F600 is represented as two UTF-16 surrogate code units in DEX MUTF-8.
  const emoji = parse_dex(create_dex_with_string(
    Buffer.from([0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]),
    2,
  ));
  assert.equal(emoji.strings[0].value, '😀');
});

test('DEX MUTF-8 decoder rejects mismatched UTF-16 lengths', () => {
  assert.throws(
    () => parse_dex(create_dex_with_string(Buffer.from('abc', 'ascii'), 2)),
    error => error.code === 'ORIX_DEX_STRING_LENGTH',
  );
});

test('DEX MUTF-8 decoder rejects truncated, overlong and four-byte UTF-8 sequences', () => {
  const malformed = [
    [Buffer.from([0xc2]), 1],
    [Buffer.from([0xc1, 0x81]), 1],
    [Buffer.from([0xe0, 0x80, 0x80]), 1],
    [Buffer.from([0xf0, 0x9f, 0x98, 0x80]), 2],
  ];
  for (const [encoded, utf16_length] of malformed) {
    assert.throws(
      () => parse_dex(create_dex_with_string(encoded, utf16_length)),
      error => error.code === 'ORIX_DEX_STRING_ENCODING',
    );
  }
});
