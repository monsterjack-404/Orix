import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_dex } from '../src/formats/dex.mjs';

function align4(value) {
  return (value + 3) & ~3;
}

function write_uleb(buffer, offset, value) {
  let current = value >>> 0;
  do {
    let byte = current & 0x7f;
    current >>>= 7;
    if (current !== 0) byte |= 0x80;
    buffer[offset++] = byte;
  } while (current !== 0);
  return offset;
}

function adler32(buffer, start = 0) {
  let a = 1;
  let b = 0;
  for (let index = start; index < buffer.length; index += 1) {
    a = (a + buffer[index]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

function finalize_integrity(buffer) {
  const { createHash } = require_crypto();
  createHash('sha1').update(buffer.subarray(32)).digest().copy(buffer, 12);
  buffer.writeUInt32LE(adler32(buffer, 12), 8);
  return buffer;
}

function require_crypto() {
  // Static import is intentionally avoided in fixtures; Node's crypto module is deterministic.
  return crypto_module;
}
import * as crypto_module from 'node:crypto';

function create_semantic_dex() {
  const strings = ['Lcom/example/App;', 'Ljava/lang/Object;', 'run', 'V', 'value', 'I'];
  const string_ids_off = 112;
  const type_ids_off = string_ids_off + strings.length * 4;
  const proto_ids_off = type_ids_off + 4 * 4;
  const field_ids_off = proto_ids_off + 12;
  const method_ids_off = field_ids_off + 8;
  const class_defs_off = method_ids_off + 8;
  const data_off = class_defs_off + 32;

  const encoded_strings = strings.map(value => {
    const bytes = Buffer.from(value, 'ascii');
    return Buffer.concat([Buffer.from([bytes.length]), bytes, Buffer.from([0])]);
  });
  const string_offsets = [];
  let cursor = data_off;
  for (const value of encoded_strings) {
    string_offsets.push(cursor);
    cursor += value.length;
  }
  const class_data_off = align4(cursor);
  const code_off = align4(class_data_off + 10);
  const map_off = align4(code_off + 18);
  const map_items = [
    [0x0000, 1, 0],
    [0x0001, strings.length, string_ids_off],
    [0x0002, 4, type_ids_off],
    [0x0003, 1, proto_ids_off],
    [0x0004, 1, field_ids_off],
    [0x0005, 1, method_ids_off],
    [0x0006, 1, class_defs_off],
    [0x2002, strings.length, data_off],
    [0x2000, 1, class_data_off],
    [0x2001, 1, code_off],
    [0x1000, 1, map_off],
  ];
  const file_size = map_off + 4 + map_items.length * 12;
  const buffer = Buffer.alloc(file_size);
  buffer.write('dex\n035\0', 0, 'ascii');
  buffer.writeUInt32LE(file_size, 32);
  buffer.writeUInt32LE(112, 36);
  buffer.writeUInt32LE(0x12345678, 40);
  buffer.writeUInt32LE(map_off, 52);
  buffer.writeUInt32LE(strings.length, 56);
  buffer.writeUInt32LE(string_ids_off, 60);
  buffer.writeUInt32LE(4, 64);
  buffer.writeUInt32LE(type_ids_off, 68);
  buffer.writeUInt32LE(1, 72);
  buffer.writeUInt32LE(proto_ids_off, 76);
  buffer.writeUInt32LE(1, 80);
  buffer.writeUInt32LE(field_ids_off, 84);
  buffer.writeUInt32LE(1, 88);
  buffer.writeUInt32LE(method_ids_off, 92);
  buffer.writeUInt32LE(1, 96);
  buffer.writeUInt32LE(class_defs_off, 100);
  buffer.writeUInt32LE(file_size - data_off, 104);
  buffer.writeUInt32LE(data_off, 108);

  string_offsets.forEach((offset, index) => {
    buffer.writeUInt32LE(offset, string_ids_off + index * 4);
    encoded_strings[index].copy(buffer, offset);
  });
  [0, 1, 3, 5].forEach((string_index, index) => {
    buffer.writeUInt32LE(string_index, type_ids_off + index * 4);
  });
  buffer.writeUInt32LE(3, proto_ids_off);
  buffer.writeUInt32LE(2, proto_ids_off + 4);
  buffer.writeUInt32LE(0, proto_ids_off + 8);
  buffer.writeUInt16LE(0, field_ids_off);
  buffer.writeUInt16LE(3, field_ids_off + 2);
  buffer.writeUInt32LE(4, field_ids_off + 4);
  buffer.writeUInt16LE(0, method_ids_off);
  buffer.writeUInt16LE(0, method_ids_off + 2);
  buffer.writeUInt32LE(2, method_ids_off + 4);

  buffer.writeUInt32LE(0, class_defs_off);
  buffer.writeUInt32LE(1, class_defs_off + 4);
  buffer.writeUInt32LE(1, class_defs_off + 8);
  buffer.writeUInt32LE(0, class_defs_off + 12);
  buffer.writeUInt32LE(0xffffffff, class_defs_off + 16);
  buffer.writeUInt32LE(0, class_defs_off + 20);
  buffer.writeUInt32LE(class_data_off, class_defs_off + 24);
  buffer.writeUInt32LE(0, class_defs_off + 28);

  let item = class_data_off;
  for (const value of [1, 0, 1, 0, 0, 2, 0, 1]) item = write_uleb(buffer, item, value);
  item = write_uleb(buffer, item, code_off);
  assert.equal(item, class_data_off + 10);

  buffer.writeUInt16LE(1, code_off);
  buffer.writeUInt16LE(1, code_off + 2);
  buffer.writeUInt16LE(0, code_off + 4);
  buffer.writeUInt16LE(0, code_off + 6);
  buffer.writeUInt32LE(0, code_off + 8);
  buffer.writeUInt32LE(1, code_off + 12);
  buffer.writeUInt16LE(0x000e, code_off + 16); // return-void; deliberately not decoded by ORIX.

  buffer.writeUInt32LE(map_items.length, map_off);
  map_items.forEach(([type, size, offset], index) => {
    const position = map_off + 4 + index * 12;
    buffer.writeUInt16LE(type, position);
    buffer.writeUInt16LE(0, position + 2);
    buffer.writeUInt32LE(size, position + 4);
    buffer.writeUInt32LE(offset, position + 8);
  });
  return finalize_integrity(buffer);
}

test('DEX semantic parser inventories prototypes, fields, methods, class data and bounded code headers', () => {
  const parsed = parse_dex(create_semantic_dex());
  assert.equal(parsed.proto_ids[0].signature, '()V');
  assert.equal(parsed.field_ids[0].name, 'value');
  assert.equal(parsed.field_ids[0].type_descriptor, 'I');
  assert.equal(parsed.method_ids[0].name, 'run');
  assert.equal(parsed.method_ids[0].prototype, '()V');
  assert.equal(parsed.class_data_summary.classes_with_data, 1);
  assert.equal(parsed.class_data_summary.static_fields, 1);
  assert.equal(parsed.class_data_summary.direct_methods, 1);
  assert.equal(parsed.class_data[0].static_fields[0].access_flags, 2);
  assert.equal(parsed.class_data[0].direct_methods[0].code.instruction_units, 1);
  assert.equal(parsed.class_data[0].direct_methods[0].code.instructions_decoded, false);
  assert.equal(parsed.integrity.adler32_verified, true);
  assert.equal(parsed.integrity.signature_sha1_verified, true);
});

test('DEX semantic parser rejects an encoded method index outside method_ids', () => {
  const fixture = create_semantic_dex();
  const class_data_off = fixture.readUInt32LE(180 + 24);
  fixture[class_data_off + 6] = 1; // method_idx_diff now resolves to method_id #1, which does not exist.
  assert.throws(() => parse_dex(fixture), error => error.code === 'ORIX_DEX_CLASS_DATA_METHOD_INDEX');
});

test('DEX semantic parser rejects method records owned by another class', () => {
  const fixture = create_semantic_dex();
  fixture.writeUInt16LE(1, 172); // method_id.class_idx points to java.lang.Object instead of this class.
  assert.throws(() => parse_dex(fixture), error => error.code === 'ORIX_DEX_CLASS_DATA_METHOD_INDEX');
});

test('DEX semantic parser rejects out-of-range code_item offsets', () => {
  const fixture = create_semantic_dex();
  const class_data_off = fixture.readUInt32LE(180 + 24);
  fixture[class_data_off + 9] = 0x7f; // Make the second ULEB byte point beyond the DEX data section.
  assert.throws(() => parse_dex(fixture), error => error.code === 'ORIX_DEX_CODE_ITEM_RANGE');
});

test('DEX semantic parser enforces a total instruction-unit budget', () => {
  const fixture = create_semantic_dex();
  const class_data_off = fixture.readUInt32LE(180 + 24);
  const code_off = fixture.readUInt32LE(class_data_off + 7) ?? 0;
  // The fixture's concrete code_item starts 12 bytes after class_data_off.
  fixture.writeUInt32LE(2, class_data_off + 12 + 12);
  assert.throws(() => parse_dex(fixture, { max_instruction_units: 1 }), error => error.code === 'ORIX_DEX_INSTRUCTION_BUDGET');
});

test('DEX checksum and SHA-1 fields are independently verified without claiming publisher authenticity', () => {
  const fixture = create_semantic_dex();
  fixture[12] ^= 1;
  fixture.writeUInt32LE(adler32(fixture, 12), 8);
  const parsed = parse_dex(fixture);
  assert.equal(parsed.integrity.adler32_verified, true);
  assert.equal(parsed.integrity.signature_sha1_verified, false);
});
