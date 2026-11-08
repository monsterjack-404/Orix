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

function create_semantic_dex({
  catch_handler_size_bytes = null,
  instructions = [0x000e],
  registers_size = 1,
  try_start_addr = 0,
  try_insn_count = instructions.length,
  handler_address = 0,
  catch_all_address = 0,
} = {}) {
  const strings = ['I', 'Lcom/example/App;', 'Ljava/lang/Object;', 'V', 'run', 'value'];
  const string_ids_off = 112;
  const type_ids_off = string_ids_off + strings.length * 4;
  const proto_ids_off = type_ids_off + 4 * 4;
  const field_ids_off = proto_ids_off + 12;
  const method_ids_off = field_ids_off + 8;
  const class_defs_off = method_ids_off + 8;
  const method_handles_off = class_defs_off + 32;
  const data_off = method_handles_off + 8;

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
  const has_catch_handlers = Array.isArray(catch_handler_size_bytes);
  const handler_bytes = has_catch_handlers
    ? Buffer.from([1, ...catch_handler_size_bytes, 0, handler_address, catch_all_address, 0])
    : Buffer.alloc(0);
  const instruction_bytes = instructions.length * 2;
  const try_padding_bytes = has_catch_handlers && (instructions.length & 1) !== 0 ? 2 : 0;
  const code_item_size = 16 + instruction_bytes + try_padding_bytes +
    (has_catch_handlers ? 8 + handler_bytes.length : 0);
  const map_off = align4(code_off + code_item_size);
  const map_items = [
    [0x0000, 1, 0],
    [0x0001, strings.length, string_ids_off],
    [0x0002, 4, type_ids_off],
    [0x0003, 1, proto_ids_off],
    [0x0004, 1, field_ids_off],
    [0x0005, 1, method_ids_off],
    [0x0006, 1, class_defs_off],
    [0x0008, 1, method_handles_off],
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
  [0, 1, 2, 3].forEach((string_index, index) => {
    buffer.writeUInt32LE(string_index, type_ids_off + index * 4);
  });
  buffer.writeUInt32LE(3, proto_ids_off);
  buffer.writeUInt32LE(3, proto_ids_off + 4);
  buffer.writeUInt32LE(0, proto_ids_off + 8);
  buffer.writeUInt16LE(1, field_ids_off);
  buffer.writeUInt16LE(0, field_ids_off + 2);
  buffer.writeUInt32LE(5, field_ids_off + 4);
  buffer.writeUInt16LE(1, method_ids_off);
  buffer.writeUInt16LE(0, method_ids_off + 2);
  buffer.writeUInt32LE(4, method_ids_off + 4);

  buffer.writeUInt32LE(1, class_defs_off);
  buffer.writeUInt32LE(1, class_defs_off + 4);
  buffer.writeUInt32LE(2, class_defs_off + 8);
  buffer.writeUInt32LE(0, class_defs_off + 12);
  buffer.writeUInt32LE(0xffffffff, class_defs_off + 16);
  buffer.writeUInt32LE(0, class_defs_off + 20);
  buffer.writeUInt32LE(class_data_off, class_defs_off + 24);
  buffer.writeUInt32LE(0, class_defs_off + 28);

  // DEX 038+ method_handle_item: static-put targeting field_id_item #0.
  buffer.writeUInt16LE(0, method_handles_off);
  buffer.writeUInt16LE(0, method_handles_off + 2);
  buffer.writeUInt16LE(0, method_handles_off + 4);
  buffer.writeUInt16LE(0, method_handles_off + 6);

  let item = class_data_off;
  for (const value of [1, 0, 1, 0, 0, 2, 0, 1]) item = write_uleb(buffer, item, value);
  item = write_uleb(buffer, item, code_off);
  assert.equal(item, class_data_off + 10);

  buffer.writeUInt16LE(registers_size, code_off);
  buffer.writeUInt16LE(1, code_off + 2);
  buffer.writeUInt16LE(0, code_off + 4);
  buffer.writeUInt16LE(has_catch_handlers ? 1 : 0, code_off + 6);
  buffer.writeUInt32LE(0, code_off + 8);
  buffer.writeUInt32LE(instructions.length, code_off + 12);
  instructions.forEach((unit, index) => buffer.writeUInt16LE(unit, code_off + 16 + index * 2));
  if (has_catch_handlers) {
    const try_item = code_off + 16 + instruction_bytes + try_padding_bytes;
    if (try_padding_bytes) buffer.writeUInt16LE(0, code_off + 16 + instruction_bytes);
    buffer.writeUInt32LE(try_start_addr, try_item);
    buffer.writeUInt16LE(try_insn_count, try_item + 4);
    buffer.writeUInt16LE(1, try_item + 6); // First handler starts one byte after the list count.
    handler_bytes.copy(buffer, try_item + 8);
  }

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
  assert.equal(parsed.class_data[0].direct_methods[0].code.instructions_decoded, true);
  assert.deepEqual(parsed.class_data[0].direct_methods[0].code.instructions.map(item => item.mnemonic), ['return-void']);
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
  fixture.writeUInt16LE(0, 172); // method_id.class_idx points to the int primitive type instead of this class.
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
  // The fixture's concrete code_item starts 12 bytes after class_data_off.
  fixture.writeUInt32LE(2, class_data_off + 12 + 12);
  assert.throws(() => parse_dex(fixture, { max_instruction_units: 1 }), error => error.code === 'ORIX_DEX_INSTRUCTION_BUDGET');
});



test('DEX SLEB128 catch-handler sizes validate fifth-byte sign extension', () => {
  const one_byte_negative = parse_dex(create_semantic_dex({ catch_handler_size_bytes: [0x7f] }));
  assert.equal(one_byte_negative.class_data[0].direct_methods[0].code.handlers, 1);

  // A redundant but correctly sign-extended five-byte encoding of -1 is valid.
  const five_byte_negative = parse_dex(create_semantic_dex({
    catch_handler_size_bytes: [0xff, 0xff, 0xff, 0xff, 0x7f],
  }));
  assert.equal(five_byte_negative.class_data[0].direct_methods[0].code.handlers, 1);

  // In both cases the fifth byte disagrees with its own sign bit. The old
  // decoder could wrap 0x70 << 28 to zero and accept the malformed handler.
  for (const invalid_last_byte of [0x08, 0x70]) {
    const malformed = create_semantic_dex({
      catch_handler_size_bytes: [0x80, 0x80, 0x80, 0x80, invalid_last_byte],
    });
    assert.throws(
      () => parse_dex(malformed),
      error => error.code === 'ORIX_DEX_SEMANTIC_LEB_OVERFLOW',
    );
  }
});

test('DEX parser validates method-handle type, reserved fields and member references', () => {
  const invalid_type = create_semantic_dex();
  const map_off = invalid_type.readUInt32LE(52);
  const map_count = invalid_type.readUInt32LE(map_off);
  let method_handle_off = -1;
  for (let index = 0; index < map_count; index += 1) {
    const item = map_off + 4 + index * 12;
    if (invalid_type.readUInt16LE(item) === 0x0008) method_handle_off = invalid_type.readUInt32LE(item + 8);
  }
  assert.ok(method_handle_off > 0);
  invalid_type.writeUInt16LE(9, method_handle_off);
  assert.throws(() => parse_dex(invalid_type), error => error.code === 'ORIX_DEX_METHOD_HANDLE_TYPE');

  const invalid_member = create_semantic_dex();
  const map_offset = invalid_member.readUInt32LE(52);
  const count = invalid_member.readUInt32LE(map_offset);
  for (let index = 0; index < count; index += 1) {
    const item = map_offset + 4 + index * 12;
    if (invalid_member.readUInt16LE(item) === 0x0008) {
      const offset = invalid_member.readUInt32LE(item + 8);
      invalid_member.writeUInt16LE(1, offset + 4);
    }
  }
  assert.throws(() => parse_dex(invalid_member), error => error.code === 'ORIX_DEX_METHOD_HANDLE_INDEX');
});

test('DEX semantic parser rejects a class_data_item map count that disagrees with class_def references', () => {
  const fixture = create_semantic_dex();
  const map_off = fixture.readUInt32LE(52);
  const map_count = fixture.readUInt32LE(map_off);
  let found = false;
  for (let index = 0; index < map_count; index += 1) {
    const item = map_off + 4 + index * 12;
    if (fixture.readUInt16LE(item) === 0x2000) {
      fixture.writeUInt32LE(2, item + 4);
      found = true;
      break;
    }
  }
  assert.equal(found, true);
  assert.throws(() => parse_dex(fixture), error => error.code === 'ORIX_DEX_CLASS_DATA_MAP_COUNT');
});

test('DEX semantic output ceiling applies across class, field and method records', () => {
  const parsed = parse_dex(create_semantic_dex(), { max_output_items: 1 });
  assert.equal(parsed.class_data_summary.output_items_reported, 1);
  assert.equal(parsed.class_data_summary.output_items_omitted, 2);
  assert.equal(parsed.class_data_summary.output_truncated, true);
  assert.equal(parsed.class_data[0].static_fields.length, 0);
  assert.equal(parsed.class_data[0].direct_methods.length, 0);
  assert.equal(parsed.class_data[0].output_truncated, true);
});

test('DEX parser rejects duplicate or unsorted string_ids and type_ids', () => {
  const duplicate_strings = create_semantic_dex();
  const second_string = duplicate_strings.readUInt32LE(112 + 4);
  duplicate_strings.writeUInt32LE(second_string, 112);
  assert.throws(() => parse_dex(duplicate_strings), error => error.code === 'ORIX_DEX_STRING_ORDER');

  const unsorted_types = create_semantic_dex();
  const type_ids_off = unsorted_types.readUInt32LE(68);
  unsorted_types.writeUInt32LE(2, type_ids_off);
  assert.throws(() => parse_dex(unsorted_types), error => error.code === 'ORIX_DEX_TYPE_ORDER');
});

test('DEX checksum and SHA-1 fields are independently verified without claiming publisher authenticity', () => {
  const fixture = create_semantic_dex();
  fixture[12] ^= 1;
  fixture.writeUInt32LE(adler32(fixture, 12), 8);
  const parsed = parse_dex(fixture);
  assert.equal(parsed.integrity.adler32_verified, true);
  assert.equal(parsed.integrity.signature_sha1_verified, false);
});

test('DEX try blocks and typed/catch-all handlers must target instruction boundaries', () => {
  const instructions = [0x0013, 0x0000, 0x000e]; // const/16 v0, #0; return-void
  const valid = parse_dex(create_semantic_dex({
    catch_handler_size_bytes: [0x7f],
    instructions,
    try_start_addr: 0,
    try_insn_count: 2,
    handler_address: 2,
    catch_all_address: 2,
  }));
  assert.equal(valid.class_data[0].direct_methods[0].code.handlers, 1);

  assert.throws(
    () => parse_dex(create_semantic_dex({
      catch_handler_size_bytes: [0x7f], instructions, try_start_addr: 0,
      try_insn_count: 2, handler_address: 1, catch_all_address: 2,
    })),
    error => error.code === 'ORIX_DEX_CODE_HANDLER_BOUNDARY' && error.details.handler_kind === 'typed',
  );

  assert.throws(
    () => parse_dex(create_semantic_dex({
      catch_handler_size_bytes: [0x7f], instructions, try_start_addr: 0,
      try_insn_count: 2, handler_address: 2, catch_all_address: 1,
    })),
    error => error.code === 'ORIX_DEX_CODE_HANDLER_BOUNDARY' && error.details.handler_kind === 'catch-all',
  );

  assert.throws(
    () => parse_dex(create_semantic_dex({
      catch_handler_size_bytes: [0x7f], instructions, try_start_addr: 1,
      try_insn_count: 1, handler_address: 2, catch_all_address: 2,
    })),
    error => error.code === 'ORIX_DEX_CODE_TRY_START_BOUNDARY',
  );
});

test('DEX typed and catch-all handlers must not begin with move-result variants', () => {
  const moveResults = [0x000a, 0x000b, 0x000c];
  for (const opcode of moveResults) {
    const instructions = [0x0013, 0x0000, opcode, 0x000e];
    const options = {
      catch_handler_size_bytes: [0x7f], instructions, registers_size: 2,
      try_start_addr: 0, try_insn_count: 2,
    };

    assert.throws(
      () => parse_dex(create_semantic_dex({ ...options, handler_address: 2, catch_all_address: 3 })),
      error => error.code === 'ORIX_DEX_CODE_HANDLER_MOVE_RESULT' && error.details.handler_kind === 'typed',
      'typed handler must reject move-result opcode 0x' + opcode.toString(16),
    );

    assert.throws(
      () => parse_dex(create_semantic_dex({ ...options, handler_address: 3, catch_all_address: 2 })),
      error => error.code === 'ORIX_DEX_CODE_HANDLER_MOVE_RESULT' && error.details.handler_kind === 'catch-all',
      'catch-all handler must reject move-result opcode 0x' + opcode.toString(16),
    );
  }
});
