import test from 'node:test';
import assert from 'node:assert/strict';
import { decode_dex_instructions } from '../src/formats/dex-bytecode.mjs';

function words(...values) {
  const buffer = Buffer.alloc(values.length * 2);
  values.forEach((value, index) => buffer.writeUInt16LE(value & 0xffff, index * 2));
  return buffer;
}

const emptyCounts = Object.freeze({
  string_ids: 0, type_ids: 0, field_ids: 0, method_ids: 0,
  proto_ids: 0, call_site_ids: 0, method_handles: 0,
});

function decode(code, options = {}) {
  return decode_dex_instructions(code, {
    offset: 0,
    instruction_units: code.length / 2,
    registers_size: 16,
    dex_version: '040',
    counts: emptyCounts,
    ...options,
  });
}

test('DEX decoder uses the correct 22x and 32x formats for object moves', () => {
  const from16 = decode(words(0x0108, 0x0010), { registers_size: 17 });
  assert.equal(from16.instructions[0].mnemonic, 'move-object/from16');
  assert.deepEqual(from16.instructions[0].registers, [1, 16]);

  const move16 = decode(words(0x0009, 0x0001, 0x0010), { registers_size: 17 });
  assert.equal(move16.instructions[0].mnemonic, 'move-object/16');
  assert.deepEqual(move16.instructions[0].registers, [1, 16]);
});

test('DEX 35c and 45cc instructions decode C-through-G registers from the third code unit', () => {
  const invoke = decode(words(0x556e, 0x0000, 0x4321), {
    registers_size: 6,
    counts: { ...emptyCounts, method_ids: 1 },
  });
  assert.deepEqual(invoke.instructions[0].registers, [1, 2, 3, 4, 5]);

  const polymorphic = decode(words(0x01fa, 0x0000, 0x0007, 0x0000), {
    registers_size: 8,
    counts: { ...emptyCounts, method_ids: 1, proto_ids: 1 },
  });
  assert.deepEqual(polymorphic.instructions[0].registers, [7]);
  assert.deepEqual(polymorphic.instructions[0].proto_reference, { index: 0, kind: 'proto_ids' });
});

test('DEX decoder checks destination and source register pairs for wide conversions and literals', () => {
  const intToDouble = decode(words(0x2083), { registers_size: 3 });
  assert.deepEqual(intToDouble.instructions[0].wide_registers, [0]);

  assert.throws(
    () => decode(words(0x0080), { registers_size: 1 }),
    error => error.code === 'ORIX_DEX_BYTECODE_REGISTER_RANGE',
  );

  const constWide = decode(words(0x0018, 0x0001, 0x0002, 0x0003, 0x0004), { registers_size: 2 });
  assert.deepEqual(constWide.instructions[0].wide_registers, [0]);

  const longShift2addr = decode(words(0x10c3), { registers_size: 2 });
  assert.deepEqual(longShift2addr.instructions[0].wide_registers, [0]);
});

test('DEX decoder extracts const/4 signed literal and return register operands', () => {
  const result = decode(words(0x2112, 0x010f), { registers_size: 2 });
  assert.equal(result.instruction_count, 2);
  assert.equal(result.instructions[0].mnemonic, 'const/4');
  assert.deepEqual(result.instructions[0].registers, [1]);
  assert.equal(result.instructions[0].literal, 2);
  assert.equal(result.instructions[1].mnemonic, 'return');
  assert.deepEqual(result.instructions[1].registers, [1]);
});

test('DEX decoder handles 22x and invoke/range register encodings', () => {
  const result = decode(words(0x0102, 0x0010, 0x0274, 0x0000, 0x0004), {
    registers_size: 20,
    counts: { ...emptyCounts, method_ids: 1 },
  });
  assert.equal(result.instructions[0].mnemonic, 'move/from16');
  assert.deepEqual(result.instructions[0].registers, [1, 16]);
  assert.equal(result.instructions[1].mnemonic, 'invoke-virtual/range');
  assert.deepEqual(result.instructions[1].register_range, { first: 4, count: 2 });
  assert.deepEqual(result.instructions[1].reference, { index: 0, kind: 'method_ids' });
});

test('DEX decoder resolves signed goto offsets to instruction boundaries', () => {
  const result = decode(words(0x0029, 0x0002, 0x000e), { registers_size: 0 });
  assert.equal(result.instructions[0].branch_target, 2);
  assert.equal(result.instructions[1].mnemonic, 'return-void');
});

test('DEX decoder rejects branches into the middle of an instruction', () => {
  assert.throws(
    () => decode(words(0x0029, 0x0001, 0x000e), { registers_size: 0 }),
    error => error.code === 'ORIX_DEX_BYTECODE_BRANCH_BOUNDARY',
  );
});

test('DEX decoder reads aligned packed-switch payload and validates case targets', () => {
  const result = decode(words(
    0x0000, 0x0000,
    0x002b, 0x0004, 0x0000, 0x0000,
    0x0100, 0x0001, 0x000a, 0x0000, 0xfffe, 0xffff,
  ), { registers_size: 1 });
  assert.equal(result.payload_count, 1);
  assert.equal(result.instructions[2].mnemonic, 'packed-switch');
  assert.equal(result.instructions[2].payload_offset, 4);
  assert.deepEqual(result.instructions[2].switch.targets, [{ key: 10, target: 0, offset: -2 }]);
  assert.equal(result.instructions[4].kind, 'packed-switch');
});

test('DEX decoder rejects unsorted sparse-switch keys', () => {
  assert.throws(
    () => decode(words(
      0x0000, 0x0000,
      0x002c, 0x0004, 0x0000, 0x0000,
      0x0200, 0x0002,
      0x0005, 0x0000, 0x0004, 0x0000,
      0xfffe, 0xffff, 0xfffe, 0xffff,
    ), { registers_size: 1 }),
    error => error.code === 'ORIX_DEX_BYTECODE_SWITCH_KEY_ORDER',
  );
});

test('DEX decoder validates bounded fill-array-data payloads', () => {
  const result = decode(words(
    0x0026, 0x0004, 0x0000, 0x0000,
    0x0300, 0x0001, 0x0004, 0x0000, 0x2211, 0x4433,
  ), { registers_size: 1 });
  assert.equal(result.payload_count, 1);
  assert.equal(result.instructions[0].payload_offset, 2);
  assert.equal(result.instructions[2].kind, 'fill-array-data');
  assert.equal(result.instructions[2].element_width, 1);
  assert.equal(result.instructions[2].data_bytes, 4);
});

test('DEX decoder rejects invalid payload widths, alignment and aggregate payload budgets', () => {
  assert.throws(
    () => decode(words(0x0026, 0x0004, 0x0000, 0x0000, 0x0300, 0x0003, 0x0001, 0x0000, 0x0000), { registers_size: 1 }),
    error => error.code === 'ORIX_DEX_BYTECODE_ARRAY_WIDTH',
  );
  assert.throws(
    () => decode(words(0x0000, 0x0100, 0x0000, 0x0000, 0x0000), { registers_size: 0 }),
    error => error.code === 'ORIX_DEX_BYTECODE_PAYLOAD_ALIGNMENT',
  );
  assert.throws(
    () => decode(words(0x0026, 0x0004, 0x0000, 0x0000, 0x0300, 0x0001, 0x0004, 0x0000, 0x2211, 0x4433), {
      registers_size: 1, max_payload_bytes: 3,
    }),
    error => error.code === 'ORIX_DEX_BYTECODE_PAYLOAD_LIMIT',
  );
});

test('DEX decoder rejects unused, truncated and version-gated opcodes', () => {
  assert.throws(() => decode(words(0x003e)), error => error.code === 'ORIX_DEX_BYTECODE_OPCODE');
  assert.throws(() => decode(words(0x0014, 0x0000)), error => error.code === 'ORIX_DEX_BYTECODE_TRUNCATED');
  assert.throws(
    () => decode(words(0x00fa, 0x0000, 0x0000, 0x0000), {
      registers_size: 0, dex_version: '037',
      counts: { ...emptyCounts, method_ids: 1, proto_ids: 1 },
    }),
    error => error.code === 'ORIX_DEX_BYTECODE_VERSION',
  );
});

test('DEX decoder validates reference indexes and register-pair bounds', () => {
  assert.throws(
    () => decode(words(0x001a, 0x0001), { registers_size: 1, counts: { ...emptyCounts, string_ids: 1 } }),
    error => error.code === 'ORIX_DEX_BYTECODE_REFERENCE_RANGE',
  );
  assert.throws(
    () => decode(words(0x0116, 0x0000), { registers_size: 2 }),
    error => error.code === 'ORIX_DEX_BYTECODE_REGISTER_RANGE',
  );
  const intToLong = decode(words(0x2081), { registers_size: 3 });
  assert.deepEqual(intToLong.instructions[0].registers, [0, 2]);
  assert.deepEqual(intToLong.instructions[0].wide_registers, [0]);
});

test('DEX decoder caps displayed instructions while validating the full stream', () => {
  const result = decode(words(0x000e, 0x000e, 0x000e), { registers_size: 0, max_output_instructions: 1 });
  assert.equal(result.instruction_count, 3);
  assert.equal(result.instruction_output_count, 1);
  assert.equal(result.instruction_output_omitted, 2);
  assert.equal(result.instructions_truncated, true);
});

test('DEX decoder rejects branch targets outside the method', () => {
  assert.throws(
    () => decode(words(0x0128), { registers_size: 0 }),
    error => error.code === 'ORIX_DEX_BYTECODE_BRANCH_RANGE',
  );
});
