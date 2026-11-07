// Bounded, non-executing Dalvik bytecode decoder for DEX code_item instruction arrays.
// Opcode formats, version gates and payload layouts follow the Android Open Source Project DEX specs.
import { OrixError } from '../core/errors.mjs';

function fail(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

const SPECS = new Map();
function one(opcode, name, format, minVersion = 35) {
  SPECS.set(opcode, Object.freeze({ opcode, mnemonic: name, format, min_version: minVersion }));
}
function range(first, names, format, minVersion = 35) {
  names.forEach((name, index) => one(first + index, name, format, minVersion));
}

one(0x00, 'nop', '10x');
range(0x01, ['move', 'move/from16', 'move/16', 'move-wide', 'move-wide/from16', 'move-wide/16', 'move-object', 'move-object/from16', 'move-object/16'], '12x');
one(0x02, 'move/from16', '22x');
one(0x03, 'move/16', '32x');
one(0x05, 'move-wide/from16', '22x');
one(0x06, 'move-wide/16', '32x');
range(0x0a, ['move-result', 'move-result-wide', 'move-result-object', 'move-exception'], '11x');
one(0x0e, 'return-void', '10x');
range(0x0f, ['return', 'return-wide', 'return-object'], '11x');
range(0x12, ['const/4'], '11n');
range(0x13, ['const/16'], '21s');
range(0x14, ['const'], '31i');
range(0x15, ['const/high16'], '21h');
range(0x16, ['const-wide/16'], '21s');
range(0x17, ['const-wide/32'], '31i');
range(0x18, ['const-wide'], '51l');
range(0x19, ['const-wide/high16'], '21h');
range(0x1a, ['const-string'], '21c');
one(0x1b, 'const-string/jumbo', '31c');
range(0x1c, ['const-class'], '21c');
range(0x1d, ['monitor-enter', 'monitor-exit'], '11x');
one(0x1f, 'check-cast', '21c');
one(0x20, 'instance-of', '22c');
one(0x21, 'array-length', '12x');
one(0x22, 'new-instance', '21c');
one(0x23, 'new-array', '22c');
one(0x24, 'filled-new-array', '35c');
one(0x25, 'filled-new-array/range', '3rc');
one(0x26, 'fill-array-data', '31t');
one(0x27, 'throw', '11x');
one(0x28, 'goto', '10t');
one(0x29, 'goto/16', '20t');
one(0x2a, 'goto/32', '30t');
range(0x2b, ['packed-switch', 'sparse-switch'], '31t');
range(0x2d, ['cmpl-float', 'cmpg-float', 'cmpl-double', 'cmpg-double', 'cmp-long'], '23x');
range(0x32, ['if-eq', 'if-ne', 'if-lt', 'if-ge', 'if-gt', 'if-le'], '22t');
range(0x38, ['if-eqz', 'if-nez', 'if-ltz', 'if-gez', 'if-gtz', 'if-lez'], '21t');
range(0x44, ['aget', 'aget-wide', 'aget-object', 'aget-boolean', 'aget-byte', 'aget-char', 'aget-short', 'aput', 'aput-wide', 'aput-object', 'aput-boolean', 'aput-byte', 'aput-char', 'aput-short'], '23x');
range(0x52, ['iget', 'iget-wide', 'iget-object', 'iget-boolean', 'iget-byte', 'iget-char', 'iget-short', 'iput', 'iput-wide', 'iput-object', 'iput-boolean', 'iput-byte', 'iput-char', 'iput-short'], '22c');
range(0x60, ['sget', 'sget-wide', 'sget-object', 'sget-boolean', 'sget-byte', 'sget-char', 'sget-short', 'sput', 'sput-wide', 'sput-object', 'sput-boolean', 'sput-byte', 'sput-char', 'sput-short'], '21c');
range(0x6e, ['invoke-virtual', 'invoke-super', 'invoke-direct', 'invoke-static', 'invoke-interface'], '35c');
range(0x74, ['invoke-virtual/range', 'invoke-super/range', 'invoke-direct/range', 'invoke-static/range', 'invoke-interface/range'], '3rc');
range(0x7b, ['neg-int', 'not-int', 'neg-long', 'not-long', 'neg-float', 'neg-double', 'int-to-long', 'int-to-float', 'int-to-double', 'long-to-int', 'long-to-float', 'long-to-double', 'float-to-int', 'float-to-long', 'float-to-double', 'double-to-int', 'double-to-long', 'double-to-float', 'int-to-byte', 'int-to-char', 'int-to-short'], '12x');
range(0x90, ['add-int', 'sub-int', 'mul-int', 'div-int', 'rem-int', 'and-int', 'or-int', 'xor-int', 'shl-int', 'shr-int', 'ushr-int', 'add-long', 'sub-long', 'mul-long', 'div-long', 'rem-long', 'and-long', 'or-long', 'xor-long', 'shl-long', 'shr-long', 'ushr-long', 'add-float', 'sub-float', 'mul-float', 'div-float', 'rem-float', 'add-double', 'sub-double', 'mul-double', 'div-double', 'rem-double'], '23x');
range(0xb0, ['add-int/2addr', 'sub-int/2addr', 'mul-int/2addr', 'div-int/2addr', 'rem-int/2addr', 'and-int/2addr', 'or-int/2addr', 'xor-int/2addr', 'shl-int/2addr', 'shr-int/2addr', 'ushr-int/2addr', 'add-long/2addr', 'sub-long/2addr', 'mul-long/2addr', 'div-long/2addr', 'rem-long/2addr', 'and-long/2addr', 'or-long/2addr', 'xor-long/2addr', 'shl-long/2addr', 'shr-long/2addr', 'ushr-long/2addr', 'add-float/2addr', 'sub-float/2addr', 'mul-float/2addr', 'div-float/2addr', 'rem-float/2addr', 'add-double/2addr', 'sub-double/2addr', 'mul-double/2addr', 'div-double/2addr', 'rem-double/2addr'], '12x');
range(0xd0, ['add-int/lit16', 'rsub-int', 'mul-int/lit16', 'div-int/lit16', 'rem-int/lit16', 'and-int/lit16', 'or-int/lit16', 'xor-int/lit16'], '22s');
range(0xd8, ['add-int/lit8', 'rsub-int/lit8', 'mul-int/lit8', 'div-int/lit8', 'rem-int/lit8', 'and-int/lit8', 'or-int/lit8', 'xor-int/lit8', 'shl-int/lit8', 'shr-int/lit8', 'ushr-int/lit8'], '22b');
one(0xfa, 'invoke-polymorphic', '45cc', 38);
one(0xfb, 'invoke-polymorphic/range', '4rcc', 38);
one(0xfc, 'invoke-custom', '35c', 38);
one(0xfd, 'invoke-custom/range', '3rc', 38);
one(0xfe, 'const-method-handle', '21c', 39);
one(0xff, 'const-method-type', '21c', 39);

const FORMAT_UNITS = Object.freeze({
  '10x': 1, '11x': 1, '12x': 1, '11n': 1, '10t': 1,
  '20t': 2, '21t': 2, '22t': 2, '22x': 2, '21s': 2, '21h': 2, '21c': 2,
  '23x': 2, '22b': 2, '22s': 2, '22c': 2,
  '30t': 3, '31t': 3, '31i': 3, '31c': 3, '32x': 3,
  '35c': 3, '3rc': 3, '45cc': 4, '4rcc': 4, '51l': 5,
});

function signed8(value) { return (value << 24) >> 24; }
function signed16(value) { return (value << 16) >> 16; }
function signed32(value) { return value | 0; }
function versionNumber(version) { return Number.parseInt(version, 10); }
function atUnit(buffer, base, unit) { return buffer.readUInt16LE(base + unit * 2); }
function checkRegister(index, width, registersSize, pc) {
  if (!Number.isSafeInteger(index) || index < 0 || index + width > registersSize) {
    fail('ORIX_DEX_BYTECODE_REGISTER_RANGE', 'DEX bytecode register operand exceeds the code_item register file', {
      pc, register: index, width, registers_size: registersSize,
    });
  }
}
function checkReference(kind, index, counts, pc) {
  const count = counts[kind] ?? 0;
  if (!Number.isInteger(index) || index < 0 || index >= count) {
    fail('ORIX_DEX_BYTECODE_REFERENCE_RANGE', 'DEX bytecode reference index is outside its identifier table', {
      pc, kind, index, count,
    });
  }
}

function payloadInfo(buffer, base, pc, totalUnits, maxPayloadBytes) {
  if ((pc & 1) !== 0) {
    fail('ORIX_DEX_BYTECODE_PAYLOAD_ALIGNMENT', 'DEX payload pseudo-instructions must be four-byte aligned', { pc });
  }
  const first = atUnit(buffer, base, pc);
  const size = atUnit(buffer, base, pc + 1);
  if (first === 0x0100) {
    const units = 4 + size * 2;
    if (!Number.isSafeInteger(units) || units > totalUnits - pc) {
      fail('ORIX_DEX_BYTECODE_PAYLOAD_RANGE', 'DEX packed-switch payload exceeds the instruction array', { pc, size, units, total_units: totalUnits });
    }
    return { kind: 'packed-switch', kind_id: 2, size, units, data_bytes: size * 4 };
  }
  if (first === 0x0200) {
    const units = 2 + size * 4;
    if (!Number.isSafeInteger(units) || units > totalUnits - pc) {
      fail('ORIX_DEX_BYTECODE_PAYLOAD_RANGE', 'DEX sparse-switch payload exceeds the instruction array', { pc, size, units, total_units: totalUnits });
    }
    return { kind: 'sparse-switch', kind_id: 3, size, units, data_bytes: size * 8 };
  }
  if (first === 0x0300) {
    const width = atUnit(buffer, base, pc + 1);
    const elementCount = buffer.readUInt32LE(base + (pc + 2) * 2);
    if (![1, 2, 4, 8].includes(width)) {
      fail('ORIX_DEX_BYTECODE_ARRAY_WIDTH', 'DEX fill-array-data element_width must be 1, 2, 4 or 8 bytes', { pc, width });
    }
    const dataBytes = width * elementCount;
    if (!Number.isSafeInteger(dataBytes) || dataBytes > maxPayloadBytes) {
      fail('ORIX_DEX_BYTECODE_PAYLOAD_LIMIT', 'DEX fill-array-data payload exceeds the configured byte budget', { pc, width, element_count: elementCount, data_bytes: dataBytes, max_payload_bytes: maxPayloadBytes });
    }
    const units = 4 + Math.ceil(dataBytes / 2);
    if (!Number.isSafeInteger(units) || units > totalUnits - pc) {
      fail('ORIX_DEX_BYTECODE_PAYLOAD_RANGE', 'DEX fill-array-data payload exceeds the instruction array', { pc, units, total_units: totalUnits });
    }
    return { kind: 'fill-array-data', kind_id: 4, size: elementCount, element_width: width, units, data_bytes: dataBytes };
  }
  fail('ORIX_DEX_BYTECODE_PAYLOAD_KIND', 'DEX code_item contains an unknown payload identifier', { pc, identifier: first });
}

function readOperands(buffer, base, pc, spec) {
  const first = atUnit(buffer, base, pc);
  const second = FORMAT_UNITS[spec.format] > 1 ? atUnit(buffer, base, pc + 1) : 0;
  const third = FORMAT_UNITS[spec.format] > 2 ? atUnit(buffer, base, pc + 2) : 0;
  const fourth = FORMAT_UNITS[spec.format] > 3 ? atUnit(buffer, base, pc + 3) : 0;
  const fifth = FORMAT_UNITS[spec.format] > 4 ? atUnit(buffer, base, pc + 4) : 0;
  const aa = first >>> 8;
  const a4 = (first >>> 8) & 0x0f;
  const b4 = (first >>> 12) & 0x0f;
  const out = { registers: [], wide_registers: [], reference: null, branch_offset: null };
  switch (spec.format) {
    case '10x':
      if (first !== spec.opcode) fail('ORIX_DEX_BYTECODE_RESERVED_BITS', 'DEX 10x instruction has nonzero unused bits', { pc, word: first });
      break;
    case '11x': out.registers = [aa]; break;
    case '12x': out.registers = [a4, b4]; break;
    case '11n': out.registers = [a4]; out.literal = signed8(b4 << 4) >> 4; break;
    case '10t': out.branch_offset = signed8(aa); break;
    case '20t': out.branch_offset = signed16(second); break;
    case '30t': out.branch_offset = signed32(second | (third << 16)); break;
    case '21t': out.registers = [aa]; out.branch_offset = signed16(second); break;
    case '22t': out.registers = [a4, b4]; out.branch_offset = signed16(second); break;
    case '22x': out.registers = [aa, second]; break;
    case '32x': out.registers = [second, third]; break;
    case '21s': out.registers = [aa]; out.literal = signed16(second); break;
    case '21h': out.registers = [aa]; out.literal_upper16 = second; break;
    case '21c': out.registers = [aa]; out.reference = { index: second }; break;
    case '31i': out.registers = [aa]; out.literal = signed32(second | (third << 16)); break;
    case '31t': out.registers = [aa]; out.branch_offset = signed32(second | (third << 16)); break;
    case '31c': out.registers = [aa]; out.reference = { index: (second | (third << 16)) >>> 0 }; break;
    case '22c': out.registers = [a4, b4]; out.reference = { index: second }; break;
    case '22s': out.registers = [a4, b4]; out.literal = signed16(second); break;
    case '23x': out.registers = [aa, second & 0xff, second >>> 8]; break;
    case '22b': out.registers = [aa, second & 0xff]; out.literal = signed8(second >>> 8); break;
    case '35c':
    case '45cc': {
      const argumentWords = a4;
      if (argumentWords > 5) fail('ORIX_DEX_BYTECODE_ARGUMENT_COUNT', 'DEX 35c/45cc instruction argument count exceeds five registers', { pc, argument_words: argumentWords });
      const nibbleRegs = [second & 0x0f, (second >>> 4) & 0x0f, (second >>> 8) & 0x0f, second >>> 12, (first >>> 12) & 0x0f];
      out.registers = nibbleRegs.slice(0, argumentWords);
      out.argument_words = argumentWords;
      out.reference = { index: third };
      if (spec.format === '45cc') out.proto_reference = { index: fourth };
      break;
    }
    case '3rc':
    case '4rcc':
      out.argument_words = aa;
      out.register_range = { first: third, count: aa };
      out.reference = { index: second };
      if (spec.format === '4rcc') out.proto_reference = { index: fourth };
      break;
    case '51l': {
      out.registers = [aa];
      const value = BigInt(second) | (BigInt(third) << 16n) | (BigInt(fourth) << 32n) | (BigInt(fifth) << 48n);
      out.literal_hex = '0x' + value.toString(16).padStart(16, '0');
      break;
    }
    default: fail('ORIX_DEX_BYTECODE_FORMAT', 'DEX opcode uses an unsupported instruction format', { pc, opcode: spec.opcode, format: spec.format });
  }
  return out;
}

function referenceKind(opcode, format) {
  if (opcode === 0x1a || opcode === 0x1b) return 'string_ids';
  if ([0x1c, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25].includes(opcode)) return 'type_ids';
  if ((opcode >= 0x52 && opcode <= 0x5f) || (opcode >= 0x60 && opcode <= 0x6d)) return 'field_ids';
  if ((opcode >= 0x6e && opcode <= 0x72) || (opcode >= 0x74 && opcode <= 0x78) || opcode === 0xfa || opcode === 0xfb) return 'method_ids';
  if (opcode === 0xfc || opcode === 0xfd) return 'call_site_ids';
  if (opcode === 0xfe) return 'method_handles';
  if (opcode === 0xff || opcode === 0xfa || opcode === 0xfb) return 'proto_ids';
  if (format === '22c') return opcode === 0x20 || opcode === 0x23 ? 'type_ids' : 'field_ids';
  return null;
}

function validateRegisters(opcode, operands, registersSize, pc, format) {
  for (const register of operands.registers) checkRegister(register, 1, registersSize, pc);
  const wide = new Set();
  const addWide = index => wide.add(index);
  if (format === '12x') {
    if ([0x04, 0x7d, 0x7e, 0x86, 0x8b].includes(opcode)) { addWide(0); addWide(1); }
    if (opcode === 0x81 || opcode === 0x86 || opcode === 0x8b) addWide(0);
    if ([0x84, 0x85, 0x86, 0x8a, 0x8b, 0x8c].includes(opcode)) addWide(1);
    if (opcode >= 0xbb && opcode <= 0xc2) { addWide(0); addWide(1); }
    if (opcode >= 0xc3 && opcode <= 0xc5) addWide(0);
    if (opcode >= 0xcb && opcode <= 0xcf) { addWide(0); addWide(1); }
  } else if (format === '22x' && opcode === 0x05) { addWide(0); addWide(1); }
  else if (format === '32x' && opcode === 0x06) { addWide(0); addWide(1); }
  else if (format === '11x' && (opcode === 0x0b || opcode === 0x10)) addWide(0);
  else if (['21s', '21h', '21c', '31i'].includes(format) && [0x16, 0x17, 0x18, 0x19].includes(opcode)) addWide(0);
  else if (format === '22c' && (opcode === 0x53 || opcode === 0x5a)) addWide(0);
  else if (format === '23x') {
    if (opcode === 0x45 || opcode === 0x4c) addWide(0);
    if (opcode === 0x2f || opcode === 0x30 || opcode === 0x31) { addWide(1); addWide(2); }
    if (opcode >= 0x9b && opcode <= 0xa2) { addWide(0); addWide(1); addWide(2); }
    if (opcode >= 0xa3 && opcode <= 0xa5) { addWide(0); addWide(1); }
    if (opcode >= 0xab && opcode <= 0xaf) { addWide(0); addWide(1); addWide(2); }
  }
  for (const index of wide) {
    const register = operands.registers[index];
    if (register !== undefined) {
      checkRegister(register, 2, registersSize, pc);
      operands.wide_registers.push(register);
    }
  }
  if (operands.register_range) {
    const { first, count } = operands.register_range;
    if (count > 0 && first + count > registersSize) {
      fail('ORIX_DEX_BYTECODE_REGISTER_RANGE', 'DEX invoke/range register span exceeds the code_item register file', { pc, first_register: first, argument_words: count, registers_size: registersSize });
    }
  }
}

function validateReference(opcode, format, operands, counts, pc) {
  const kind = referenceKind(opcode, format);
  if (kind && operands.reference) {
    checkReference(kind, operands.reference.index, counts, pc);
    operands.reference.kind = kind;
  }
  if (operands.proto_reference) {
    checkReference('proto_ids', operands.proto_reference.index, counts, pc);
    operands.proto_reference.kind = 'proto_ids';
  }
}

function validateBranchTarget(target, boundaries, totalUnits, pc, type = 'instruction') {
  if (!Number.isSafeInteger(target) || target < 0 || target >= totalUnits) {
    fail('ORIX_DEX_BYTECODE_BRANCH_RANGE', 'DEX bytecode branch target is outside its method instruction array', { pc, target, instruction_units: totalUnits });
  }
  const flags = boundaries[target];
  if (type === 'instruction' && flags !== 1) {
    fail('ORIX_DEX_BYTECODE_BRANCH_BOUNDARY', 'DEX bytecode branch target does not point to an instruction boundary', { pc, target, target_kind: flags === undefined ? 'not-boundary' : 'payload' });
  }
  if (type === 'packed-switch' && flags !== 2) fail('ORIX_DEX_BYTECODE_PAYLOAD_REFERENCE', 'packed-switch must reference a packed-switch payload', { pc, target, payload_kind: flags });
  if (type === 'sparse-switch' && flags !== 3) fail('ORIX_DEX_BYTECODE_PAYLOAD_REFERENCE', 'sparse-switch must reference a sparse-switch payload', { pc, target, payload_kind: flags });
  if (type === 'fill-array-data' && flags !== 4) fail('ORIX_DEX_BYTECODE_PAYLOAD_REFERENCE', 'fill-array-data must reference a fill-array-data payload', { pc, target, payload_kind: flags });
}

function switchPayloadTargets(buffer, base, payloadPc, switchPc, kind, maxTargets, boundaries, totalUnits) {
  const size = atUnit(buffer, base, payloadPc + 1);
  let keysOffset;
  let targetsOffset;
  let firstKey = null;
  if (kind === 'packed-switch') {
    firstKey = buffer.readInt32LE(base + (payloadPc + 2) * 2);
    keysOffset = null;
    targetsOffset = base + (payloadPc + 4) * 2;
    if (size && firstKey + size - 1 > 0x7fffffff) {
      fail('ORIX_DEX_BYTECODE_SWITCH_KEY_RANGE', 'DEX packed-switch key range overflows signed 32-bit values', { payload_pc: payloadPc, first_key: firstKey, size });
    }
  } else {
    keysOffset = base + (payloadPc + 2) * 2;
    targetsOffset = keysOffset + size * 4;
  }
  const targets = [];
  let previousKey = -1;
  for (let index = 0; index < size; index += 1) {
    const key = kind === 'packed-switch' ? firstKey + index : buffer.readInt32LE(keysOffset + index * 4);
    const delta = buffer.readInt32LE(targetsOffset + index * 4);
    if (kind === 'sparse-switch' && index > 0 && key <= previousKey) {
      fail('ORIX_DEX_BYTECODE_SWITCH_KEY_ORDER', 'DEX sparse-switch keys must be strictly increasing', { payload_pc: payloadPc, index, key, previous_key: previousKey });
    }
    previousKey = key;
    const target = switchPc + delta;
    validateBranchTarget(target, boundaries, totalUnits, switchPc);
    if (index < maxTargets) targets.push({ key, target, offset: delta });
  }
  return { count: size, first_key: firstKey, targets, targets_truncated: size > maxTargets };
}

/** Decode and structurally validate one DEX code_item instruction stream without executing it. */
export function decode_dex_instructions(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('decode_dex_instructions requires a Buffer');
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('DEX bytecode options must be an object');
  const offset = options.offset;
  const instructionUnits = options.instruction_units;
  const registersSize = options.registers_size;
  const dexVersion = options.dex_version ?? '040';
  const counts = options.counts ?? {};
  const maxOutput = options.max_output_instructions ?? 10_000;
  const maxPayloadBytes = options.max_payload_bytes ?? 16 * 1024 * 1024;
  const maxSwitchTargets = options.max_switch_targets ?? 1_024;
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(instructionUnits) || instructionUnits < 0 ||
      !Number.isSafeInteger(registersSize) || registersSize < 0 || !Number.isSafeInteger(maxOutput) || maxOutput < 0 || maxOutput > 100_000 ||
      !Number.isSafeInteger(maxPayloadBytes) || maxPayloadBytes < 0 || maxPayloadBytes > 128 * 1024 * 1024 ||
      !Number.isSafeInteger(maxSwitchTargets) || maxSwitchTargets < 0 || maxSwitchTargets > 65_535) {
    throw new TypeError('DEX bytecode option is outside its supported range');
  }
  if (offset > buffer.length || instructionUnits > Math.floor((buffer.length - offset) / 2)) {
    fail('ORIX_DEX_BYTECODE_RANGE', 'DEX code_item instruction array exceeds the input buffer', { offset, instruction_units: instructionUnits, file_size: buffer.length });
  }
  const version = versionNumber(dexVersion);
  if (!Number.isInteger(version)) throw new TypeError('DEX version must be a numeric three-digit string');

  // One byte per code unit records instruction starts (1) and payload starts (2–4).
  // This permits O(1) target checks without retaining an unbounded instruction object graph.
  const boundaries = new Uint8Array(instructionUnits);
  let pc = 0;
  let totalInstructions = 0;
  let payloadCount = 0;
  let payloadBytes = 0;
  while (pc < instructionUnits) {
    const word = atUnit(buffer, offset, pc);
    const opcode = word & 0xff;
    if (opcode === 0x00 && word !== 0) {
      const payload = payloadInfo(buffer, offset, pc, instructionUnits, maxPayloadBytes);
      if (payload.data_bytes > maxPayloadBytes - payloadBytes) {
        fail('ORIX_DEX_BYTECODE_PAYLOAD_BUDGET', 'DEX aggregate inline payload bytes exceed the configured budget', { pc, payload_bytes: payload.data_bytes, previous_bytes: payloadBytes, max_payload_bytes: maxPayloadBytes });
      }
      payloadBytes += payload.data_bytes;
      boundaries[pc] = payload.kind_id;
      payloadCount += 1;
      pc += payload.units;
      continue;
    }
    const spec = SPECS.get(opcode);
    if (!spec) {
      fail('ORIX_DEX_BYTECODE_OPCODE', 'DEX code_item contains an unused or unsupported opcode', { pc, opcode, word, dex_version: dexVersion });
    }
    if (version < spec.min_version) {
      fail('ORIX_DEX_BYTECODE_VERSION', 'DEX opcode is not available in the declared DEX version', { pc, opcode, mnemonic: spec.mnemonic, dex_version: dexVersion, minimum_version: String(spec.min_version).padStart(3, '0') });
    }
    const units = FORMAT_UNITS[spec.format];
    if (units > instructionUnits - pc) {
      fail('ORIX_DEX_BYTECODE_TRUNCATED', 'DEX instruction is truncated at the end of the code_item', { pc, opcode, mnemonic: spec.mnemonic, format: spec.format, required_units: units, remaining_units: instructionUnits - pc });
    }
    boundaries[pc] = 1;
    totalInstructions += 1;
    pc += units;
  }

  const instructions = [];
  const opcodeCounts = Object.create(null);
  let branchReferenceCount = 0;
  pc = 0;
  while (pc < instructionUnits) {
    const flags = boundaries[pc];
    if (flags >= 2) {
      const payload = payloadInfo(buffer, offset, pc, instructionUnits, maxPayloadBytes);
      const item = { offset: pc, kind: payload.kind, size: payload.size, code_units: payload.units, data_bytes: payload.data_bytes };
      if (payload.element_width !== undefined) item.element_width = payload.element_width;
      if (instructions.length < maxOutput) instructions.push(item);
      pc += payload.units;
      continue;
    }
    const word = atUnit(buffer, offset, pc);
    const opcode = word & 0xff;
    const spec = SPECS.get(opcode);
    const operands = readOperands(buffer, offset, pc, spec);
    validateRegisters(opcode, operands, registersSize, pc, spec.format);
    validateReference(opcode, spec.format, operands, counts, pc);
    const item = {
      offset: pc,
      opcode,
      mnemonic: spec.mnemonic,
      format: spec.format,
      code_units: FORMAT_UNITS[spec.format],
    };
    if (operands.registers.length) item.registers = operands.registers;
    if (operands.wide_registers.length) item.wide_registers = operands.wide_registers;
    if (operands.register_range) item.register_range = operands.register_range;
    if (operands.argument_words !== undefined) item.argument_words = operands.argument_words;
    if (operands.literal !== undefined) item.literal = operands.literal;
    if (operands.literal_upper16 !== undefined) item.literal_upper16 = operands.literal_upper16;
    if (operands.literal_hex !== undefined) item.literal_hex = operands.literal_hex;
    if (operands.reference) item.reference = operands.reference;
    if (operands.proto_reference) item.proto_reference = operands.proto_reference;

    if (operands.branch_offset !== null) {
      const target = pc + operands.branch_offset;
      if (operands.branch_offset === 0 && [0x28, 0x29, 0x2a, ...Array.from({ length: 12 }, (_, i) => 0x32 + i)].includes(opcode)) {
        fail('ORIX_DEX_BYTECODE_BRANCH_ZERO', 'DEX goto/conditional-branch instruction must not have a zero offset', { pc, opcode });
      }
      if (opcode === 0x26 || opcode === 0x2b || opcode === 0x2c) {
        const expected = opcode === 0x26 ? 'fill-array-data' : opcode === 0x2b ? 'packed-switch' : 'sparse-switch';
        validateBranchTarget(target, boundaries, instructionUnits, pc, expected);
        item.payload_offset = target;
        if (opcode === 0x2b || opcode === 0x2c) {
          item.switch = switchPayloadTargets(buffer, offset, target, pc, expected, maxSwitchTargets, boundaries, instructionUnits);
        }
      } else {
        validateBranchTarget(target, boundaries, instructionUnits, pc);
        item.branch_target = target;
      }
      branchReferenceCount += 1;
    }

    opcodeCounts[spec.mnemonic] = (opcodeCounts[spec.mnemonic] ?? 0) + 1;
    if (instructions.length < maxOutput) instructions.push(item);
    pc += item.code_units;
  }
  return {
    instruction_units: instructionUnits,
    instruction_count: totalInstructions,
    payload_count: payloadCount,
    instruction_output_count: instructions.length,
    instruction_output_omitted: totalInstructions + payloadCount - instructions.length,
    instructions_truncated: totalInstructions + payloadCount > instructions.length,
    payload_bytes: payloadBytes,
    branch_reference_count: branchReferenceCount,
    opcode_counts: opcodeCounts,
    instructions,
    notes: [
      'Dalvik instruction boundaries, standard opcode formats, register bounds, identifier references, branch targets and inline payload layouts are decoded statically.',
      'This is instruction inventory and structural validation, not bytecode execution, full semantic verification, control-flow graph reconstruction or decompilation.',
    ],
  };
}
