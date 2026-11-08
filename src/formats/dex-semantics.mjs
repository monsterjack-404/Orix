// JavaScript, src/formats/dex-semantics.mjs, Node.js 20+, bounded DEX method/field/class-data inventory.
// This module validates bounded DEX structures and instruction encodings; it never executes code.
import { OrixError } from '../core/errors.mjs';
import { decode_dex_instructions } from './dex-bytecode.mjs';

const MAX_CODE_ADDRESS_REFERENCES = 1_000_000;

function fail(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function need(buffer, offset, size, end, label) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || size < 0 ||
      offset < 0 || end > buffer.length || offset > end - size) {
    fail('ORIX_DEX_SEMANTIC_RANGE', 'DEX ' + label + ' exceeds its enclosing range', { offset, size, end });
  }
}

function uleb(buffer, offset, end, label) {
  let value = 0;
  for (let index = 0; index < 5; index += 1) {
    need(buffer, offset + index, 1, end, label + ' ULEB128');
    const byte = buffer[offset + index];
    if (index === 4 && (byte & 0xf0) !== 0) {
      fail('ORIX_DEX_SEMANTIC_LEB_OVERFLOW', 'DEX ' + label + ' ULEB128 exceeds 32 bits', { offset });
    }
    value |= (byte & 0x7f) << (index * 7);
    if ((byte & 0x80) === 0) return { value: value >>> 0, next: offset + index + 1 };
  }
  fail('ORIX_DEX_SEMANTIC_LEB_OVERFLOW', 'DEX ' + label + ' ULEB128 is too long', { offset });
}

function sleb(buffer, offset, end, label) {
  let value = 0;
  let shift = 0;
  for (let index = 0; index < 5; index += 1) {
    need(buffer, offset + index, 1, end, label + ' SLEB128');
    const byte = buffer[offset + index];
    if (index === 4) {
      // A 32-bit SLEB128 has only four payload bits left in byte five.
      // Its upper three payload bits must repeat the sign bit (bit 3).
      const sign_extension = (byte & 0x08) !== 0 ? 0x70 : 0;
      if ((byte & 0x70) !== sign_extension) {
        fail('ORIX_DEX_SEMANTIC_LEB_OVERFLOW', 'DEX ' + label + ' SLEB128 exceeds signed 32-bit range', { offset });
      }
    }
    value |= (byte & 0x7f) << shift;
    shift += 7;
    if ((byte & 0x80) === 0) {
      if (shift < 32 && (byte & 0x40) !== 0) value |= (~0 << shift);
      return { value: value | 0, next: offset + index + 1 };
    }
  }
  fail('ORIX_DEX_SEMANTIC_LEB_OVERFLOW', 'DEX ' + label + ' SLEB128 is too long', { offset });
}

function parse_type_list(buffer, offset, data, type_count, max_items, aggregate) {
  if (offset === 0) return [];
  if (offset < data.offset || offset % 4 !== 0 || offset > data.end - 4) {
    fail('ORIX_DEX_PROTO_PARAMETERS_RANGE', 'DEX prototype parameter type_list offset is invalid', { offset });
  }
  const count = buffer.readUInt32LE(offset);
  if (count > max_items || count * 2 > data.end - offset - 4) {
    fail('ORIX_DEX_PROTO_PARAMETERS_LIMIT', 'DEX prototype parameter list exceeds bounds or limits', { offset, count, max_items });
  }
  aggregate.total += count;
  if (aggregate.total > max_items) {
    fail('ORIX_DEX_PROTO_PARAMETERS_BUDGET', 'DEX aggregate prototype parameter count exceeds the configured limit', { total: aggregate.total, max_items });
  }
  const result = [];
  for (let index = 0; index < count; index += 1) {
    const type_index = buffer.readUInt16LE(offset + 4 + index * 2);
    if (type_index >= type_count) {
      fail('ORIX_DEX_PROTO_TYPE_INDEX', 'DEX prototype parameter references an invalid type index', { offset, index, type_index, type_count });
    }
    result.push(type_index);
  }
  return result;
}

function parse_code_item(buffer, offset, data, type_count, limits, state, dex_version, counts) {
  if (!offset || offset < data.offset || offset % 4 !== 0 || offset > data.end - 16) {
    fail('ORIX_DEX_CODE_ITEM_RANGE', 'DEX code_item offset is invalid or unaligned', { offset, data });
  }
  if (state.code_items >= limits.max_items) {
    fail('ORIX_DEX_CODE_ITEM_LIMIT', 'DEX code_item count exceeds the configured limit', { max_items: limits.max_items });
  }
  state.code_items += 1;
  const registers_size = buffer.readUInt16LE(offset);
  const ins_size = buffer.readUInt16LE(offset + 2);
  const outs_size = buffer.readUInt16LE(offset + 4);
  const tries_size = buffer.readUInt16LE(offset + 6);
  const debug_info_off = buffer.readUInt32LE(offset + 8);
  const insns_size = buffer.readUInt32LE(offset + 12);
  if (ins_size > registers_size) {
    fail('ORIX_DEX_CODE_REGISTER_BOUNDS', 'DEX code_item incoming registers exceed the register file', { offset, registers_size, ins_size });
  }
  if (debug_info_off !== 0 && (debug_info_off < data.offset || debug_info_off >= data.end)) {
    fail('ORIX_DEX_DEBUG_INFO_RANGE', 'DEX code_item debug_info_off is outside the data section', { offset, debug_info_off });
  }
  const instruction_bytes = insns_size * 2;
  if (!Number.isSafeInteger(instruction_bytes) || instruction_bytes > data.end - offset - 16) {
    fail('ORIX_DEX_CODE_INSTRUCTIONS_RANGE', 'DEX code_item instruction array exceeds data bounds', { offset, insns_size, data_end: data.end });
  }
  state.instruction_units += insns_size;
  if (state.instruction_units > limits.max_instruction_units) {
    fail('ORIX_DEX_INSTRUCTION_BUDGET', 'DEX aggregate instruction-unit count exceeds the configured limit', {
      instruction_units: state.instruction_units,
      max_instruction_units: limits.max_instruction_units,
    });
  }
  // Parse code_item metadata first so every referenced code address can be
  // checked against the decoded instruction-boundary map in one bounded pass.
  let cursor = offset + 16 + instruction_bytes;
  const code_address_references = [];
  const remember_code_address = value => {
    if (state.code_address_references >= MAX_CODE_ADDRESS_REFERENCES) {
      fail('ORIX_DEX_CODE_ADDRESS_LIMIT', 'DEX aggregate try/catch code-address references exceed the configured safety limit', {
        max_code_address_references: MAX_CODE_ADDRESS_REFERENCES,
      });
    }
    state.code_address_references += 1;
    code_address_references.push(value);
  };
  const try_items = [];
  const handler_offsets = new Set();
  let handler_count = 0;
  if (tries_size > 0) {
    if ((insns_size & 1) !== 0) {
      need(buffer, cursor, 2, data.end, 'code_item try padding');
      if (buffer.readUInt16LE(cursor) !== 0) {
        fail('ORIX_DEX_CODE_PADDING', 'DEX code_item alignment padding must be zero', { offset, cursor });
      }
      cursor += 2;
    }
    const tries_bytes = tries_size * 8;
    if (!Number.isSafeInteger(tries_bytes)) {
      fail('ORIX_DEX_CODE_TRY_RANGE', 'DEX code_item try-item size overflows', { offset, tries_size });
    }
    need(buffer, cursor, tries_bytes, data.end, 'code_item try items');
    let previous_end = 0;
    for (let index = 0; index < tries_size; index += 1) {
      const position = cursor + index * 8;
      const start_addr = buffer.readUInt32LE(position);
      const insn_count = buffer.readUInt16LE(position + 4);
      const handler_off = buffer.readUInt16LE(position + 6);
      const end_addr = start_addr + insn_count;
      if (insn_count === 0 || !Number.isSafeInteger(end_addr) || end_addr > insns_size || start_addr < previous_end) {
        fail('ORIX_DEX_CODE_TRY_BOUNDS', 'DEX code_item try ranges are empty, overlapping, unsorted or out of bounds', { offset, index, start_addr, insn_count, insns_size, previous_end });
      }
      previous_end = end_addr;
      try_items.push({ start_addr, insn_count, handler_off });
      remember_code_address(start_addr);
      remember_code_address(end_addr);
    }
    cursor += tries_bytes;
    const handler_list_start = cursor;
    const header = uleb(buffer, cursor, data.end, 'encoded catch handler count');
    if (header.value > limits.max_items) {
      fail('ORIX_DEX_CODE_HANDLER_LIMIT', 'DEX encoded catch-handler count exceeds the configured limit', { offset, count: header.value });
    }
    handler_count = header.value;
    cursor = header.next;
    for (let index = 0; index < handler_count; index += 1) {
      const relative = cursor - handler_list_start;
      handler_offsets.add(relative);
      const size = sleb(buffer, cursor, data.end, 'encoded catch handler size');
      cursor = size.next;
      const typed_count = Math.abs(size.value);
      if (!Number.isSafeInteger(typed_count) || typed_count > limits.max_items) {
        fail('ORIX_DEX_CODE_HANDLER_LIMIT', 'DEX encoded catch-handler typed count exceeds the configured limit', { offset, index, size: size.value });
      }
      for (let item = 0; item < typed_count; item += 1) {
        const type = uleb(buffer, cursor, data.end, 'catch handler type index');
        cursor = type.next;
        const address = uleb(buffer, cursor, data.end, 'catch handler address');
        cursor = address.next;
        if (type.value >= type_count || address.value >= insns_size) {
          fail('ORIX_DEX_CODE_HANDLER_TARGET', 'DEX catch handler references an invalid type or instruction address', {
            offset, index, item, type_index: type.value, type_count, address: address.value, insns_size,
          });
        }
        remember_code_address(address.value);
      }
      if (size.value <= 0) {
        const catch_all = uleb(buffer, cursor, data.end, 'catch-all handler address');
        cursor = catch_all.next;
        if (catch_all.value >= insns_size) {
          fail('ORIX_DEX_CODE_HANDLER_TARGET', 'DEX catch-all handler address is outside the instruction array', {
            offset, index, address: catch_all.value, insns_size,
          });
        }
        remember_code_address(catch_all.value);
      }
    }
    for (const item of try_items) {
      if (!handler_offsets.has(item.handler_off)) {
        fail('ORIX_DEX_CODE_HANDLER_OFFSET', 'DEX try_item handler_off does not point to an encoded handler start', {
          offset, handler_off: item.handler_off,
        });
      }
    }
  }
  const decoded = decode_dex_instructions(buffer, {
    offset: offset + 16,
    instruction_units: insns_size,
    registers_size,
    dex_version,
    counts,
    max_output_instructions: Math.max(0, limits.max_decoded_instructions - state.decoded_instruction_items),
    max_payload_bytes: limits.max_payload_bytes,
    max_switch_targets: limits.max_switch_targets,
    max_output_switch_targets: Math.max(0, limits.max_output_switch_targets - state.switch_target_output_items),
    required_instruction_boundaries: code_address_references,
  });
  state.decoded_instruction_items += decoded.instruction_count + decoded.payload_count;
  state.instruction_output_items += decoded.instructions.length;
  state.instruction_output_omitted += decoded.instruction_output_omitted;
  state.switch_target_count += decoded.switch_target_count;
  state.switch_target_output_items += decoded.switch_target_output_count;
  state.switch_target_output_omitted += decoded.switch_target_output_omitted;
  state.code_bytes += cursor - offset;
  return {
    offset,
    registers_size,
    ins_size,
    outs_size,
    tries_size,
    handlers: handler_count,
    debug_info_off,
    instruction_units: insns_size,
    instruction_bytes,
    item_bytes: cursor - offset,
    instructions_decoded: true,
    instruction_count: decoded.instruction_count,
    payload_count: decoded.payload_count,
    instruction_output_omitted: decoded.instruction_output_omitted,
    switch_target_count: decoded.switch_target_count,
    switch_target_output_count: decoded.switch_target_output_count,
    switch_target_output_omitted: decoded.switch_target_output_omitted,
    instructions_truncated: decoded.instructions_truncated,
    opcode_counts: decoded.opcode_counts,
    instructions: decoded.instructions,
  };
}

/**
 * Parse DEX identifier/prototype tables and bounded class_data/code_item records.
 * Inputs are the already checked DEX header/index data from parse_dex().
 */
export function parse_dex_semantics({
  buffer, offsets, counts, data, types, strings, map_items = [], max_items = 250_000,
  max_output_items = 10_000, max_instruction_units = 20_000_000,
  dex_version = '040', max_decoded_instructions = 10_000,
  max_payload_bytes = 16 * 1024 * 1024, max_switch_targets = 1_024,
  max_output_switch_targets = 4_096,
} = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_dex_semantics requires a Buffer');
  const limits = { max_items, max_instruction_units, max_decoded_instructions, max_payload_bytes, max_switch_targets, max_output_switch_targets };
  for (const [name, value, min, max] of [
    ['max_items', max_items, 1, 1_000_000],
    ['max_output_items', max_output_items, 1, 100_000],
    ['max_instruction_units', max_instruction_units, 1, 100_000_000],
    ['max_decoded_instructions', max_decoded_instructions, 0, 100_000],
    ['max_payload_bytes', max_payload_bytes, 0, 128 * 1024 * 1024],
    ['max_switch_targets', max_switch_targets, 0, 65_535],
    ['max_output_switch_targets', max_output_switch_targets, 0, 100_000],
  ]) {
    if (!Number.isSafeInteger(value) || value < min || value > max) {
      throw new TypeError(name + ' is outside its supported range');
    }
  }
  const data_end = data.offset + data.size;
  if (!Number.isSafeInteger(data_end) || data_end > buffer.length) {
    fail('ORIX_DEX_SEMANTIC_DATA_RANGE', 'DEX semantic data section exceeds the supplied file');
  }
  const type_at = index => types[index]?.descriptor ?? null;
  const string_at = index => strings[index]?.value ?? null;

  const proto_ids = [];
  const proto_meta = [];
  let total_parameters = 0;
  for (let index = 0; index < counts.proto_ids; index += 1) {
    const position = offsets.proto_ids + index * 12;
    need(buffer, position, 12, data_end, 'proto_id_item');
    const shorty_index = buffer.readUInt32LE(position);
    const return_type_index = buffer.readUInt32LE(position + 4);
    const parameters_off = buffer.readUInt32LE(position + 8);
    if (shorty_index >= counts.string_ids || return_type_index >= counts.type_ids) {
      fail('ORIX_DEX_PROTO_INDEX', 'DEX proto_id_item has an invalid shorty or return-type index', { index, shorty_index, return_type_index });
    }
    const parameters = parse_type_list(buffer, parameters_off, data, counts.type_ids, max_items, { get total() { return total_parameters; }, set total(value) { total_parameters = value; } });
    if (index > 0) {
      const previous = proto_meta[index - 1];
      let order = return_type_index - previous.return_type_index;
      if (order === 0) {
        const shared = Math.min(parameters.length, previous.parameter_type_indices.length);
        for (let item = 0; item < shared && order === 0; item += 1) {
          order = parameters[item] - previous.parameter_type_indices[item];
        }
        if (order === 0) order = parameters.length - previous.parameter_type_indices.length;
      }
      if (order <= 0) {
        fail('ORIX_DEX_PROTO_ORDER', 'DEX proto_id_item entries must be unique and sorted by return type and parameter type list', {
          index, previous_index: index - 1, return_type_index, previous_return_type_index: previous.return_type_index,
        });
      }
    }
    const signature = '(' + parameters.map(type_at).join('') + ')' + (type_at(return_type_index) ?? '?');
    const item = {
      index,
      shorty_index,
      shorty: string_at(shorty_index),
      return_type_index,
      return_type: type_at(return_type_index),
      parameters_off,
      parameter_type_indices: parameters,
      parameter_types: parameters.map(type_at),
      signature,
    };
    proto_meta.push(item);
    if (index < max_output_items) proto_ids.push(item);
  }

  const field_meta = [];
  const field_ids = [];
  for (let index = 0; index < counts.field_ids; index += 1) {
    const position = offsets.field_ids + index * 8;
    need(buffer, position, 8, data_end, 'field_id_item');
    const class_index = buffer.readUInt16LE(position);
    const type_index = buffer.readUInt16LE(position + 2);
    const name_index = buffer.readUInt32LE(position + 4);
    if (class_index >= counts.type_ids || type_index >= counts.type_ids || name_index >= counts.string_ids) {
      fail('ORIX_DEX_FIELD_INDEX', 'DEX field_id_item has an invalid class, type or name index', { index, class_index, type_index, name_index });
    }
    if (index > 0) {
      const previous = field_meta[index - 1];
      const order = class_index - previous.class_index ||
        name_index - previous.name_index || type_index - previous.type_index;
      if (order <= 0) {
        fail('ORIX_DEX_FIELD_ORDER', 'DEX field_id_item entries must be unique and sorted by class, name and type indexes', {
          index, class_index, name_index, type_index,
        });
      }
    }
    const item = {
      index, class_index, class_descriptor: type_at(class_index),
      type_index, type_descriptor: type_at(type_index),
      name_index, name: string_at(name_index),
    };
    field_meta.push(item);
    if (index < max_output_items) field_ids.push(item);
  }

  const method_meta = [];
  const method_ids = [];
  for (let index = 0; index < counts.method_ids; index += 1) {
    const position = offsets.method_ids + index * 8;
    need(buffer, position, 8, data_end, 'method_id_item');
    const class_index = buffer.readUInt16LE(position);
    const proto_index = buffer.readUInt16LE(position + 2);
    const name_index = buffer.readUInt32LE(position + 4);
    if (class_index >= counts.type_ids || proto_index >= counts.proto_ids || name_index >= counts.string_ids) {
      fail('ORIX_DEX_METHOD_INDEX', 'DEX method_id_item has an invalid class, prototype or name index', { index, class_index, proto_index, name_index });
    }
    if (index > 0) {
      const previous = method_meta[index - 1];
      const order = class_index - previous.class_index ||
        name_index - previous.name_index || proto_index - previous.proto_index;
      if (order <= 0) {
        fail('ORIX_DEX_METHOD_ORDER', 'DEX method_id_item entries must be unique and sorted by class, name and prototype indexes', {
          index, class_index, name_index, proto_index,
        });
      }
    }
    const item = {
      index, class_index, class_descriptor: type_at(class_index),
      proto_index, prototype: proto_meta[proto_index]?.signature ?? null,
      name_index, name: string_at(name_index),
    };
    method_meta.push(item);
    if (index < max_output_items) method_ids.push(item);
  }

  const state = { total_data_items: 0, class_data_items: 0, encoded_fields: 0, encoded_methods: 0, code_items: 0, instruction_units: 0, code_bytes: 0, code_address_references: 0, decoded_instruction_items: 0, instruction_output_items: 0, instruction_output_omitted: 0, switch_target_count: 0, switch_target_output_items: 0, switch_target_output_omitted: 0, output_items: 0, output_items_omitted: 0 };
  const class_data = [];
  const class_data_counts = { classes_with_data: 0, static_fields: 0, instance_fields: 0, direct_methods: 0, virtual_methods: 0 };
  for (let class_index = 0; class_index < counts.class_defs; class_index += 1) {
    const class_position = offsets.class_defs + class_index * 32;
    const class_type_index = buffer.readUInt32LE(class_position);
    const class_data_off = buffer.readUInt32LE(class_position + 24);
    if (!class_data_off) continue;
    if (class_data_off < data.offset || class_data_off >= data_end) {
      fail('ORIX_DEX_CLASS_DATA_RANGE', 'DEX class_data_off is outside the data section', { class_index, class_data_off, data });
    }
    state.class_data_items += 1;
    if (state.class_data_items > max_items) {
      fail('ORIX_DEX_CLASS_DATA_LIMIT', 'DEX class_data_item count exceeds the configured limit', { max_items });
    }
    class_data_counts.classes_with_data += 1;
    let cursor = class_data_off;
    const values = [];
    for (const label of ['static_fields', 'instance_fields', 'direct_methods', 'virtual_methods']) {
      const decoded = uleb(buffer, cursor, data_end, label + ' count');
      cursor = decoded.next;
      if (decoded.value > max_items) {
        fail('ORIX_DEX_CLASS_DATA_LIMIT', 'DEX class_data_item ' + label + ' count exceeds the configured limit', { class_index, count: decoded.value, max_items });
      }
      values.push(decoded.value);
    }
    const [static_count, instance_count, direct_count, virtual_count] = values;
    const total_fields = static_count + instance_count;
    const total_methods = direct_count + virtual_count;
    if (!Number.isSafeInteger(total_fields + total_methods) || total_fields + total_methods > max_items ||
        state.total_data_items + total_fields + total_methods > max_items) {
      fail('ORIX_DEX_CLASS_DATA_BUDGET', 'DEX aggregate class-data field/method count exceeds the configured limit', {
        class_index, total_fields, total_methods, previous_total: state.total_data_items, max_items,
      });
    }
    state.total_data_items += total_fields + total_methods;
    state.encoded_fields += total_fields;
    state.encoded_methods += total_methods;
    class_data_counts.static_fields += static_count;
    class_data_counts.instance_fields += instance_count;
    class_data_counts.direct_methods += direct_count;
    class_data_counts.virtual_methods += virtual_count;

    const visible = class_data.length < max_output_items && state.output_items < max_output_items;
    if (visible) state.output_items += 1;
    else state.output_items_omitted += 1;
    const groups = { static_fields: [], instance_fields: [], direct_methods: [], virtual_methods: [] };
    const class_descriptor = type_at(class_type_index);
    const parse_fields = (count, label) => {
      let previous = 0;
      for (let index = 0; index < count; index += 1) {
        const difference = uleb(buffer, cursor, data_end, label + ' field index difference');
        cursor = difference.next;
        const access = uleb(buffer, cursor, data_end, label + ' field access flags');
        cursor = access.next;
        if ((index > 0 && difference.value === 0) || difference.value > 0xffffffff - previous) {
          fail('ORIX_DEX_CLASS_DATA_FIELD_ORDER', 'DEX encoded field indices are duplicated or overflow', { class_index, label, index, difference: difference.value, previous });
        }
        const field_index = previous + difference.value;
        previous = field_index;
        const field = field_meta[field_index];
        if (!field || field.class_index !== class_type_index) {
          fail('ORIX_DEX_CLASS_DATA_FIELD_INDEX', 'DEX class_data_item field index is invalid or belongs to another class', {
            class_index, class_type_index, label, index, field_index, field_owner: field?.class_index ?? null,
          });
        }
        if (visible && state.output_items < max_output_items) { groups[label].push({ ...field, access_flags: access.value }); state.output_items += 1; }
        else state.output_items_omitted += 1;
      }
    };
    const parse_methods = (count, label) => {
      let previous = 0;
      for (let index = 0; index < count; index += 1) {
        const difference = uleb(buffer, cursor, data_end, label + ' method index difference');
        cursor = difference.next;
        const access = uleb(buffer, cursor, data_end, label + ' method access flags');
        cursor = access.next;
        const code = uleb(buffer, cursor, data_end, label + ' method code offset');
        cursor = code.next;
        if ((index > 0 && difference.value === 0) || difference.value > 0xffffffff - previous) {
          fail('ORIX_DEX_CLASS_DATA_METHOD_ORDER', 'DEX encoded method indices are duplicated or overflow', { class_index, label, index, difference: difference.value, previous });
        }
        const method_index = previous + difference.value;
        previous = method_index;
        const method = method_meta[method_index];
        if (!method || method.class_index !== class_type_index) {
          fail('ORIX_DEX_CLASS_DATA_METHOD_INDEX', 'DEX class_data_item method index is invalid or belongs to another class', {
            class_index, class_type_index, label, index, method_index, method_owner: method?.class_index ?? null,
          });
        }
        const is_abstract_or_native = (access.value & (0x0400 | 0x0100)) !== 0;
        if (is_abstract_or_native !== (code.value === 0)) {
          fail('ORIX_DEX_CLASS_DATA_CODE_OFFSET', 'DEX abstract/native methods must have no code_item and concrete methods must reference one', {
            class_index, label, method_index, access_flags: access.value, code_off: code.value,
          });
        }
        const referenceCounts = {
          ...counts,
          call_site_ids: map_items.find(item => item.type === 7)?.size ?? 0,
          method_handles: map_items.find(item => item.type === 8)?.size ?? 0,
        };
        const body = code.value === 0 ? null : parse_code_item(buffer, code.value, data, counts.type_ids, limits, state, dex_version, referenceCounts);
        if (visible && state.output_items < max_output_items) {
          groups[label].push({ ...method, access_flags: access.value, code_off: code.value, code: body });
          state.output_items += 1;
        } else state.output_items_omitted += 1;
      }
    };
    parse_fields(static_count, 'static_fields');
    parse_fields(instance_count, 'instance_fields');
    parse_methods(direct_count, 'direct_methods');
    parse_methods(virtual_count, 'virtual_methods');
    if (visible) {
      class_data.push({
        class_index,
        descriptor: class_descriptor,
        counts: { static_fields: static_count, instance_fields: instance_count, direct_methods: direct_count, virtual_methods: virtual_count },
        ...groups,
        output_truncated: groups.static_fields.length < static_count || groups.instance_fields.length < instance_count || groups.direct_methods.length < direct_count || groups.virtual_methods.length < virtual_count,
      });
    }
  }
  const class_data_map = map_items.find(item => item.type === 0x2000);
  if ((class_data_map?.size ?? 0) !== state.class_data_items) {
    fail('ORIX_DEX_CLASS_DATA_MAP_COUNT', 'DEX class_data_item map count does not match class_def references', {
      map_count: class_data_map?.size ?? 0, referenced_count: state.class_data_items,
    });
  }
  return {
    proto_ids,
    field_ids,
    method_ids,
    class_data,
    class_data_summary: {
      ...class_data_counts,
      class_data_items: state.class_data_items,
      encoded_fields: state.encoded_fields,
      encoded_methods: state.encoded_methods,
      code_items: state.code_items,
      instruction_units: state.instruction_units,
      code_bytes: state.code_bytes,
      decoded_instruction_items: state.decoded_instruction_items,
      instruction_output_items: state.instruction_output_items,
      instruction_output_omitted: state.instruction_output_omitted,
      switch_target_count: state.switch_target_count,
      switch_target_output_items: state.switch_target_output_items,
      switch_target_output_omitted: state.switch_target_output_omitted,
      output_items_reported: state.output_items,
      output_items_omitted: state.output_items_omitted,
      output_truncated: state.output_items_omitted > 0 || state.switch_target_output_omitted > 0 || counts.proto_ids > max_output_items ||
        counts.field_ids > max_output_items || counts.method_ids > max_output_items ||
        state.class_data_items > max_output_items ||
        state.total_data_items > max_output_items,
    },
    notes: [
      'Prototype, field, method and class-data indexes are structurally validated; class data is reported within output limits.',
      'Method code_item headers, Dalvik opcodes and operands, register/reference bounds, branch targets, payload layouts, try ranges and catch-handler references are bounded and validated.',
      'Bytecode is statically decoded for inventory and structural validation only; it is not executed, fully verified, converted into a complete control-flow graph or decompiled.',
    ],
  };
}
