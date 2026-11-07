// Bounded AAPT2 ResourceTable decoder for Android App Bundle resources.pb.
// This is metadata inventory, not Android's complete resource resolution engine.
import { createHash } from 'node:crypto';
import { OrixError } from '../core/errors.mjs';

const VISIBILITY = { 0: 'UNKNOWN', 1: 'PRIVATE', 2: 'PUBLIC' };
const OVERLAY_POLICY = {
  0: 'NONE', 1: 'PUBLIC', 2: 'SYSTEM', 3: 'VENDOR', 4: 'PRODUCT',
  5: 'SIGNATURE', 6: 'ODM', 7: 'OEM', 8: 'ACTOR', 9: 'CONFIG_SIGNATURE',
};
const REFERENCE_TYPE = { 0: 'REFERENCE', 1: 'ATTRIBUTE' };
const FILE_TYPE = { 0: 'UNKNOWN', 1: 'PNG', 2: 'BINARY_XML', 3: 'PROTO_XML' };
const CONFIG_ENUMS = {
  layout_direction: { 0: 'UNSET', 1: 'LTR', 2: 'RTL' },
  screen_layout_size: { 0: 'UNSET', 1: 'SMALL', 2: 'NORMAL', 3: 'LARGE', 4: 'XLARGE' },
  screen_layout_long: { 0: 'UNSET', 1: 'LONG', 2: 'NOTLONG' },
  screen_round: { 0: 'UNSET', 1: 'ROUND', 2: 'NOTROUND' },
  wide_color_gamut: { 0: 'UNSET', 1: 'WIDECG', 2: 'NOWIDECG' },
  hdr: { 0: 'UNSET', 1: 'HIGHDR', 2: 'LOWDR' },
  orientation: { 0: 'UNSET', 1: 'PORT', 2: 'LAND', 3: 'SQUARE' },
  ui_mode_type: { 0: 'UNSET', 1: 'NORMAL', 2: 'DESK', 3: 'CAR', 4: 'TELEVISION', 5: 'APPLIANCE', 6: 'WATCH', 7: 'VRHEADSET' },
  ui_mode_night: { 0: 'UNSET', 1: 'NIGHT', 2: 'NOTNIGHT' },
  touchscreen: { 0: 'UNSET', 1: 'NOTOUCH', 2: 'STYLUS', 3: 'FINGER' },
  keys_hidden: { 0: 'UNSET', 1: 'KEYSEXPOSED', 2: 'KEYSHIDDEN', 3: 'KEYSSOFT' },
  keyboard: { 0: 'UNSET', 1: 'NOKEYS', 2: 'QWERTY', 3: 'TWELVEKEY' },
  nav_hidden: { 0: 'UNSET', 1: 'NAVEXPOSED', 2: 'NAVHIDDEN' },
  navigation: { 0: 'UNSET', 1: 'NONAV', 2: 'DPAD', 3: 'TRACKBALL', 4: 'WHEEL' },
  grammatical_gender: { 0: 'UNSET', 1: 'NEUTER', 2: 'FEMININE', 3: 'MASCULINE' },
};

function fail(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function integer_limit(name, value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new TypeError(name + ' must be an integer between ' + min + ' and ' + max);
  }
}

function read_varint(buffer, cursor, end, label) {
  let value = 0n;
  for (let index = 0; index < 10; index += 1) {
    if (cursor >= end) fail('ORIX_RESOURCE_VARINT_TRUNCATED', 'Truncated ResourceTable protobuf varint', { label, offset: cursor });
    const byte = buffer[cursor++];
    if (index === 9 && (byte & 0xfe) !== 0) {
      fail('ORIX_RESOURCE_VARINT_OVERFLOW', 'ResourceTable protobuf varint exceeds 64 bits', { label, offset: cursor - 1 });
    }
    value |= BigInt(byte & 0x7f) << BigInt(index * 7);
    if ((byte & 0x80) === 0) return { value, next: cursor };
  }
  fail('ORIX_RESOURCE_VARINT_OVERFLOW', 'ResourceTable protobuf varint exceeds ten bytes', { label, offset: cursor });
}

function read_length(buffer, cursor, end, label) {
  const decoded = read_varint(buffer, cursor, end, label + ' length');
  const remaining = BigInt(end - decoded.next);
  if (decoded.value > remaining) {
    fail('ORIX_RESOURCE_LENGTH_RANGE', 'ResourceTable protobuf field exceeds its enclosing message', {
      label, offset: cursor, length: decoded.value.toString(), remaining: end - decoded.next,
    });
  }
  const size = Number(decoded.value);
  return { start: decoded.next, end: decoded.next + size, next: decoded.next + size };
}

function expect_wire(label, field, actual, expected) {
  if (actual !== expected) fail('ORIX_RESOURCE_WIRE_MISMATCH', label + ' has an unexpected protobuf wire type', { field, actual, expected });
}

function singular(seen, field, label) {
  if (seen.has(field)) fail('ORIX_RESOURCE_DUPLICATE_FIELD', label + ' contains a duplicate singular field', { field });
  seen.add(field);
}

function decode_string(buffer, value, label, budget, limits) {
  const size = value.end - value.start;
  if (size > limits.max_string_bytes || budget.string_bytes > limits.max_total_string_bytes - size) {
    fail('ORIX_RESOURCE_STRING_LIMIT', 'ResourceTable string budget exceeded', {
      label, size, total: budget.string_bytes, max_string_bytes: limits.max_string_bytes,
      max_total_string_bytes: limits.max_total_string_bytes,
    });
  }
  budget.string_bytes += size;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(value.start, value.end));
  } catch {
    fail('ORIX_RESOURCE_UTF8', 'ResourceTable string is not valid UTF-8', { label, offset: value.start, size });
  }
}

function enum_value(value, mapping) {
  const number = Number(BigInt.asIntN(32, value));
  return { value: number, name: Object.hasOwn(mapping, number) ? mapping[number] : 'UNKNOWN', known: Object.hasOwn(mapping, number) };
}

function add_output(array, item, budget) {
  if (budget.output_items >= budget.limits.max_output_items) {
    budget.items_omitted += 1;
    budget.output_truncated = true;
    return false;
  }
  array.push(item);
  budget.output_items += 1;
  return true;
}

function consume_item(budget, kind) {
  budget.items_seen += 1;
  budget.counts[kind] = (budget.counts[kind] ?? 0) + 1;
  if (budget.items_seen > budget.limits.max_items) {
    fail('ORIX_RESOURCE_ITEM_LIMIT', 'ResourceTable aggregate item limit exceeded', {
      kind, max_items: budget.limits.max_items,
    });
  }
}

function assert_depth(depth, budget, label) {
  if (depth > budget.limits.max_depth) {
    fail('ORIX_RESOURCE_DEPTH_LIMIT', 'ResourceTable protobuf nesting depth exceeded', {
      label, depth, max_depth: budget.limits.max_depth,
    });
  }
}

function walk_fields(buffer, start, end, budget, label, visitor) {
  let cursor = start;
  while (cursor < end) {
    budget.fields_seen += 1;
    if (budget.fields_seen > budget.limits.max_fields) {
      fail('ORIX_RESOURCE_FIELD_LIMIT', 'ResourceTable protobuf field-count limit exceeded', {
        label, max_fields: budget.limits.max_fields,
      });
    }
    const tag = read_varint(buffer, cursor, end, label + ' tag');
    cursor = tag.next;
    if (tag.value === 0n || tag.value > 0xffffffffn) {
      fail('ORIX_RESOURCE_FIELD_NUMBER', 'ResourceTable protobuf tag is outside the uint32 range', { label, tag: tag.value.toString() });
    }
    const field = Number(tag.value >> 3n);
    const wire = Number(tag.value & 7n);
    if (field < 1 || field > 0x1fffffff) fail('ORIX_RESOURCE_FIELD_NUMBER', 'Invalid ResourceTable protobuf field number', { label, field });
    let value;
    if (wire === 0) {
      const decoded = read_varint(buffer, cursor, end, label + ' field ' + field);
      value = decoded.value;
      cursor = decoded.next;
    } else if (wire === 1) {
      if (cursor > end - 8) fail('ORIX_RESOURCE_FIXED64_RANGE', 'Truncated ResourceTable fixed64 value', { label, field, cursor });
      value = { start: cursor, end: cursor + 8 };
      cursor += 8;
    } else if (wire === 2) {
      value = read_length(buffer, cursor, end, label + ' field ' + field);
      cursor = value.next;
    } else if (wire === 5) {
      if (cursor > end - 4) fail('ORIX_RESOURCE_FIXED32_RANGE', 'Truncated ResourceTable fixed32 value', { label, field, cursor });
      value = { start: cursor, end: cursor + 4 };
      cursor += 4;
    } else {
      fail('ORIX_RESOURCE_WIRE_TYPE', 'Unsupported ResourceTable protobuf wire type', { label, field, wire });
    }
    visitor(field, wire, value);
  }
  if (cursor !== end) fail('ORIX_RESOURCE_MESSAGE_RANGE', 'ResourceTable message did not end at its declared boundary', { label, cursor, end });
}

function opaque_message(buffer, value, budget, label, depth) {
  assert_depth(depth, budget, label);
  let field_count = 0;
  walk_fields(buffer, value.start, value.end, budget, label, () => { field_count += 1; budget.opaque_fields_skipped += 1; });
  return { field_count };
}

function parse_source_position(buffer, value, budget, depth) {
  assert_depth(depth, budget, 'SourcePosition');
  const result = { line_number: null, column_number: null };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'SourcePosition', (field, wire, raw) => {
    if (field === 1 || field === 2) {
      expect_wire('SourcePosition', field, wire, 0);
      singular(seen, field, 'SourcePosition');
      result[field === 1 ? 'line_number' : 'column_number'] = Number(raw);
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_source(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'Source');
  const result = { path_index: null, position: null };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'Source', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('Source', field, wire, 0);
      singular(seen, field, 'Source');
      result.path_index = Number(raw);
    } else if (field === 2) {
      expect_wire('Source', field, wire, 2);
      singular(seen, field, 'Source');
      result.position = parse_source_position(buffer, raw, budget, depth + 1);
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_package_id(buffer, value, budget, depth, label = 'PackageId') {
  assert_depth(depth, budget, label);
  const result = { id: null };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, label, (field, wire, raw) => {
    if (field === 1) {
      expect_wire(label, field, wire, 0);
      singular(seen, field, label);
      if (raw > 255n) fail('ORIX_RESOURCE_PACKAGE_ID_RANGE', 'Resource package ID exceeds 8 bits', { id: raw.toString() });
      result.id = Number(raw);
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_type_id(buffer, value, budget, depth) {
  assert_depth(depth, budget, 'TypeId');
  const result = { id: null };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'TypeId', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('TypeId', field, wire, 0);
      singular(seen, field, 'TypeId');
      if (raw > 255n) fail('ORIX_RESOURCE_TYPE_ID_RANGE', 'Resource type ID exceeds 8 bits', { id: raw.toString() });
      result.id = Number(raw);
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_entry_id(buffer, value, budget, depth) {
  assert_depth(depth, budget, 'EntryId');
  const result = { id: null };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'EntryId', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('EntryId', field, wire, 0);
      singular(seen, field, 'EntryId');
      if (raw > 65535n) fail('ORIX_RESOURCE_ENTRY_ID_RANGE', 'Resource entry ID exceeds 16 bits', { id: raw.toString() });
      result.id = Number(raw);
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_visibility(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'Visibility');
  const result = { level: enum_value(0n, VISIBILITY), source: null, comment: '', staged_api: false };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'Visibility', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('Visibility', field, wire, 0);
      singular(seen, field, 'Visibility');
      result.level = enum_value(raw, VISIBILITY);
    } else if (field === 2) {
      expect_wire('Visibility', field, wire, 2);
      singular(seen, field, 'Visibility');
      result.source = parse_source(buffer, raw, budget, limits, depth + 1);
    } else if (field === 3) {
      expect_wire('Visibility', field, wire, 2);
      singular(seen, field, 'Visibility');
      result.comment = decode_string(buffer, raw, 'Visibility.comment', budget, budget.limits);
    } else if (field === 4) {
      expect_wire('Visibility', field, wire, 0);
      singular(seen, field, 'Visibility');
      result.staged_api = raw !== 0n;
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_reference(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'Reference');
  const result = { type: enum_value(0n, REFERENCE_TYPE), resource_id: null, name: '', private: false, dynamic: false, type_flags: 0, allow_raw: false };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'Reference', (field, wire, raw) => {
    if (field === 1 || field === 2 || field === 4 || field === 6 || field === 7) {
      expect_wire('Reference', field, wire, 0);
      singular(seen, field, 'Reference');
      if (field === 1) result.type = enum_value(raw, REFERENCE_TYPE);
      if (field === 2) result.resource_id = Number(raw);
      if (field === 4) result.private = raw !== 0n;
      if (field === 6) result.type_flags = Number(raw);
      if (field === 7) result.allow_raw = raw !== 0n;
    } else if (field === 3) {
      expect_wire('Reference', field, wire, 2);
      singular(seen, field, 'Reference');
      result.name = decode_string(buffer, raw, 'Reference.name', budget, limits);
    } else if (field === 5) {
      expect_wire('Reference', field, wire, 2);
      singular(seen, field, 'Reference');
      let dynamic = false;
      const dynamic_seen = new Set();
      walk_fields(buffer, raw.start, raw.end, budget, 'Reference.is_dynamic', (f, w, v) => {
        if (f === 1) {
          expect_wire('Reference.is_dynamic', f, w, 0);
          singular(dynamic_seen, f, 'Reference.is_dynamic');
          dynamic = v !== 0n;
        } else budget.unknown_fields += 1;
      });
      result.dynamic = dynamic;
    } else budget.unknown_fields += 1;
  });
  if (result.resource_id === null && !result.name) {
    fail('ORIX_RESOURCE_REFERENCE_EMPTY', 'Resource reference has neither an ID nor a name');
  }
  return result;
}

function parse_primitive(buffer, value, budget, depth) {
  assert_depth(depth, budget, 'Primitive');
  const kinds = {
    1: 'null', 2: 'empty', 3: 'float', 4: 'dimension_deprecated',
    5: 'fraction_deprecated', 6: 'int_decimal', 7: 'int_hexadecimal',
    8: 'boolean', 9: 'color_argb8', 10: 'color_rgb8', 11: 'color_argb4',
    12: 'color_rgb4', 13: 'dimension', 14: 'fraction',
  };
  let selected = null;
  const seen = new Set();
  let selected_field = null;
  walk_fields(buffer, value.start, value.end, budget, 'Primitive', (field, wire, raw) => {
    if (field >= 1 && field <= 14) {
      const expected = field === 3 || field === 4 || field === 5 ? 5 : field === 1 || field === 2 ? 2 : 0;
      expect_wire('Primitive', field, wire, expected);
      if (selected_field !== null) fail('ORIX_RESOURCE_ONEOF_DUPLICATE', 'Primitive has more than one concrete oneof value', { first: selected_field, second: field });
      selected_field = field;
      singular(seen, field, 'Primitive.oneof_value');
      selected = { kind: kinds[field], value: null };
      if (wire === 0) selected.value = field === 6 ? Number(BigInt.asIntN(32, raw)) : field === 8 ? raw !== 0n : Number(raw);
      if (wire === 5) selected.value = buffer.readFloatLE(raw.start);
      if (wire === 2 && raw.start !== raw.end) fail('ORIX_RESOURCE_PRIMITIVE_EMPTY_TYPE', 'Primitive null/empty marker must be an empty message', { field });
    } else budget.unknown_fields += 1;
  });
  return selected;
}

function parse_item(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'Item');
  const result = { kind: null, value: null, flag_status: 0, flag_negated: false, flag_name: '' };
  const seen = new Set();
  let oneof_field = null;
  walk_fields(buffer, value.start, value.end, budget, 'Item', (field, wire, raw) => {
    if (field >= 1 && field <= 7) {
      expect_wire('Item', field, wire, 2);
      if (oneof_field !== null) fail('ORIX_RESOURCE_ONEOF_DUPLICATE', 'Item has more than one concrete oneof value', { first: oneof_field, second: field });
      oneof_field = field;
      singular(seen, field, 'Item.oneof_value');
      const kinds = { 1: 'reference', 2: 'string', 3: 'raw_string', 4: 'styled_string', 5: 'file', 6: 'id', 7: 'primitive' };
      result.kind = kinds[field];
      if (field === 1) {
        result.value = parse_reference(buffer, raw, budget, limits, depth + 1);
        budget.counts.direct_references += 1;
      }
      else if (field === 2 || field === 3) {
        const seen_string = new Set();
        let string_value = '';
        walk_fields(buffer, raw.start, raw.end, budget, 'Item.' + kinds[field], (f, w, v) => {
          if (f === 1) {
            expect_wire('Item.' + kinds[field], f, w, 2);
            singular(seen_string, f, 'Item.' + kinds[field]);
            string_value = decode_string(buffer, v, 'Item.' + kinds[field] + '.value', budget, limits);
          } else budget.unknown_fields += 1;
        });
        result.value = string_value;
      } else if (field === 4) {
        let text = '';
        let spans = 0;
        const nested_seen = new Set();
        walk_fields(buffer, raw.start, raw.end, budget, 'StyledString', (f, w, v) => {
          if (f === 1) {
            expect_wire('StyledString', f, w, 2);
            singular(nested_seen, f, 'StyledString');
            text = decode_string(buffer, v, 'StyledString.value', budget, limits);
          } else if (f === 2) {
            expect_wire('StyledString', f, w, 2);
            consume_item(budget, 'styled_spans');
            spans += 1;
            opaque_message(buffer, v, budget, 'StyledString.Span', depth + 1);
          } else budget.unknown_fields += 1;
        });
        result.value = { text, span_count: spans };
      } else if (field === 5) {
        const file = { path: '', type: enum_value(0n, FILE_TYPE) };
        const nested_seen = new Set();
        walk_fields(buffer, raw.start, raw.end, budget, 'FileReference', (f, w, v) => {
          if (f === 1) {
            expect_wire('FileReference', f, w, 2);
            singular(nested_seen, f, 'FileReference');
            file.path = decode_string(buffer, v, 'FileReference.path', budget, limits);
          } else if (f === 2) {
            expect_wire('FileReference', f, w, 0);
            singular(nested_seen, f, 'FileReference');
            file.type = enum_value(v, FILE_TYPE);
          } else budget.unknown_fields += 1;
        });
        result.value = file;
      } else if (field === 6) {
        result.value = { placeholder: true };
        opaque_message(buffer, raw, budget, 'Item.Id', depth + 1);
      } else result.value = parse_primitive(buffer, raw, budget, depth + 1);
    } else if (field === 8 || field === 9) {
      expect_wire('Item', field, wire, 0);
      singular(seen, field, 'Item');
      if (field === 8) result.flag_status = Number(raw);
      else result.flag_negated = raw !== 0n;
    } else if (field === 10) {
      expect_wire('Item', field, wire, 2);
      singular(seen, field, 'Item');
      result.flag_name = decode_string(buffer, raw, 'Item.flag_name', budget, limits);
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_value(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'Value');
  const result = { comment: '', weak: false, kind: null, item: null, compound_kind: null };
  const seen = new Set();
  let oneof_field = null;
  walk_fields(buffer, value.start, value.end, budget, 'Value', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('Value', field, wire, 2);
      singular(seen, field, 'Value');
      result.source = parse_source(buffer, raw, budget, limits, depth + 1);
    } else if (field === 2) {
      expect_wire('Value', field, wire, 2);
      singular(seen, field, 'Value');
      result.comment = decode_string(buffer, raw, 'Value.comment', budget, limits);
    } else if (field === 3) {
      expect_wire('Value', field, wire, 0);
      singular(seen, field, 'Value');
      result.weak = raw !== 0n;
    } else if (field === 4 || field === 5) {
      expect_wire('Value', field, wire, 2);
      if (oneof_field !== null) fail('ORIX_RESOURCE_ONEOF_DUPLICATE', 'Value has more than one concrete oneof value', { first: oneof_field, second: field });
      oneof_field = field;
      singular(seen, field, 'Value.oneof_value');
      if (field === 4) {
        const item = parse_item(buffer, raw, budget, limits, depth + 1);
        result.kind = 'item:' + (item.kind ?? 'unknown');
        result.item = item;
      } else {
        const names = { 1: 'attribute', 2: 'style', 3: 'styleable', 4: 'array', 5: 'plural', 6: 'macro' };
        let nested_fields = 0;
        const nested = [];
        let selected = null;
        walk_fields(buffer, raw.start, raw.end, budget, 'CompoundValue', (f, w, v) => {
          nested_fields += 1;
          if (f >= 1 && f <= 6) {
            expect_wire('CompoundValue', f, w, 2);
            if (selected !== null) fail('ORIX_RESOURCE_ONEOF_DUPLICATE', 'CompoundValue has more than one concrete value', { first: selected, second: f });
            selected = names[f] ?? 'unknown';
            nested.push({ field: f, kind: selected, framing_fields: opaque_message(buffer, v, budget, 'CompoundValue.' + selected, depth + 2).field_count });
          } else budget.unknown_fields += 1;
        });
        result.kind = 'compound:' + (selected ?? 'unknown');
        result.compound_kind = selected;
        result.compound_field_count = nested_fields;
        if (selected) budget.compound_value_kinds[selected] = (budget.compound_value_kinds[selected] ?? 0) + 1;
        result.compound_metadata = nested;
      }
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_configuration(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'Configuration');
  const fields = {
    1: 'mcc', 2: 'mnc', 3: 'locale', 4: 'layout_direction', 5: 'screen_width',
    6: 'screen_height', 7: 'screen_width_dp', 8: 'screen_height_dp',
    9: 'smallest_screen_width_dp', 10: 'screen_layout_size', 11: 'screen_layout_long',
    12: 'screen_round', 13: 'wide_color_gamut', 14: 'hdr', 15: 'orientation',
    16: 'ui_mode_type', 17: 'ui_mode_night', 18: 'density', 19: 'touchscreen',
    20: 'keys_hidden', 21: 'keyboard', 22: 'nav_hidden', 23: 'navigation',
    24: 'sdk_version', 25: 'product', 26: 'grammatical_gender',
  };
  const result = {};
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'Configuration', (field, wire, raw) => {
    const name = fields[field];
    if (!name) { budget.unknown_fields += 1; return; }
    const string_field = field === 3 || field === 25;
    expect_wire('Configuration', field, wire, string_field ? 2 : 0);
    singular(seen, field, 'Configuration');
    if (string_field) result[name] = decode_string(buffer, raw, 'Configuration.' + name, budget, limits);
    else if (CONFIG_ENUMS[name]) result[name] = enum_value(raw, CONFIG_ENUMS[name]);
    else result[name] = Number(raw);
  });
  return result;
}

function parse_config_value(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'ConfigValue');
  const result = { configuration: {}, value: null };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'ConfigValue', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('ConfigValue', field, wire, 2);
      singular(seen, field, 'ConfigValue');
      result.configuration = parse_configuration(buffer, raw, budget, limits, depth + 1);
    } else if (field === 2) {
      expect_wire('ConfigValue', field, wire, 2);
      singular(seen, field, 'ConfigValue');
      result.value = parse_value(buffer, raw, budget, limits, depth + 1);
    } else budget.unknown_fields += 1;
  });
  if (!seen.has(2)) fail('ORIX_RESOURCE_VARIANT_VALUE_MISSING', 'ConfigValue is missing its Value message');
  return result;
}

function parse_allow_new(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'AllowNew');
  const result = { source: null, comment: '' };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'AllowNew', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('AllowNew', field, wire, 2);
      singular(seen, field, 'AllowNew');
      result.source = parse_source(buffer, raw, budget, limits, depth + 1);
    } else if (field === 2) {
      expect_wire('AllowNew', field, wire, 2);
      singular(seen, field, 'AllowNew');
      result.comment = decode_string(buffer, raw, 'AllowNew.comment', budget, limits);
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_overlayable_item(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'OverlayableItem');
  const result = { policies: [], overlayable_index: null, comment: '', source: null };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'OverlayableItem', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('OverlayableItem', field, wire, 2);
      singular(seen, field, 'OverlayableItem');
      result.source = parse_source(buffer, raw, budget, limits, depth + 1);
    } else if (field === 2) {
      expect_wire('OverlayableItem', field, wire, 2);
      singular(seen, field, 'OverlayableItem');
      result.comment = decode_string(buffer, raw, 'OverlayableItem.comment', budget, limits);
    } else if (field === 3 && wire === 0) {
      consume_item(budget, 'overlay_policies');
      add_output(result.policies, enum_value(raw, OVERLAY_POLICY), budget);
    } else if (field === 3 && wire === 2) {
      let cursor = raw.start;
      while (cursor < raw.end) {
        const decoded = read_varint(buffer, cursor, raw.end, 'OverlayableItem.policy');
        cursor = decoded.next;
        consume_item(budget, 'overlay_policies');
        add_output(result.policies, enum_value(decoded.value, OVERLAY_POLICY), budget);
      }
    } else if (field === 4) {
      expect_wire('OverlayableItem', field, wire, 0);
      singular(seen, field, 'OverlayableItem');
      result.overlayable_index = Number(raw);
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_staged_id(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'StagedId');
  const result = { source: null, staged_id: null };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'StagedId', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('StagedId', field, wire, 2);
      singular(seen, field, 'StagedId');
      result.source = parse_source(buffer, raw, budget, limits, depth + 1);
    } else if (field === 2) {
      expect_wire('StagedId', field, wire, 0);
      singular(seen, field, 'StagedId');
      result.staged_id = Number(raw);
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_entry(buffer, value, budget, limits, depth, package_id, type_id) {
  assert_depth(depth, budget, 'Entry');
  consume_item(budget, 'entries');
  const result = {
    entry_id: null, name: '', visibility: null, allow_new: null, overlayable_item: null,
    config_values: [], flag_disabled_config_values: [], staged_id: null, resource_id: null,
    value_kind_counts: {},
  };
  const seen = new Set();
  const process_variants = (raw, disabled) => {
    consume_item(budget, disabled ? 'disabled_variants' : 'variants');
    const parsed = parse_config_value(buffer, raw, budget, limits, depth + 1);
    const kind = parsed.value?.kind ?? 'unknown';
    result.value_kind_counts[kind] = (result.value_kind_counts[kind] ?? 0) + 1;
    add_output(disabled ? result.flag_disabled_config_values : result.config_values, parsed, budget);
  };
  walk_fields(buffer, value.start, value.end, budget, 'Entry', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('Entry', field, wire, 2);
      singular(seen, field, 'Entry');
      result.entry_id = parse_entry_id(buffer, raw, budget, depth + 1);
    } else if (field === 2) {
      expect_wire('Entry', field, wire, 2);
      singular(seen, field, 'Entry');
      result.name = decode_string(buffer, raw, 'Entry.name', budget, limits);
    } else if (field === 3) {
      expect_wire('Entry', field, wire, 2);
      singular(seen, field, 'Entry');
      result.visibility = parse_visibility(buffer, raw, budget, limits, depth + 1);
    } else if (field === 4) {
      expect_wire('Entry', field, wire, 2);
      singular(seen, field, 'Entry');
      result.allow_new = parse_allow_new(buffer, raw, budget, limits, depth + 1);
    } else if (field === 5) {
      expect_wire('Entry', field, wire, 2);
      singular(seen, field, 'Entry');
      result.overlayable_item = parse_overlayable_item(buffer, raw, budget, limits, depth + 1);
    } else if (field === 6) {
      expect_wire('Entry', field, wire, 2);
      process_variants(raw, false);
    } else if (field === 7) {
      expect_wire('Entry', field, wire, 2);
      singular(seen, field, 'Entry');
      result.staged_id = parse_staged_id(buffer, raw, budget, limits, depth + 1);
    } else if (field === 8) {
      expect_wire('Entry', field, wire, 2);
      process_variants(raw, true);
    } else budget.unknown_fields += 1;
  });
  const entry = result.entry_id?.id ?? null;
  if (package_id !== null && type_id !== null && entry !== null) {
    result.resource_id = '0x' + (((package_id << 24) | (type_id << 16) | entry) >>> 0).toString(16).padStart(8, '0');
  }
  if (!result.name && entry === null) fail('ORIX_RESOURCE_ENTRY_IDENTITY', 'Resource entry has neither an ID nor a name');
  return result;
}

function parse_type(buffer, value, budget, limits, depth, package_id) {
  assert_depth(depth, budget, 'Type');
  consume_item(budget, 'types');
  const result = { type_id: null, name: '', entries: [], entry_count: 0 };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'Type', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('Type', field, wire, 2);
      singular(seen, field, 'Type');
      result.type_id = parse_type_id(buffer, raw, budget, depth + 1);
    } else if (field === 2) {
      expect_wire('Type', field, wire, 2);
      singular(seen, field, 'Type');
      result.name = decode_string(buffer, raw, 'Type.name', budget, limits);
    } else if (field === 3) {
      expect_wire('Type', field, wire, 2);
      result.entry_count += 1;
      const parsed = parse_entry(buffer, raw, budget, limits, depth + 1, package_id, result.type_id?.id ?? null);
      add_output(result.entries, parsed, budget);
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_package(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'Package');
  consume_item(budget, 'packages');
  const result = { package_id: null, name: '', types: [], type_count: 0 };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'Package', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('Package', field, wire, 2);
      singular(seen, field, 'Package');
      result.package_id = parse_package_id(buffer, raw, budget, depth + 1).id;
    } else if (field === 2) {
      expect_wire('Package', field, wire, 2);
      singular(seen, field, 'Package');
      result.name = decode_string(buffer, raw, 'Package.package_name', budget, limits);
    } else if (field === 3) {
      expect_wire('Package', field, wire, 2);
      result.type_count += 1;
      add_output(result.types, parse_type(buffer, raw, budget, limits, depth + 1, result.package_id), budget);
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_overlayable(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'Overlayable');
  const result = { name: '', actor: '', source: null };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'Overlayable', (field, wire, raw) => {
    if (field === 1 || field === 3) {
      expect_wire('Overlayable', field, wire, 2);
      singular(seen, field, 'Overlayable');
      result[field === 1 ? 'name' : 'actor'] = decode_string(buffer, raw, 'Overlayable.' + field, budget, limits);
    } else if (field === 2) {
      expect_wire('Overlayable', field, wire, 2);
      singular(seen, field, 'Overlayable');
      result.source = parse_source(buffer, raw, budget, limits, depth + 1);
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_tool_fingerprint(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'ToolFingerprint');
  const result = { tool: '', version: '' };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'ToolFingerprint', (field, wire, raw) => {
    if (field === 1 || field === 2) {
      expect_wire('ToolFingerprint', field, wire, 2);
      singular(seen, field, 'ToolFingerprint');
      result[field === 1 ? 'tool' : 'version'] = decode_string(buffer, raw, 'ToolFingerprint.' + field, budget, limits);
    } else budget.unknown_fields += 1;
  });
  return result;
}

function parse_dynamic_ref_table(buffer, value, budget, limits, depth) {
  assert_depth(depth, budget, 'DynamicRefTable');
  const result = { package_id: null, package_name: '' };
  const seen = new Set();
  walk_fields(buffer, value.start, value.end, budget, 'DynamicRefTable', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('DynamicRefTable', field, wire, 2);
      singular(seen, field, 'DynamicRefTable');
      result.package_id = parse_package_id(buffer, raw, budget, depth + 1).id;
    } else if (field === 2) {
      expect_wire('DynamicRefTable', field, wire, 2);
      singular(seen, field, 'DynamicRefTable');
      result.package_name = decode_string(buffer, raw, 'DynamicRefTable.package_name', budget, limits);
    } else budget.unknown_fields += 1;
  });
  // Protobuf field order is arbitrary. Compute stable resource IDs only after
  // the package and all type IDs have been parsed.
  for (const type of result.types) {
    for (const entry of type.entries) {
      const package_id = result.package_id;
      const type_id = type.type_id?.id ?? null;
      const entry_id = entry.entry_id?.id ?? null;
      if (package_id !== null && type_id !== null && entry_id !== null) {
        entry.resource_id = '0x' + (((package_id << 24) | (type_id << 16) | entry_id) >>> 0).toString(16).padStart(8, '0');
      }
    }
  }
  return result;
}

/**
 * Decode bounded AAPT2 ResourceTable package/type/entry indexes and value summaries.
 * StringPool bytes remain opaque: source path indexes are retained, not resolved.
 */
export function parse_android_resource_table(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('Android ResourceTable input must be a Buffer');
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Android ResourceTable options must be an object');
  const limits = {
    max_file_bytes: options.max_file_bytes ?? 16 * 1024 * 1024,
    max_fields: options.max_fields ?? 500_000,
    max_items: options.max_items ?? 100_000,
    max_depth: options.max_depth ?? 48,
    max_string_bytes: options.max_string_bytes ?? 64 * 1024,
    max_total_string_bytes: options.max_total_string_bytes ?? 8 * 1024 * 1024,
    max_output_items: options.max_output_items ?? 5000,
  };
  integer_limit('max_file_bytes', limits.max_file_bytes, 1, 64 * 1024 * 1024);
  integer_limit('max_fields', limits.max_fields, 1, 2_000_000);
  integer_limit('max_items', limits.max_items, 1, 500_000);
  integer_limit('max_depth', limits.max_depth, 1, 96);
  integer_limit('max_string_bytes', limits.max_string_bytes, 1, 1024 * 1024);
  integer_limit('max_total_string_bytes', limits.max_total_string_bytes, 1, 32 * 1024 * 1024);
  integer_limit('max_output_items', limits.max_output_items, 1, 50_000);
  if (buffer.length > limits.max_file_bytes) {
    fail('ORIX_RESOURCE_FILE_LIMIT', 'ResourceTable exceeds the configured file-size limit', { actual: buffer.length, max_file_bytes: limits.max_file_bytes });
  }

  const budget = {
    limits, fields_seen: 0, items_seen: 0, output_items: 0, items_omitted: 0,
    string_bytes: 0, unknown_fields: 0, opaque_fields_skipped: 0, output_truncated: false,
    compound_value_kinds: {},
    counts: { packages: 0, types: 0, entries: 0, variants: 0, disabled_variants: 0, styled_spans: 0, overlay_policies: 0, direct_references: 0 },
  };
  const result = {
    schema_version: 'orix.android-resource-table.v1',
    source_pool: null,
    packages: [],
    overlayables: [],
    tool_fingerprints: [],
    dynamic_ref_tables: [],
    summary: null,
    coverage: null,
    notes: [
      'Package, type, entry, ID, visibility, configuration variant and top-level value-kind metadata are decoded from AAPT2 ResourceTable.',
      'Direct Item references, strings and file-reference paths are inventoried where recognized; numeric resource IDs are preserved, not resolved to runtime values.',
      'StringPool.data is retained as a SHA-256/size receipt. Its Android ResStringPool binary contents and Source.path_index values are not decoded or resolved.',
      'Compound values are reported by concrete kind and bounded field framing; nested styles, arrays, plurals, attributes, styleables and macros are not semantically expanded.',
      'Unknown protobuf fields are wire-validated, skipped and counted. This is offline metadata analysis, not resource installation or device-specific resource selection.',
    ],
  };
  const seen = new Set();
  walk_fields(buffer, 0, buffer.length, budget, 'ResourceTable', (field, wire, raw) => {
    if (field === 1) {
      expect_wire('ResourceTable', field, wire, 2);
      singular(seen, field, 'ResourceTable');
      let data = null;
      const string_pool_seen = new Set();
      walk_fields(buffer, raw.start, raw.end, budget, 'StringPool', (f, w, v) => {
        if (f === 1) {
          expect_wire('StringPool', f, w, 2);
          singular(string_pool_seen, f, 'StringPool');
          const bytes = buffer.subarray(v.start, v.end);
          data = { size_bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), decoded: false };
        } else budget.unknown_fields += 1;
      });
      result.source_pool = data ?? { size_bytes: 0, sha256: null, decoded: false };
    } else if (field === 2) {
      expect_wire('ResourceTable', field, wire, 2);
      const pkg = parse_package(buffer, raw, budget, limits, 1);
      add_output(result.packages, pkg, budget);
    } else if (field === 3) {
      expect_wire('ResourceTable', field, wire, 2);
      consume_item(budget, 'overlayables');
      add_output(result.overlayables, parse_overlayable(buffer, raw, budget, limits, 1), budget);
    } else if (field === 4) {
      expect_wire('ResourceTable', field, wire, 2);
      consume_item(budget, 'tool_fingerprints');
      add_output(result.tool_fingerprints, parse_tool_fingerprint(buffer, raw, budget, limits, 1), budget);
    } else if (field === 5) {
      expect_wire('ResourceTable', field, wire, 2);
      consume_item(budget, 'dynamic_ref_tables');
      add_output(result.dynamic_ref_tables, parse_dynamic_ref_table(buffer, raw, budget, limits, 1), budget);
    } else budget.unknown_fields += 1;
  });

  result.summary = {
    package_count: budget.counts.packages,
    type_count: budget.counts.types,
    entry_count: budget.counts.entries,
    variant_count: budget.counts.variants,
    disabled_variant_count: budget.counts.disabled_variants,
    direct_references: budget.counts.direct_references,
    compound_value_kinds: budget.compound_value_kinds,
  };
  result.coverage = {
    fields_seen: budget.fields_seen,
    items_seen: budget.items_seen,
    items_reported: budget.output_items,
    items_omitted: budget.items_omitted,
    unknown_fields: budget.unknown_fields,
    opaque_fields_skipped: budget.opaque_fields_skipped,
    string_bytes: budget.string_bytes,
    output_truncated: budget.output_truncated,
    counts: budget.counts,
  };
  result.summary.output_truncated = budget.output_truncated;
  return result;
}
