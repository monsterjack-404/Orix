// Bounded structural inventory for AAPT2 resources.pb ResourceTable messages.
// This parser inventories declarations and selected value/configuration metadata only.
// It does not resolve resource references, decode compiled resource files or build APKs.

const ITEM_KINDS = {
  1: 'reference',
  2: 'string',
  3: 'raw-string',
  4: 'styled-string',
  5: 'file',
  6: 'id',
  7: 'primitive',
};
const COMPOUND_KINDS = {
  1: 'attribute',
  2: 'style',
  3: 'styleable',
  4: 'array',
  5: 'plural',
  6: 'macro',
};
const VISIBILITY = { 0: 'unknown', 1: 'private', 2: 'public' };
const CONFIG_FIELDS = {
  1: 'mcc',
  2: 'mnc',
  4: 'layout_direction',
  5: 'screen_width',
  6: 'screen_height',
  7: 'screen_width_dp',
  8: 'screen_height_dp',
  9: 'smallest_screen_width_dp',
  10: 'screen_layout_size',
  11: 'screen_layout_long',
  12: 'screen_round',
  13: 'wide_color_gamut',
  14: 'hdr',
  15: 'orientation',
  16: 'ui_mode_type',
  17: 'ui_mode_night',
  18: 'density',
  19: 'touchscreen',
  20: 'keys_hidden',
  21: 'keyboard',
  22: 'nav_hidden',
  23: 'navigation',
  24: 'sdk_version',
  26: 'grammatical_gender',
};

function fail(code, message, details = {}) {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  throw error;
}

function bounded_integer(name, value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(name + ' must be an integer between ' + minimum + ' and ' + maximum);
  }
  return value;
}

function read_varint(buffer, cursor, end, label) {
  let value = 0n;
  for (let index = 0; index < 10; index += 1) {
    if (cursor >= end) fail('ORIX_RESOURCE_TABLE_VARINT_TRUNCATED', 'Truncated ResourceTable protobuf varint', { label, offset: cursor });
    const byte = buffer[cursor++];
    if (index === 9 && (byte & 0xfe) !== 0) {
      fail('ORIX_RESOURCE_TABLE_VARINT_OVERFLOW', 'ResourceTable protobuf varint exceeds 64 bits', { label, offset: cursor - 1 });
    }
    value |= BigInt(byte & 0x7f) << BigInt(index * 7);
    if ((byte & 0x80) === 0) return { value, next: cursor };
  }
  fail('ORIX_RESOURCE_TABLE_VARINT_OVERFLOW', 'ResourceTable protobuf varint is unterminated or exceeds 64 bits', { label, offset: cursor });
}

function read_length(buffer, cursor, end, label) {
  const decoded = read_varint(buffer, cursor, end, label + ' length');
  const remaining = BigInt(end - decoded.next);
  if (decoded.value > remaining) {
    fail('ORIX_RESOURCE_TABLE_LENGTH_RANGE', 'ResourceTable field length exceeds its enclosing message', {
      label, offset: cursor, length: decoded.value.toString(), remaining: end - decoded.next,
    });
  }
  const size = Number(decoded.value);
  return { start: decoded.next, end: decoded.next + size, next: decoded.next + size };
}

function uint32(value, label) {
  if (typeof value !== 'bigint' || value < 0n || value > 0xffffffffn) {
    fail('ORIX_RESOURCE_TABLE_UINT32', 'ResourceTable field is outside the uint32 range', { label, value: String(value) });
  }
  return Number(value);
}

function decode_string(buffer, range, label, budget, limits) {
  const size = range.end - range.start;
  if (size > limits.max_string_bytes || budget.string_bytes > limits.max_total_string_bytes - size) {
    fail('ORIX_RESOURCE_TABLE_STRING_LIMIT', 'ResourceTable string budget exceeded', {
      label, size, total: budget.string_bytes,
      max_string_bytes: limits.max_string_bytes,
      max_total_string_bytes: limits.max_total_string_bytes,
    });
  }
  budget.string_bytes += size;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(range.start, range.end));
  } catch {
    fail('ORIX_RESOURCE_TABLE_UTF8', 'ResourceTable string is not valid UTF-8', { label, offset: range.start, size });
  }
}

function assert_depth(depth, limits, label) {
  if (depth > limits.max_depth) {
    fail('ORIX_RESOURCE_TABLE_DEPTH_LIMIT', 'ResourceTable protobuf nesting depth exceeds the configured limit', {
      label, depth, max_depth: limits.max_depth,
    });
  }
}

function consume_item(budget, limits, label) {
  budget.items_seen += 1;
  if (budget.items_seen > limits.max_items) {
    fail('ORIX_RESOURCE_TABLE_ITEM_LIMIT', 'ResourceTable repeated-item limit exceeded', {
      label, items_seen: budget.items_seen, max_items: limits.max_items,
    });
  }
}

function add_output(array, value, budget) {
  if (budget.output_items >= budget.limits.max_output_items) {
    budget.items_omitted += 1;
    budget.output_truncated = true;
    return false;
  }
  array.push(value);
  budget.output_items += 1;
  return true;
}

function walk_fields(buffer, start, end, budget, visitor, label) {
  let cursor = start;
  while (cursor < end) {
    budget.fields_seen += 1;
    if (budget.fields_seen > budget.limits.max_fields) {
      fail('ORIX_RESOURCE_TABLE_FIELD_LIMIT', 'ResourceTable protobuf field-count limit exceeded', {
        fields_seen: budget.fields_seen, max_fields: budget.limits.max_fields,
      });
    }
    const tag = read_varint(buffer, cursor, end, label + ' tag');
    cursor = tag.next;
    if (tag.value === 0n || tag.value > 0xffffffffn) {
      fail('ORIX_RESOURCE_TABLE_FIELD_NUMBER', 'ResourceTable protobuf tag is outside the uint32 range', {
        label, tag: tag.value.toString(),
      });
    }
    const field_number = Number(tag.value >> 3n);
    const wire_type = Number(tag.value & 7n);
    if (field_number < 1 || field_number > 0x1fffffff) {
      fail('ORIX_RESOURCE_TABLE_FIELD_NUMBER', 'ResourceTable protobuf field number is invalid', { label, field_number });
    }
    let value;
    if (wire_type === 0) {
      const decoded = read_varint(buffer, cursor, end, label + ' field ' + field_number);
      value = decoded.value;
      cursor = decoded.next;
    } else if (wire_type === 1) {
      if (cursor > end - 8) fail('ORIX_RESOURCE_TABLE_FIXED64_RANGE', 'Truncated ResourceTable fixed64 field', { label, field_number, offset: cursor });
      value = { start: cursor, end: cursor + 8 };
      cursor += 8;
    } else if (wire_type === 2) {
      value = read_length(buffer, cursor, end, label + ' field ' + field_number);
      cursor = value.next;
    } else if (wire_type === 5) {
      if (cursor > end - 4) fail('ORIX_RESOURCE_TABLE_FIXED32_RANGE', 'Truncated ResourceTable fixed32 field', { label, field_number, offset: cursor });
      value = { start: cursor, end: cursor + 4 };
      cursor += 4;
    } else {
      fail('ORIX_RESOURCE_TABLE_WIRE_TYPE', 'Unsupported ResourceTable protobuf wire type', { label, field_number, wire_type });
    }
    visitor(field_number, wire_type, value);
  }
  if (cursor !== end) {
    fail('ORIX_RESOURCE_TABLE_MESSAGE_RANGE', 'ResourceTable message did not end at its declared boundary', { label, cursor, end });
  }
}

function expect_wire(label, field, actual, expected) {
  if (actual !== expected) {
    fail('ORIX_RESOURCE_TABLE_WIRE_MISMATCH', 'ResourceTable field has an unexpected wire type', {
      label, field, expected, actual,
    });
  }
}

function singular(seen, field, label) {
  if (seen.has(field)) {
    fail('ORIX_RESOURCE_TABLE_DUPLICATE_FIELD', 'Duplicate singular ResourceTable field', { label, field });
  }
  seen.add(field);
}

function parse_id_message(buffer, start, end, budget, label, maximum, minimum = 0) {
  let id = null;
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire(label, field, wire, 0);
      singular(seen, field, label);
      id = uint32(value, label + '.id');
      if (id < minimum || id > maximum) {
        fail('ORIX_RESOURCE_TABLE_ID_RANGE', label + ' identifier is outside its format range', { id, minimum, maximum });
      }
    } else {
      budget.unknown_fields += 1;
    }
  }, label);
  return id;
}

function read_pool_length_u8(bytes, cursor, end, label) {
  if (cursor >= end) fail('ORIX_RESOURCE_TABLE_STRING_POOL_LENGTH', 'Truncated UTF-8 string-pool length', { label, cursor, end });
  const first = bytes[cursor++];
  if ((first & 0x80) === 0) return { value: first, next: cursor };
  if (cursor >= end) fail('ORIX_RESOURCE_TABLE_STRING_POOL_LENGTH', 'Truncated two-byte UTF-8 string-pool length', { label, cursor, end });
  return { value: ((first & 0x7f) << 8) | bytes[cursor], next: cursor + 1 };
}

function read_pool_length_u16(bytes, cursor, end, label) {
  if (cursor > end - 2) fail('ORIX_RESOURCE_TABLE_STRING_POOL_LENGTH', 'Truncated UTF-16 string-pool length', { label, cursor, end });
  const first = bytes.readUInt16LE(cursor);
  cursor += 2;
  if ((first & 0x8000) === 0) return { value: first, next: cursor };
  if (cursor > end - 2) fail('ORIX_RESOURCE_TABLE_STRING_POOL_LENGTH', 'Truncated extended UTF-16 string-pool length', { label, cursor, end });
  const second = bytes.readUInt16LE(cursor);
  return { value: ((first & 0x7fff) * 0x10000) + second, next: cursor + 2 };
}

function charge_pool_string(size, budget, limits, label) {
  if (!Number.isSafeInteger(size) || size > limits.max_string_bytes ||
      budget.string_bytes > limits.max_total_string_bytes - size) {
    fail('ORIX_RESOURCE_TABLE_STRING_LIMIT', 'ResourceTable source-pool string budget exceeded', {
      label, size, total: budget.string_bytes,
      max_string_bytes: limits.max_string_bytes,
      max_total_string_bytes: limits.max_total_string_bytes,
    });
  }
  budget.string_bytes += size;
}

function decode_pool_string(bytes, offset, string_end, utf8, budget, limits, index) {
  let cursor = offset;
  if (cursor < 0 || cursor >= string_end) {
    fail('ORIX_RESOURCE_TABLE_STRING_POOL_OFFSET', 'ResourceTable source-pool string offset is outside the string data region', {
      index, offset, strings_start: 0, string_end,
    });
  }
  const utf16_length = utf8
    ? read_pool_length_u8(bytes, cursor, string_end, 'string[' + index + '] UTF-16 length')
    : read_pool_length_u16(bytes, cursor, string_end, 'string[' + index + '] UTF-16 length');
  cursor = utf16_length.next;
  let decoded;
  if (utf8) {
    const byte_length = read_pool_length_u8(bytes, cursor, string_end, 'string[' + index + '] UTF-8 length');
    cursor = byte_length.next;
    charge_pool_string(byte_length.value, budget, limits, 'source_pool[' + index + ']');
    if (byte_length.value > string_end - cursor - 1) {
      fail('ORIX_RESOURCE_TABLE_STRING_POOL_RANGE', 'UTF-8 source-pool string exceeds its data region', {
        index, byte_length: byte_length.value, cursor, string_end,
      });
    }
    const terminator = cursor + byte_length.value;
    if (bytes[terminator] !== 0) {
      fail('ORIX_RESOURCE_TABLE_STRING_POOL_TERMINATOR', 'UTF-8 source-pool string is not null-terminated', { index, terminator });
    }
    try {
      decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(cursor, terminator));
    } catch {
      fail('ORIX_RESOURCE_TABLE_UTF8', 'ResourceTable source-pool string is not valid UTF-8', { index, offset: cursor, size: byte_length.value });
    }
    if (decoded.length !== utf16_length.value) {
      fail('ORIX_RESOURCE_TABLE_STRING_POOL_LENGTH_MISMATCH', 'UTF-8 source-pool string UTF-16 length does not match its declaration', {
        index, declared: utf16_length.value, decoded: decoded.length,
      });
    }
  } else {
    if (utf16_length.value > Math.floor((string_end - cursor - 2) / 2)) {
      fail('ORIX_RESOURCE_TABLE_STRING_POOL_RANGE', 'UTF-16 source-pool string exceeds its data region', {
        index, utf16_length: utf16_length.value, cursor, string_end,
      });
    }
    const byte_length = utf16_length.value * 2;
    charge_pool_string(byte_length, budget, limits, 'source_pool[' + index + ']');
    const terminator = cursor + byte_length;
    if (bytes.readUInt16LE(terminator) !== 0) {
      fail('ORIX_RESOURCE_TABLE_STRING_POOL_TERMINATOR', 'UTF-16 source-pool string is not null-terminated', { index, terminator });
    }
    try {
      decoded = new TextDecoder('utf-16le', { fatal: true }).decode(bytes.subarray(cursor, terminator));
    } catch {
      fail('ORIX_RESOURCE_TABLE_STRING_POOL_UTF16', 'ResourceTable source-pool string is not valid UTF-16LE', { index, offset: cursor, size: byte_length });
    }
    if (decoded.length !== utf16_length.value) {
      fail('ORIX_RESOURCE_TABLE_STRING_POOL_LENGTH_MISMATCH', 'UTF-16 source-pool string length does not match its declaration', {
        index, declared: utf16_length.value, decoded: decoded.length,
      });
    }
  }
  return decoded;
}

function parse_binary_source_string_pool(bytes, budget, limits) {
  const chunk_header_size = 28;
  if (bytes.length < chunk_header_size) {
    fail('ORIX_RESOURCE_TABLE_STRING_POOL_HEADER', 'ResourceTable source pool is shorter than a ResStringPool header', { size: bytes.length });
  }
  const type = bytes.readUInt16LE(0);
  const header_size = bytes.readUInt16LE(2);
  const chunk_size = bytes.readUInt32LE(4);
  const string_count = bytes.readUInt32LE(8);
  const style_count = bytes.readUInt32LE(12);
  const flags = bytes.readUInt32LE(16);
  const strings_start = bytes.readUInt32LE(20);
  const styles_start = bytes.readUInt32LE(24);
  if (type !== 0x0001 || header_size < chunk_header_size || header_size > chunk_size ||
      chunk_size !== bytes.length) {
    fail('ORIX_RESOURCE_TABLE_STRING_POOL_HEADER', 'ResourceTable source pool has an invalid ResStringPool chunk header', {
      type, header_size, chunk_size, actual_size: bytes.length,
    });
  }
  if ((flags & ~0x101) !== 0) {
    fail('ORIX_RESOURCE_TABLE_STRING_POOL_FLAGS', 'ResourceTable source pool contains unsupported flag bits', { flags });
  }
  if (string_count > limits.max_items || style_count > string_count) {
    fail('ORIX_RESOURCE_TABLE_STRING_POOL_COUNT', 'ResourceTable source pool counts exceed the configured item budget or format bounds', {
      string_count, style_count, max_items: limits.max_items,
    });
  }
  const table_bytes = (string_count + style_count) * 4;
  if (!Number.isSafeInteger(table_bytes) || table_bytes > chunk_size - header_size) {
    fail('ORIX_RESOURCE_TABLE_STRING_POOL_TABLE_RANGE', 'ResourceTable source pool offset tables exceed the chunk', {
      header_size, string_count, style_count, chunk_size,
    });
  }
  const table_end = header_size + table_bytes;
  if (string_count > 0) {
    if (strings_start < table_end || strings_start >= chunk_size) {
      fail('ORIX_RESOURCE_TABLE_STRING_POOL_STRINGS_RANGE', 'ResourceTable source-pool string data offset is invalid', {
        strings_start, table_end, chunk_size,
      });
    }
  } else if (strings_start > chunk_size) {
    fail('ORIX_RESOURCE_TABLE_STRING_POOL_STRINGS_RANGE', 'Empty source-pool string data offset exceeds the chunk', {
      strings_start, chunk_size,
    });
  }
  let string_end = chunk_size;
  if (style_count > 0) {
    if (styles_start <= strings_start || styles_start >= chunk_size) {
      fail('ORIX_RESOURCE_TABLE_STRING_POOL_STYLES_RANGE', 'ResourceTable source-pool style data offset is invalid', {
        strings_start, styles_start, chunk_size,
      });
    }
    string_end = styles_start;
  } else if (styles_start !== 0) {
    fail('ORIX_RESOURCE_TABLE_STRING_POOL_STYLES_RANGE', 'ResourceTable source pool declares a styles offset without style entries', {
      style_count, styles_start,
    });
  }
  const utf8 = (flags & 0x100) !== 0;
  const strings = [];
  for (let index = 0; index < string_count; index += 1) {
    consume_item(budget, limits, 'StringPool.String');
    const relative = bytes.readUInt32LE(header_size + index * 4);
    if (!utf8 && (relative & 1) !== 0) {
      fail('ORIX_RESOURCE_TABLE_STRING_POOL_ALIGNMENT', 'UTF-16 source-pool string offsets must be two-byte aligned', { index, offset: relative });
    }
    strings.push(decode_pool_string(bytes, strings_start + relative, string_end, utf8, budget, limits, index));
  }
  let style_spans = 0;
  if (style_count > 0) {
    const styles_table = header_size + string_count * 4;
    for (let index = 0; index < style_count; index += 1) {
      const relative = bytes.readUInt32LE(styles_table + index * 4);
      if (relative === 0xffffffff) continue;
      if ((relative & 3) !== 0 || relative > chunk_size - styles_start - 12) {
        fail('ORIX_RESOURCE_TABLE_STRING_POOL_STYLE_OFFSET', 'Source-pool style offset is misaligned or outside the style data region', {
          index, offset: relative, style_data_bytes: chunk_size - styles_start,
        });
      }
      let cursor = styles_start + relative;
      let terminated = false;
      while (cursor <= chunk_size - 12) {
        consume_item(budget, limits, 'StringPool.StyleSpan');
        const name = bytes.readUInt32LE(cursor);
        const first_char = bytes.readUInt32LE(cursor + 4);
        const last_char = bytes.readUInt32LE(cursor + 8);
        cursor += 12;
        if (name === 0xffffffff && first_char === 0xffffffff && last_char === 0xffffffff) {
          terminated = true;
          break;
        }
        const styled_string_length = strings[index]?.length ?? 0;
        if (name >= string_count || first_char > last_char || last_char >= styled_string_length) {
          fail('ORIX_RESOURCE_TABLE_STRING_POOL_STYLE_SPAN_RANGE', 'Source-pool style span has an invalid name index or exceeds the associated string range', {
            index, name, string_count, first_char, last_char, styled_string_length,
          });
        }
        style_spans += 1;
      }
      if (!terminated) {
        fail('ORIX_RESOURCE_TABLE_STRING_POOL_STYLE_TERMINATOR', 'Source-pool style span list lacks its END marker', { index });
      }
    }
  }
  return {
    data_bytes: bytes.length,
    string_count,
    style_count,
    encoding: utf8 ? 'utf-8' : 'utf-16le',
    strings,
    style_spans,
  };
}

function parse_string_pool(buffer, start, end, budget, limits, label) {
  let pool = null;
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire(label, field, wire, 2);
      singular(seen, field, label);
      pool = parse_binary_source_string_pool(buffer.subarray(value.start, value.end), budget, limits);
    } else {
      budget.unknown_fields += 1;
    }
  }, label);
  if (!pool) {
    fail('ORIX_RESOURCE_TABLE_STRING_POOL_DATA', 'ResourceTable StringPool is missing its binary data field');
  }
  return pool;
}

function parse_configuration(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Configuration');
  const result = {};
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 3 || field === 25) {
      const key = field === 3 ? 'locale' : 'product';
      expect_wire('Configuration', field, wire, 2);
      singular(seen, field, 'Configuration');
      result[key] = decode_string(buffer, value, 'Configuration.' + key, budget, limits);
    } else if (Object.hasOwn(CONFIG_FIELDS, field)) {
      expect_wire('Configuration', field, wire, 0);
      singular(seen, field, 'Configuration');
      result[CONFIG_FIELDS[field]] = uint32(value, 'Configuration.' + CONFIG_FIELDS[field]);
    } else {
      budget.unknown_fields += 1;
    }
  }, 'Configuration');
  return result;
}

function parse_reference(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Reference');
  // Count every Reference protobuf, including nested compound-value references.
  budget.reference_count += 1;
  const result = { type: 0, id: null, name: null, private: false, dynamic: false };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1 || field === 2) {
      expect_wire('Reference', field, wire, 0);
      singular(seen, field, 'Reference');
      const decoded = uint32(value, 'Reference.field_' + field);
      if (field === 1) {
        if (decoded > 1) {
          fail('ORIX_RESOURCE_TABLE_REFERENCE_TYPE', 'Reference type must be REFERENCE (0) or ATTRIBUTE (1)', { type: decoded });
        }
        result.type = decoded;
      } else result.id = decoded;
    } else if (field === 4) {
      expect_wire('Reference', field, wire, 0);
      singular(seen, field, 'Reference');
      result.private = value !== 0n;
    } else if (field === 3) {
      expect_wire('Reference', field, wire, 2);
      singular(seen, field, 'Reference');
      result.name = decode_string(buffer, value, 'Reference.name', budget, limits);
    } else if (field === 5) {
      expect_wire('Reference', field, wire, 2);
      singular(seen, field, 'Reference');
      let dynamic = false;
      const nested_seen = new Set();
      walk_fields(buffer, value.start, value.end, budget, (nested_field, nested_wire, nested_value) => {
        if (nested_field === 1) {
          expect_wire('Reference.is_dynamic', nested_field, nested_wire, 0);
          singular(nested_seen, nested_field, 'Reference.is_dynamic');
          dynamic = nested_value !== 0n;
        } else budget.unknown_fields += 1;
      }, 'Reference.is_dynamic');
      result.dynamic = dynamic;
    } else if (field === 6) {
      expect_wire('Reference', field, wire, 0);
      singular(seen, field, 'Reference');
      uint32(value, 'Reference.type_flags');
    } else if (field === 7) {
      expect_wire('Reference', field, wire, 0);
      singular(seen, field, 'Reference');
    } else {
      budget.unknown_fields += 1;
    }
  }, 'Reference');
  return result;
}

function parse_text_item(buffer, start, end, budget, limits, label) {
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire(label, field, wire, 2);
      singular(seen, field, label);
      decode_string(buffer, value, label + '.value', budget, limits);
    } else budget.unknown_fields += 1;
  }, label);
}

function parse_styled_text_item(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'StyledString');
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('StyledString', field, wire, 2);
      singular(seen, field, 'StyledString');
      decode_string(buffer, value, 'StyledString.value', budget, limits);
    } else if (field === 2) {
      expect_wire('StyledString', field, wire, 2);
      consume_item(budget, limits, 'StyledString.Span');
      const span_seen = new Set();
      walk_fields(buffer, value.start, value.end, budget, (span_field, span_wire, span_value) => {
        if (span_field === 1) {
          expect_wire('StyledString.Span', span_field, span_wire, 2);
          singular(span_seen, span_field, 'StyledString.Span');
          decode_string(buffer, span_value, 'StyledString.Span.tag', budget, limits);
        } else if (span_field === 2 || span_field === 3) {
          expect_wire('StyledString.Span', span_field, span_wire, 0);
          singular(span_seen, span_field, 'StyledString.Span');
          uint32(span_value, 'StyledString.Span.' + (span_field === 2 ? 'first_char' : 'last_char'));
        } else budget.unknown_fields += 1;
      }, 'StyledString.Span');
    } else budget.unknown_fields += 1;
  }, 'StyledString');
}

function parse_file_reference(buffer, start, end, budget, limits) {
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('FileReference', field, wire, 2);
      singular(seen, field, 'FileReference');
      decode_string(buffer, value, 'FileReference.path', budget, limits);
    } else if (field === 2) {
      expect_wire('FileReference', field, wire, 0);
      singular(seen, field, 'FileReference');
      uint32(value, 'FileReference.type');
    } else budget.unknown_fields += 1;
  }, 'FileReference');
}

function parse_primitive(buffer, start, end, budget) {
  const variants = {
    1: { name: 'null_value', wire: 2 },
    2: { name: 'empty_value', wire: 2 },
    3: { name: 'float_value', wire: 5 },
    4: { name: 'dimension_value_deprecated', wire: 5 },
    5: { name: 'fraction_value_deprecated', wire: 5 },
    6: { name: 'int_decimal_value', wire: 0 },
    7: { name: 'int_hexadecimal_value', wire: 0 },
    8: { name: 'boolean_value', wire: 0 },
    9: { name: 'color_argb8_value', wire: 0 },
    10: { name: 'color_rgb8_value', wire: 0 },
    11: { name: 'color_argb4_value', wire: 0 },
    12: { name: 'color_rgb4_value', wire: 0 },
    13: { name: 'dimension_value', wire: 0 },
    14: { name: 'fraction_value', wire: 0 },
  };
  let selected = null;
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    const variant = variants[field];
    if (!variant) {
      budget.unknown_fields += 1;
      return;
    }
    expect_wire('Primitive', field, wire, variant.wire);
    if (selected !== null) {
      fail('ORIX_RESOURCE_TABLE_ONEOF', 'ResourceTable Primitive contains more than one value variant', {
        previous: variants[selected].name, next: variant.name,
      });
    }
    selected = field;
    if (wire === 2) {
      walk_fields(buffer, value.start, value.end, budget, () => { budget.unknown_fields += 1; }, 'Primitive.' + variant.name);
    } else if (field === 6) {
      // int32 uses sign-extended varints; preserve only its format-valid width.
      BigInt.asIntN(32, value);
    } else {
      uint32(value, 'Primitive.' + variant.name);
    }
  }, 'Primitive');
}

function parse_item(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Item');
  let kind = null;
  let reference = null;
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (Object.hasOwn(ITEM_KINDS, field)) {
      expect_wire('Item', field, wire, 2);
      if (kind !== null) {
        fail('ORIX_RESOURCE_TABLE_ONEOF', 'ResourceTable Item contains more than one value variant', {
          previous: kind, next: ITEM_KINDS[field],
        });
      }
      kind = ITEM_KINDS[field];
      if (field === 1) reference = parse_reference(buffer, value.start, value.end, budget, limits, depth + 1);
      else if (field === 2 || field === 3) parse_text_item(buffer, value.start, value.end, budget, limits, 'Item.' + kind);
      else if (field === 4) parse_styled_text_item(buffer, value.start, value.end, budget, limits, depth + 1);
      else if (field === 5) parse_file_reference(buffer, value.start, value.end, budget, limits);
      else if (field === 6) walk_fields(buffer, value.start, value.end, budget, () => { budget.unknown_fields += 1; }, 'Item.id');
      else parse_primitive(buffer, value.start, value.end, budget);
    } else if (field === 8) {
      expect_wire('Item', field, wire, 0);
      singular(seen, field, 'Item');
      uint32(value, 'Item.flag_status');
    } else if (field === 9) {
      expect_wire('Item', field, wire, 0);
      singular(seen, field, 'Item');
    } else if (field === 10) {
      expect_wire('Item', field, wire, 2);
      singular(seen, field, 'Item');
      decode_string(buffer, value, 'Item.flag_name', budget, limits);
    } else {
      budget.unknown_fields += 1;
    }
  }, 'Item');
  return { kind: kind ?? 'unspecified', reference };
}

function validate_schema_message(buffer, start, end, budget, limits, depth, label, schema) {
  assert_depth(depth, limits, label);
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    const spec = schema[field];
    if (!spec) {
      budget.unknown_fields += 1;
      return;
    }
    expect_wire(label, field, wire, spec.wire);
    if (spec.repeated) consume_item(budget, limits, label + '.' + spec.name);
    else singular(seen, field, label);
    if (spec.type === 'uint32' || spec.type === 'enum') uint32(value, label + '.' + spec.name);
    else if (spec.type === 'int32') BigInt.asIntN(32, value);
    else if (spec.type === 'bool') { /* protobuf bool accepts any nonzero varint */ }
    else if (spec.type === 'uint64') { /* read_varint already enforces the 64-bit bound */ }
    else if (spec.type === 'string') decode_string(buffer, value, label + '.' + spec.name, budget, limits);
    else if (spec.type === 'message') spec.parse(buffer, value.start, value.end, budget, limits, depth + 1);
    else fail('ORIX_RESOURCE_TABLE_SCHEMA', 'Unknown ResourceTable schema validator type', { label, field, type: spec.type });
  }, label);
}

function parse_attribute_symbol(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'Attribute.Symbol', {
    1: { name: 'source', wire: 2, type: 'message', parse: parse_source },
    2: { name: 'comment', wire: 2, type: 'string' },
    3: { name: 'name', wire: 2, type: 'message', parse: parse_reference },
    4: { name: 'value', wire: 0, type: 'uint32' },
    5: { name: 'type', wire: 0, type: 'uint32' },
  });
}

function parse_attribute(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Attribute');
  const seen = new Set();
  let format_flags = 0;
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('Attribute', field, wire, 0);
      singular(seen, field, 'Attribute');
      format_flags = uint32(value, 'Attribute.format_flags');
    } else if (field === 2 || field === 3) {
      expect_wire('Attribute', field, wire, 0);
      singular(seen, field, 'Attribute');
      BigInt.asIntN(32, value);
    } else if (field === 4) {
      expect_wire('Attribute', field, wire, 2);
      consume_item(budget, limits, 'Attribute.Symbol');
      parse_attribute_symbol(buffer, value.start, value.end, budget, limits, depth + 1);
    } else {
      budget.unknown_fields += 1;
    }
  }, 'Attribute');
  // AOSP Resources.proto explicitly forbids ENUM and FLAGS together.
  const enum_and_flags = 0x00010000 | 0x00020000;
  if ((format_flags & enum_and_flags) === enum_and_flags) {
    fail('ORIX_RESOURCE_TABLE_ATTRIBUTE_FORMAT_FLAGS', 'Attribute.format_flags must not combine ENUM and FLAGS', {
      format_flags,
      enum_flag: 0x00010000,
      flags_flag: 0x00020000,
    });
  }
}

function parse_style_entry(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'Style.Entry', {
    1: { name: 'source', wire: 2, type: 'message', parse: parse_source },
    2: { name: 'comment', wire: 2, type: 'string' },
    3: { name: 'key', wire: 2, type: 'message', parse: parse_reference },
    4: { name: 'item', wire: 2, type: 'message', parse: parse_item },
  });
}

function parse_style(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'Style', {
    1: { name: 'parent', wire: 2, type: 'message', parse: parse_reference },
    2: { name: 'parent_source', wire: 2, type: 'message', parse: parse_source },
    3: { name: 'entry', wire: 2, type: 'message', repeated: true, parse: parse_style_entry },
  });
}

function parse_styleable_entry(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'Styleable.Entry', {
    1: { name: 'source', wire: 2, type: 'message', parse: parse_source },
    2: { name: 'comment', wire: 2, type: 'string' },
    3: { name: 'attr', wire: 2, type: 'message', parse: parse_reference },
  });
}

function parse_styleable(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'Styleable', {
    1: { name: 'entry', wire: 2, type: 'message', repeated: true, parse: parse_styleable_entry },
  });
}

function parse_array_element(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'Array.Element', {
    1: { name: 'source', wire: 2, type: 'message', parse: parse_source },
    2: { name: 'comment', wire: 2, type: 'string' },
    3: { name: 'item', wire: 2, type: 'message', parse: parse_item },
  });
}

function parse_array(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'Array', {
    1: { name: 'element', wire: 2, type: 'message', repeated: true, parse: parse_array_element },
  });
}

function parse_plural_entry(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'Plural.Entry', {
    1: { name: 'source', wire: 2, type: 'message', parse: parse_source },
    2: { name: 'comment', wire: 2, type: 'string' },
    3: { name: 'arity', wire: 0, type: 'enum' },
    4: { name: 'item', wire: 2, type: 'message', parse: parse_item },
  });
}

function parse_plural(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'Plural', {
    1: { name: 'entry', wire: 2, type: 'message', repeated: true, parse: parse_plural_entry },
  });
}

function parse_style_string_span(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'StyleString.Span', {
    1: { name: 'name', wire: 2, type: 'string' },
    2: { name: 'start_index', wire: 0, type: 'uint32' },
    3: { name: 'end_index', wire: 0, type: 'uint32' },
  });
}

function parse_style_string(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'StyleString', {
    1: { name: 'str', wire: 2, type: 'string' },
    2: { name: 'spans', wire: 2, type: 'message', repeated: true, parse: parse_style_string_span },
  });
}

function parse_untranslatable_section(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'UntranslatableSection', {
    1: { name: 'start_index', wire: 0, type: 'uint64' },
    2: { name: 'end_index', wire: 0, type: 'uint64' },
  });
}

function parse_namespace_alias(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'NamespaceAlias', {
    1: { name: 'prefix', wire: 2, type: 'string' },
    2: { name: 'package_name', wire: 2, type: 'string' },
    3: { name: 'is_private', wire: 0, type: 'bool' },
  });
}

function parse_macro_body(buffer, start, end, budget, limits, depth) {
  validate_schema_message(buffer, start, end, budget, limits, depth, 'MacroBody', {
    1: { name: 'raw_string', wire: 2, type: 'string' },
    2: { name: 'style_string', wire: 2, type: 'message', parse: parse_style_string },
    3: { name: 'untranslatable_sections', wire: 2, type: 'message', repeated: true, parse: parse_untranslatable_section },
    4: { name: 'namespace_stack', wire: 2, type: 'message', repeated: true, parse: parse_namespace_alias },
    5: { name: 'source', wire: 2, type: 'message', parse: parse_source_position },
  });
}

function parse_compound_value(buffer, start, end, budget, depth, limits) {
  assert_depth(depth, limits, 'CompoundValue');
  let kind = null;
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (Object.hasOwn(COMPOUND_KINDS, field)) {
      expect_wire('CompoundValue', field, wire, 2);
      if (kind !== null) {
        fail('ORIX_RESOURCE_TABLE_ONEOF', 'ResourceTable CompoundValue contains more than one value variant', {
          previous: kind, next: COMPOUND_KINDS[field],
        });
      }
      kind = COMPOUND_KINDS[field];
      const validators = {
        1: parse_attribute,
        2: parse_style,
        3: parse_styleable,
        4: parse_array,
        5: parse_plural,
        6: parse_macro_body,
      };
      validators[field](buffer, value.start, value.end, budget, limits, depth + 1);
    } else if (field === 7) {
      expect_wire('CompoundValue', field, wire, 0);
      singular(seen, field, 'CompoundValue');
      uint32(value, 'CompoundValue.flag_status');
    } else if (field === 8) {
      expect_wire('CompoundValue', field, wire, 0);
      singular(seen, field, 'CompoundValue');
    } else if (field === 9) {
      expect_wire('CompoundValue', field, wire, 2);
      singular(seen, field, 'CompoundValue');
      decode_string(buffer, value, 'CompoundValue.flag_name', budget, limits);
    } else {
      budget.unknown_fields += 1;
    }
  }, 'CompoundValue');
  return kind ?? 'unspecified';
}

function parse_value(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Value');
  const result = { weak: false, kind: 'unspecified', detail_kind: null, reference: null };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('Value', field, wire, 2);
      singular(seen, field, 'Value');
      parse_source(buffer, value.start, value.end, budget, limits, depth + 1);
    } else if (field === 2) {
      expect_wire('Value', field, wire, 2);
      singular(seen, field, 'Value');
      decode_string(buffer, value, 'Value.comment', budget, limits);
    } else if (field === 3) {
      expect_wire('Value', field, wire, 0);
      singular(seen, field, 'Value');
      result.weak = value !== 0n;
    } else if (field === 4 || field === 5) {
      expect_wire('Value', field, wire, 2);
      if (result.kind !== 'unspecified') {
        fail('ORIX_RESOURCE_TABLE_ONEOF', 'ResourceTable Value contains more than one value variant', { previous: result.kind, next: field });
      }
      if (field === 4) {
        const item = parse_item(buffer, value.start, value.end, budget, limits, depth + 1);
        result.kind = 'item';
        result.detail_kind = item.kind;
        result.reference = item.reference;
      } else {
        result.kind = 'compound';
        result.detail_kind = parse_compound_value(buffer, value.start, value.end, budget, depth + 1, limits);
      }
    } else {
      budget.unknown_fields += 1;
    }
  }, 'Value');
  return result;
}

function parse_config_value(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'ConfigValue');
  const result = { configuration: {}, value: null };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('ConfigValue', field, wire, 2);
      singular(seen, field, 'ConfigValue');
      result.configuration = parse_configuration(buffer, value.start, value.end, budget, limits, depth + 1);
    } else if (field === 2) {
      expect_wire('ConfigValue', field, wire, 2);
      singular(seen, field, 'ConfigValue');
      result.value = parse_value(buffer, value.start, value.end, budget, limits, depth + 1);
    } else {
      budget.unknown_fields += 1;
    }
  }, 'ConfigValue');
  if (result.value) {
    if (result.value.kind === 'item') {
      budget.item_kinds[result.value.detail_kind] = (budget.item_kinds[result.value.detail_kind] ?? 0) + 1;
    } else if (result.value.kind === 'compound') {
      budget.compound_kinds[result.value.detail_kind] = (budget.compound_kinds[result.value.detail_kind] ?? 0) + 1;
    }
  }
  return result;
}

function parse_source_position(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'SourcePosition');
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1 || field === 2) {
      expect_wire('SourcePosition', field, wire, 0);
      singular(seen, field, 'SourcePosition');
      uint32(value, field === 1 ? 'SourcePosition.line_number' : 'SourcePosition.column_number');
    } else budget.unknown_fields += 1;
  }, 'SourcePosition');
}

function parse_source(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Source');
  const seen = new Set();
  // Proto3 uint32 defaults to zero when omitted; Source.path_idx therefore
  // still refers to source-pool entry zero if the field is not serialized.
  let path_idx = 0;
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('Source', field, wire, 0);
      singular(seen, field, 'Source');
      path_idx = uint32(value, 'Source.path_idx');
    } else if (field === 2) {
      expect_wire('Source', field, wire, 2);
      singular(seen, field, 'Source');
      parse_source_position(buffer, value.start, value.end, budget, limits, depth + 1);
    } else budget.unknown_fields += 1;
  }, 'Source');
  budget.source_path_references += 1;
  budget.source_path_indexes.set(path_idx, (budget.source_path_indexes.get(path_idx) ?? 0) + 1);
}

function parse_visibility(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Visibility');
  let level = 0;
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('Visibility', field, wire, 0);
      singular(seen, field, 'Visibility');
      level = uint32(value, 'Visibility.level');
    } else if (field === 2) {
      expect_wire('Visibility', field, wire, 2);
      singular(seen, field, 'Visibility');
      parse_source(buffer, value.start, value.end, budget, limits, depth + 1);
    } else if (field === 3) {
      expect_wire('Visibility', field, wire, 2);
      singular(seen, field, 'Visibility');
      decode_string(buffer, value, 'Visibility.comment', budget, limits);
    } else if (field === 4) {
      expect_wire('Visibility', field, wire, 0);
      singular(seen, field, 'Visibility');
    } else budget.unknown_fields += 1;
  }, 'Visibility');
  return VISIBILITY[level] ?? 'unknown';
}

function parse_allow_new(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'AllowNew');
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('AllowNew', field, wire, 2);
      singular(seen, field, 'AllowNew');
      parse_source(buffer, value.start, value.end, budget, limits, depth + 1);
    } else if (field === 2) {
      expect_wire('AllowNew', field, wire, 2);
      singular(seen, field, 'AllowNew');
      decode_string(buffer, value, 'AllowNew.comment', budget, limits);
    } else budget.unknown_fields += 1;
  }, 'AllowNew');
}

function parse_overlayable_item(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'OverlayableItem');
  const seen = new Set();
  // Proto3 scalar omission means overlayable_idx defaults to zero.
  let overlayable_idx = 0;
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('OverlayableItem', field, wire, 2);
      singular(seen, field, 'OverlayableItem');
      parse_source(buffer, value.start, value.end, budget, limits, depth + 1);
    } else if (field === 2) {
      expect_wire('OverlayableItem', field, wire, 2);
      singular(seen, field, 'OverlayableItem');
      decode_string(buffer, value, 'OverlayableItem.comment', budget, limits);
    } else if (field === 3) {
      // Repeated proto3 enums may be encoded as unpacked varints (wire 0)
      // or as a packed length-delimited run (wire 2).
      if (wire === 0) {
        consume_item(budget, limits, 'OverlayableItem.policy');
        uint32(value, 'OverlayableItem.policy');
      } else if (wire === 2) {
        let cursor = value.start;
        while (cursor < value.end) {
          const decoded = read_varint(buffer, cursor, value.end, 'OverlayableItem.policy');
          consume_item(budget, limits, 'OverlayableItem.policy');
          uint32(decoded.value, 'OverlayableItem.policy');
          cursor = decoded.next;
        }
      } else {
        expect_wire('OverlayableItem', field, wire, 0);
      }
    } else if (field === 4) {
      expect_wire('OverlayableItem', field, wire, 0);
      singular(seen, field, 'OverlayableItem');
      overlayable_idx = uint32(value, 'OverlayableItem.overlayable_idx');
    } else budget.unknown_fields += 1;
  }, 'OverlayableItem');
  budget.overlayable_indexes.push(overlayable_idx);
}

function parse_staged_id(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'StagedId');
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('StagedId', field, wire, 2);
      singular(seen, field, 'StagedId');
      parse_source(buffer, value.start, value.end, budget, limits, depth + 1);
    } else if (field === 2) {
      expect_wire('StagedId', field, wire, 0);
      singular(seen, field, 'StagedId');
      uint32(value, 'StagedId.staged_id');
    } else budget.unknown_fields += 1;
  }, 'StagedId');
}

function parse_entry(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Entry');
  consume_item(budget, limits, 'Entry');
  budget.entry_count += 1;
  const result = {
    id: null, name: null, visibility: 'unknown', resource_id: null,
    config_value_count: 0, flag_disabled_config_value_count: 0,
    config_values: [], flag_disabled_config_values: [],
  };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('Entry', field, wire, 2);
      singular(seen, field, 'Entry');
      result.id = parse_id_message(buffer, value.start, value.end, budget, 'EntryId', 0xffff);
    } else if (field === 2) {
      expect_wire('Entry', field, wire, 2);
      singular(seen, field, 'Entry');
      result.name = decode_string(buffer, value, 'Entry.name', budget, limits);
    } else if (field === 3) {
      expect_wire('Entry', field, wire, 2);
      singular(seen, field, 'Entry');
      result.visibility = parse_visibility(buffer, value.start, value.end, budget, limits, depth + 1);
    } else if (field === 6 || field === 8) {
      expect_wire('Entry', field, wire, 2);
      consume_item(budget, limits, field === 6 ? 'ConfigValue' : 'FlagDisabledConfigValue');
      const decoded = parse_config_value(buffer, value.start, value.end, budget, limits, depth + 1);
      if (field === 6) {
        result.config_value_count += 1;
        budget.config_value_count += 1;
        add_output(result.config_values, decoded, budget);
      } else {
        result.flag_disabled_config_value_count += 1;
        budget.flag_disabled_config_value_count += 1;
        add_output(result.flag_disabled_config_values, decoded, budget);
      }
    } else if (field === 4 || field === 5 || field === 7) {
      expect_wire('Entry', field, wire, 2);
      singular(seen, field, 'Entry');
      if (field === 4) parse_allow_new(buffer, value.start, value.end, budget, limits, depth + 1);
      else if (field === 5) parse_overlayable_item(buffer, value.start, value.end, budget, limits, depth + 1);
      else parse_staged_id(buffer, value.start, value.end, budget, limits, depth + 1);
    } else {
      budget.unknown_fields += 1;
    }
  }, 'Entry');
  result.config_values_reported = result.config_values.length;
  result.config_values_omitted = result.config_value_count - result.config_values_reported;
  result.flag_disabled_config_values_reported = result.flag_disabled_config_values.length;
  result.flag_disabled_config_values_omitted = result.flag_disabled_config_value_count - result.flag_disabled_config_values_reported;
  return result;
}

function parse_type(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Type');
  consume_item(budget, limits, 'Type');
  budget.type_count += 1;
  const result = { id: null, name: null, entry_count: 0, entries: [] };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('Type', field, wire, 2);
      singular(seen, field, 'Type');
      result.id = parse_id_message(buffer, value.start, value.end, budget, 'TypeId', 0xff, 1);
    } else if (field === 2) {
      expect_wire('Type', field, wire, 2);
      singular(seen, field, 'Type');
      result.name = decode_string(buffer, value, 'Type.name', budget, limits);
    } else if (field === 3) {
      expect_wire('Type', field, wire, 2);
      result.entry_count += 1;
      const entry = parse_entry(buffer, value.start, value.end, budget, limits, depth + 1);
      add_output(result.entries, entry, budget);
    } else {
      budget.unknown_fields += 1;
    }
  }, 'Type');
  result.entries_reported = result.entries.length;
  result.entries_omitted = result.entry_count - result.entries_reported;
  return result;
}

function parse_package(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Package');
  consume_item(budget, limits, 'Package');
  const result = { id: null, name: null, type_count: 0, entry_count: 0, types: [] };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('Package', field, wire, 2);
      singular(seen, field, 'Package');
      result.id = parse_id_message(buffer, value.start, value.end, budget, 'PackageId', 0xff);
    } else if (field === 2) {
      expect_wire('Package', field, wire, 2);
      singular(seen, field, 'Package');
      result.name = decode_string(buffer, value, 'Package.name', budget, limits);
    } else if (field === 3) {
      expect_wire('Package', field, wire, 2);
      result.type_count += 1;
      const type = parse_type(buffer, value.start, value.end, budget, limits, depth + 1);
      result.entry_count += type.entry_count;
      add_output(result.types, type, budget);
    } else {
      budget.unknown_fields += 1;
    }
  }, 'Package');
  result.types_reported = result.types.length;
  result.types_omitted = result.type_count - result.types_reported;
  for (const type of result.types) {
    if (result.id === null || type.id === null) continue;
    for (const entry of type.entries) {
      if (entry.id === null) continue;
      const resource_id = result.id * 0x1000000 + type.id * 0x10000 + entry.id;
      entry.resource_id = '0x' + resource_id.toString(16).padStart(8, '0');
    }
  }
  return result;
}

function parse_tool_fingerprint(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'ToolFingerprint');
  const result = { tool: null, version: null };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1 || field === 2) {
      expect_wire('ToolFingerprint', field, wire, 2);
      singular(seen, field, 'ToolFingerprint');
      result[field === 1 ? 'tool' : 'version'] = decode_string(buffer, value, 'ToolFingerprint.' + field, budget, limits);
    } else budget.unknown_fields += 1;
  }, 'ToolFingerprint');
  return result;
}

function parse_overlayable(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'Overlayable');
  const result = { name: null, actor: null };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1 || field === 3) {
      expect_wire('Overlayable', field, wire, 2);
      singular(seen, field, 'Overlayable');
      result[field === 1 ? 'name' : 'actor'] = decode_string(buffer, value, 'Overlayable.' + field, budget, limits);
    } else if (field === 2) {
      expect_wire('Overlayable', field, wire, 2);
      singular(seen, field, 'Overlayable');
      parse_source(buffer, value.start, value.end, budget, limits, depth + 1);
    } else budget.unknown_fields += 1;
  }, 'Overlayable');
  return result;
}

function parse_dynamic_ref_table(buffer, start, end, budget, limits, depth) {
  assert_depth(depth, limits, 'DynamicRefTable');
  const result = { package_id: null, package_name: null };
  const seen = new Set();
  walk_fields(buffer, start, end, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('DynamicRefTable', field, wire, 2);
      singular(seen, field, 'DynamicRefTable');
      result.package_id = parse_id_message(buffer, value.start, value.end, budget, 'DynamicRefTable.PackageId', 0xff);
    } else if (field === 2) {
      expect_wire('DynamicRefTable', field, wire, 2);
      singular(seen, field, 'DynamicRefTable');
      result.package_name = decode_string(buffer, value, 'DynamicRefTable.package_name', budget, limits);
    } else budget.unknown_fields += 1;
  }, 'DynamicRefTable');
  return result;
}

/** Parse an AAPT2 ResourceTable protobuf into a bounded structural inventory. */
export function parse_android_resource_table(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_android_resource_table requires a Buffer');
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('ResourceTable options must be an object');
  }
  const limits = {
    max_file_bytes: options.max_file_bytes ?? 4 * 1024 * 1024,
    max_fields: options.max_fields ?? 200_000,
    max_items: options.max_items ?? 100_000,
    max_output_items: options.max_output_items ?? 5_000,
    max_depth: options.max_depth ?? 24,
    max_string_bytes: options.max_string_bytes ?? 16_384,
    max_total_string_bytes: options.max_total_string_bytes ?? 8 * 1024 * 1024,
    max_source_paths: options.max_source_paths ?? 1_000,
  };
  bounded_integer('max_file_bytes', limits.max_file_bytes, 1, 64 * 1024 * 1024);
  bounded_integer('max_fields', limits.max_fields, 1, 2_000_000);
  bounded_integer('max_items', limits.max_items, 1, 1_000_000);
  bounded_integer('max_output_items', limits.max_output_items, 0, 100_000);
  bounded_integer('max_depth', limits.max_depth, 1, 64);
  bounded_integer('max_string_bytes', limits.max_string_bytes, 1, 1_048_576);
  bounded_integer('max_total_string_bytes', limits.max_total_string_bytes, 1, 64 * 1024 * 1024);
  bounded_integer('max_source_paths', limits.max_source_paths, 0, 10_000);
  if (buffer.length > limits.max_file_bytes) {
    fail('ORIX_RESOURCE_TABLE_FILE_LIMIT', 'ResourceTable exceeds the configured file-size limit', {
      file_size: buffer.length, max_file_bytes: limits.max_file_bytes,
    });
  }
  const budget = {
    limits,
    fields_seen: 0,
    items_seen: 0,
    output_items: 0,
    items_omitted: 0,
    unknown_fields: 0,
    string_bytes: 0,
    output_truncated: false,
    item_kinds: {},
    compound_kinds: {},
    reference_count: 0,
    type_count: 0,
    entry_count: 0,
    config_value_count: 0,
    flag_disabled_config_value_count: 0,
    source_pool: null,
    source_path_references: 0,
    source_path_indexes: new Map(),
    overlayable_indexes: [],
  };
  const result = {
    schema_version: 'orix.android-resource-table.v1',
    source_pool_present: false,
    source_pool_data_bytes: null,
    source_pool_string_count: 0,
    source_pool_style_count: 0,
    source_pool_style_span_count: 0,
    source_pool_encoding: null,
    source_paths: [],
    source_paths_omitted: 0,
    source_path_references: 0,
    source_paths_resolved: 0,
    source_paths_unresolved: 0,
    package_count: 0,
    packages_reported: 0,
    packages: [],
    packages_omitted: 0,
    overlayable_count: 0,
    overlayables_reported: 0,
    overlayables: [],
    overlayables_omitted: 0,
    tool_fingerprint_count: 0,
    tool_fingerprints_reported: 0,
    tool_fingerprints_omitted: 0,
    tool_fingerprints: [],
    dynamic_ref_table_count: 0,
    dynamic_ref_tables_reported: 0,
    dynamic_ref_tables_omitted: 0,
    dynamic_ref_tables: [],
  };
  const seen = new Set();
  walk_fields(buffer, 0, buffer.length, budget, (field, wire, value) => {
    if (field === 1) {
      expect_wire('ResourceTable', field, wire, 2);
      singular(seen, field, 'ResourceTable');
      const pool = parse_string_pool(buffer, value.start, value.end, budget, limits, 'StringPool');
      budget.source_pool = pool;
      result.source_pool_present = true;
      result.source_pool_data_bytes = pool.data_bytes;
      result.source_pool_string_count = pool.string_count;
      result.source_pool_style_count = pool.style_count;
      result.source_pool_style_span_count = pool.style_spans;
      result.source_pool_encoding = pool.encoding;
    } else if (field === 2) {
      expect_wire('ResourceTable', field, wire, 2);
      result.package_count += 1;
      const item = parse_package(buffer, value.start, value.end, budget, limits, 1);
      if (!add_output(result.packages, item, budget)) result.packages_omitted += 1;
    } else if (field === 3) {
      expect_wire('ResourceTable', field, wire, 2);
      consume_item(budget, limits, 'Overlayable');
      result.overlayable_count += 1;
      const item = parse_overlayable(buffer, value.start, value.end, budget, limits, 1);
      if (!add_output(result.overlayables, item, budget)) result.overlayables_omitted += 1;
    } else if (field === 4) {
      expect_wire('ResourceTable', field, wire, 2);
      consume_item(budget, limits, 'ToolFingerprint');
      result.tool_fingerprint_count += 1;
      const item = parse_tool_fingerprint(buffer, value.start, value.end, budget, limits, 1);
      if (!add_output(result.tool_fingerprints, item, budget)) result.tool_fingerprints_omitted += 1;
    } else if (field === 5) {
      expect_wire('ResourceTable', field, wire, 2);
      consume_item(budget, limits, 'DynamicRefTable');
      result.dynamic_ref_table_count += 1;
      const item = parse_dynamic_ref_table(buffer, value.start, value.end, budget, limits, 1);
      if (!add_output(result.dynamic_ref_tables, item, budget)) result.dynamic_ref_tables_omitted += 1;
    } else {
      budget.unknown_fields += 1;
    }
  }, 'ResourceTable');
  // OverlayableItem.overlayable_idx is an index into the ResourceTable's
  // top-level repeated Overlayable declarations (AOSP Resources.proto).
  for (const overlayable_idx of budget.overlayable_indexes) {
    if (overlayable_idx >= result.overlayable_count) {
      fail('ORIX_RESOURCE_TABLE_OVERLAYABLE_INDEX', 'OverlayableItem.overlayable_idx points outside the ResourceTable overlayable list', {
        overlayable_idx,
        overlayable_count: result.overlayable_count,
      });
    }
  }
  result.source_path_references = budget.source_path_references;
  if (budget.source_pool) {
    for (const [index, references] of budget.source_path_indexes) {
      if (index >= budget.source_pool.strings.length) {
        fail('ORIX_RESOURCE_TABLE_SOURCE_PATH_INDEX', 'Source.path_idx points outside the ResourceTable source string pool', {
          path_idx: index, source_pool_string_count: budget.source_pool.strings.length,
        });
      }
      result.source_paths_resolved += references;
      if (result.source_paths.length < limits.max_source_paths) {
        result.source_paths.push({ index, path: budget.source_pool.strings[index], reference_count: references });
      } else {
        result.source_paths_omitted += 1;
      }
    }
    if (result.source_paths_omitted > 0) budget.output_truncated = true;
  } else {
    result.source_paths_unresolved = budget.source_path_references;
  }
  result.packages_reported = result.packages.length;
  result.overlayables_reported = result.overlayables.length;
  result.tool_fingerprints_reported = result.tool_fingerprints.length;
  result.dynamic_ref_tables_reported = result.dynamic_ref_tables.length;
  return {
    ...result,
    summary: {
      package_count: result.package_count,
      type_count: budget.type_count,
      entry_count: budget.entry_count,
      config_value_count: budget.config_value_count,
      flag_disabled_config_value_count: budget.flag_disabled_config_value_count,
      item_kinds: budget.item_kinds,
      compound_kinds: budget.compound_kinds,
      reference_count: budget.reference_count,
      source_path_references: result.source_path_references,
      source_paths_resolved: result.source_paths_resolved,
      source_paths_unresolved: result.source_paths_unresolved,
    },
    coverage: {
      fields_seen: budget.fields_seen,
      items_seen: budget.items_seen,
      output_items: budget.output_items,
      items_omitted: budget.items_omitted,
      unknown_fields: budget.unknown_fields,
      string_bytes: budget.string_bytes,
      output_truncated: budget.output_truncated,
    },
    notes: [
      'AAPT2 ResourceTable package, type, entry, resource-ID, visibility, configuration and value-kind metadata are inventoried under explicit protobuf, string and output budgets.',
      'The embedded binary ResStringPool chunk is validated in UTF-8 or UTF-16LE form, including string/style offset tables, terminators and style spans; Source.path_idx references are resolved after the top-level message is read.',
      'Configuration metadata includes locale, density, SDK and selected device qualifiers; unknown wire-valid fields are skipped and counted.',
      'Resource references are inventoried by kind only. Reference resolution, complete compound-value decoding, compiled resource-file decoding and install/split semantics are not implemented.',
    ],
  };
}
