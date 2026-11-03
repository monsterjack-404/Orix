// JavaScript, src/formats/wasm.mjs, Node.js 20+, bounded WebAssembly structure indexer.

import { OrixError } from '../core/errors.mjs';
import { BinaryReader } from '../core/binary-reader.mjs';

const SECTION_NAMES = new Map([
  [0, 'custom'], [1, 'type'], [2, 'import'], [3, 'function'], [4, 'table'],
  [5, 'memory'], [6, 'global'], [7, 'export'], [8, 'start'], [9, 'element'],
  [10, 'code'], [11, 'data'], [12, 'data-count'], [13, 'tag'],
]);
const VALUE_TYPES = new Map([
  [0x7f, 'i32'], [0x7e, 'i64'], [0x7d, 'f32'], [0x7c, 'f64'],
  [0x7b, 'v128'], [0x70, 'funcref'], [0x6f, 'externref'],
]);

function wasm_error(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function read_varuint(reader, offset, end_limit = reader.buffer.length, max_bytes = 5) {
  let value = 0;
  let multiplier = 1;
  let cursor = offset;
  for (let count = 0; count < max_bytes; count += 1) {
    if (cursor >= end_limit) {
      wasm_error('ORIX_WASM_TRUNCATED_LEB128', 'WebAssembly integer crosses its containing boundary', {
        offset, end_limit,
      });
    }
    const byte = reader.u8(cursor, 'WebAssembly varuint');
    const payload = byte & 0x7f;
    if (count === max_bytes - 1 && payload > 0x0f) {
      wasm_error('ORIX_WASM_BAD_LEB128', 'WebAssembly u32 integer exceeds its 32-bit encoding range', {
        offset, byte, max_bytes,
      });
    }
    value += payload * multiplier;
    cursor += 1;
    if ((byte & 0x80) === 0) return { value, next: cursor };
    multiplier *= 128;
  }
  wasm_error('ORIX_WASM_BAD_LEB128', 'WebAssembly integer uses too many LEB128 bytes', { offset, max_bytes });
}

function read_count(reader, cursor, end, maximum, field) {
  const result = read_varuint(reader, cursor, end);
  if (result.value > maximum) {
    wasm_error('ORIX_WASM_VECTOR_LIMIT', 'WebAssembly vector exceeds configured limit', {
      field, count: result.value, maximum,
    });
  }
  return result;
}

function read_name(reader, cursor, end, maximum_name_bytes) {
  const length = read_varuint(reader, cursor, end);
  if (length.value > maximum_name_bytes) {
    wasm_error('ORIX_WASM_NAME_LIMIT', 'WebAssembly name exceeds configured byte limit', {
      offset: cursor, length: length.value, maximum_name_bytes,
    });
  }
  if (length.value > end - length.next) {
    wasm_error('ORIX_WASM_BAD_NAME', 'WebAssembly name extends beyond its containing section', {
      offset: cursor, length: length.value, end,
    });
  }
  let value;
  try {
    value = new TextDecoder('utf-8', { fatal: true }).decode(reader.bytes(length.next, length.value, 'WebAssembly UTF-8 name'));
  } catch {
    wasm_error('ORIX_WASM_BAD_UTF8', 'WebAssembly name contains invalid UTF-8', {
      offset: length.next, length: length.value,
    });
  }
  return { value, next: length.next + length.value };
}

function read_value_type(reader, cursor, end, field) {
  if (cursor >= end) wasm_error('ORIX_WASM_TRUNCATED_SECTION', 'WebAssembly value type crosses its containing section', { offset: cursor, end, field });
  const code = reader.u8(cursor, field);
  const value = VALUE_TYPES.get(code);
  if (!value) {
    wasm_error('ORIX_WASM_UNSUPPORTED_VALUE_TYPE', 'WebAssembly value or reference type is not supported by this indexer', {
      offset: cursor, code, field,
    });
  }
  return { value, next: cursor + 1 };
}

function read_limits(reader, cursor, end, kind) {
  const flags = read_varuint(reader, cursor, end);
  const allowed = kind === 'memory' ? 0x03 : 0x01;
  if ((flags.value & ~allowed) !== 0) {
    wasm_error('ORIX_WASM_UNSUPPORTED_LIMIT_FLAGS', 'WebAssembly limits use unsupported flags', {
      offset: cursor, flags: flags.value, kind,
    });
  }
  const minimum = read_varuint(reader, flags.next, end);
  let maximum = null;
  let next = minimum.next;
  if ((flags.value & 0x01) !== 0) {
    const parsed_maximum = read_varuint(reader, next, end);
    maximum = parsed_maximum.value;
    next = parsed_maximum.next;
    if (maximum < minimum.value) {
      wasm_error('ORIX_WASM_INVALID_LIMITS', 'WebAssembly maximum is smaller than its minimum', {
        kind, minimum: minimum.value, maximum,
      });
    }
  }
  if (kind === 'memory' && (flags.value & 0x02) !== 0 && maximum === null) {
    wasm_error('ORIX_WASM_INVALID_LIMITS', 'A shared WebAssembly memory must declare a maximum', {
      minimum: minimum.value,
    });
  }
  return {
    value: {
      minimum: minimum.value,
      maximum,
      shared: kind === 'memory' && (flags.value & 0x02) !== 0,
    },
    next,
  };
}

function require_section_end(cursor, end, section_name) {
  if (cursor !== end) {
    wasm_error('ORIX_WASM_SECTION_TRAILING_DATA', 'WebAssembly section parser did not consume its complete payload', {
      section: section_name, parsed_bytes: cursor, section_end: end, trailing_bytes: end - cursor,
    });
  }
}

function parse_type_section(reader, start, end, limits) {
  const count = read_count(reader, start, end, limits.max_vector_entries, 'type');
  let cursor = count.next;
  const types = [];
  for (let index = 0; index < count.value; index += 1) {
    if (cursor >= end) wasm_error('ORIX_WASM_TRUNCATED_SECTION', 'WebAssembly function type form is truncated', { index, end });
    const form = reader.u8(cursor, 'function type form');
    cursor += 1;
    if (form !== 0x60) {
      wasm_error('ORIX_WASM_BAD_FUNCTION_TYPE', 'WebAssembly type entry is not a function type', {
        index, form,
      });
    }
    const params_count = read_count(reader, cursor, end, limits.max_vector_entries, 'function parameters');
    cursor = params_count.next;
    const params = [];
    for (let parameter = 0; parameter < params_count.value; parameter += 1) {
      const parsed = read_value_type(reader, cursor, end, 'function parameter type');
      params.push(parsed.value);
      cursor = parsed.next;
    }
    const results_count = read_count(reader, cursor, end, limits.max_vector_entries, 'function results');
    cursor = results_count.next;
    const results = [];
    for (let result = 0; result < results_count.value; result += 1) {
      const parsed = read_value_type(reader, cursor, end, 'function result type');
      results.push(parsed.value);
      cursor = parsed.next;
    }
    types.push({ params, results });
  }
  require_section_end(cursor, end, 'type');
  return { value: types, next: cursor };
}

function parse_import_section(reader, start, end, limits) {
  const count = read_count(reader, start, end, limits.max_vector_entries, 'import');
  let cursor = count.next;
  const imports = [];
  for (let index = 0; index < count.value; index += 1) {
    const module_name = read_name(reader, cursor, end, limits.max_name_bytes);
    cursor = module_name.next;
    const field_name = read_name(reader, cursor, end, limits.max_name_bytes);
    cursor = field_name.next;
    if (cursor >= end) wasm_error('ORIX_WASM_TRUNCATED_SECTION', 'WebAssembly import kind is truncated', { index, end });
    const kind = reader.u8(cursor, 'import kind');
    cursor += 1;
    const item = { module: module_name.value, name: field_name.value, kind: null };
    if (kind === 0) {
      const type_index = read_varuint(reader, cursor, end);
      item.kind = 'function';
      item.type_index = type_index.value;
      cursor = type_index.next;
    } else if (kind === 1) {
      const reference_type = read_value_type(reader, cursor, end, 'import table reference type');
      const table_limits = read_limits(reader, reference_type.next, end, 'table');
      item.kind = 'table';
      item.reference_type = reference_type.value;
      item.limits = table_limits.value;
      cursor = table_limits.next;
    } else if (kind === 2) {
      const memory_limits = read_limits(reader, cursor, end, 'memory');
      item.kind = 'memory';
      item.limits = memory_limits.value;
      cursor = memory_limits.next;
    } else if (kind === 3) {
      const value_type = read_value_type(reader, cursor, end, 'import global type');
      if (value_type.next >= end) wasm_error('ORIX_WASM_TRUNCATED_SECTION', 'WebAssembly imported global mutability is truncated', { index, end });
      const mutability = reader.u8(value_type.next, 'import global mutability');
      if (mutability !== 0 && mutability !== 1) {
        wasm_error('ORIX_WASM_BAD_MUTABILITY', 'WebAssembly global mutability must be zero or one', {
          offset: value_type.next, mutability,
        });
      }
      item.kind = 'global';
      item.value_type = value_type.value;
      item.mutable = mutability === 1;
      cursor = value_type.next + 1;
    } else if (kind === 4) {
      if (cursor >= end) wasm_error('ORIX_WASM_TRUNCATED_SECTION', 'WebAssembly import tag attribute is truncated', { index, end });
      const attribute = reader.u8(cursor, 'import tag attribute');
      if (attribute !== 0) {
        wasm_error('ORIX_WASM_BAD_TAG_ATTRIBUTE', 'WebAssembly tag attribute is not supported', {
          offset: cursor, attribute,
        });
      }
      const type_index = read_varuint(reader, cursor + 1, end);
      item.kind = 'tag';
      item.type_index = type_index.value;
      cursor = type_index.next;
    } else {
      wasm_error('ORIX_WASM_BAD_IMPORT_KIND', 'WebAssembly import uses an unknown external kind', {
        offset: cursor - 1, kind,
      });
    }
    imports.push(item);
  }
  require_section_end(cursor, end, 'import');
  return { value: imports, next: cursor };
}

function parse_function_section(reader, start, end, limits) {
  const count = read_count(reader, start, end, limits.max_vector_entries, 'function');
  let cursor = count.next;
  const type_indices = [];
  for (let index = 0; index < count.value; index += 1) {
    const type_index = read_varuint(reader, cursor, end);
    type_indices.push(type_index.value);
    cursor = type_index.next;
  }
  require_section_end(cursor, end, 'function');
  return { value: type_indices, next: cursor };
}

function parse_export_section(reader, start, end, limits) {
  const count = read_count(reader, start, end, limits.max_vector_entries, 'export');
  let cursor = count.next;
  const exports = [];
  const names = new Set();
  const kinds = new Map([[0, 'function'], [1, 'table'], [2, 'memory'], [3, 'global'], [4, 'tag']]);
  for (let index = 0; index < count.value; index += 1) {
    const name = read_name(reader, cursor, end, limits.max_name_bytes);
    cursor = name.next;
    if (names.has(name.value)) {
      wasm_error('ORIX_WASM_DUPLICATE_EXPORT', 'WebAssembly export names must be unique', {
        index, name: name.value,
      });
    }
    names.add(name.value);
    if (cursor >= end) wasm_error('ORIX_WASM_TRUNCATED_SECTION', 'WebAssembly export kind is truncated', { index, end });
    const kind_code = reader.u8(cursor, 'export kind');
    cursor += 1;
    const kind = kinds.get(kind_code);
    if (!kind) {
      wasm_error('ORIX_WASM_BAD_EXPORT_KIND', 'WebAssembly export uses an unknown external kind', {
        index, kind: kind_code,
      });
    }
    const item_index = read_varuint(reader, cursor, end);
    cursor = item_index.next;
    exports.push({ name: name.value, kind, index: item_index.value });
  }
  require_section_end(cursor, end, 'export');
  return { value: exports, next: cursor };
}

function parse_code_section(reader, start, end, limits) {
  const count = read_count(reader, start, end, limits.max_vector_entries, 'code');
  let cursor = count.next;
  const bodies = [];
  for (let index = 0; index < count.value; index += 1) {
    const body_size = read_varuint(reader, cursor, end);
    cursor = body_size.next;
    if (body_size.value > end - cursor) {
      wasm_error('ORIX_WASM_BAD_CODE_BODY', 'WebAssembly function body extends beyond the code section', {
        index, body_offset: cursor, body_size: body_size.value, section_end: end,
      });
    }
    bodies.push({ offset: cursor, size: body_size.value });
    cursor += body_size.value;
  }
  require_section_end(cursor, end, 'code');
  return { value: bodies, next: cursor };
}

function parse_single_index(reader, start, end, section_name) {
  const index = read_varuint(reader, start, end);
  require_section_end(index.next, end, section_name);
  return { value: index.value, next: index.next };
}

export function parse_wasm(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_wasm requires a Buffer');
  const reader = new BinaryReader(buffer, { label: 'WebAssembly module' });
  if (reader.ascii(0, 4, 'WebAssembly magic') !== '\0asm') {
    wasm_error('ORIX_WASM_BAD_MAGIC', 'Input does not contain the WebAssembly magic');
  }
  const version = reader.u32(4, true, 'WebAssembly version');
  if (version !== 1) {
    wasm_error('ORIX_WASM_UNSUPPORTED_VERSION', 'Only WebAssembly binary version 1 is supported', { version });
  }

  const max_sections = options.max_sections ?? 4_096;
  const max_vector_entries = options.max_vector_entries ?? 100_000;
  const max_name_bytes = options.max_name_bytes ?? 4_096;
  for (const [name, value, minimum, maximum] of [
    ['max_sections', max_sections, 1, 65_535],
    ['max_vector_entries', max_vector_entries, 1, 1_000_000],
    ['max_name_bytes', max_name_bytes, 1, 1_048_576],
  ]) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
      throw new TypeError(name + ' must be an integer between ' + minimum + ' and ' + maximum);
    }
  }

  const limits = { max_vector_entries, max_name_bytes };
  const sections = [];
  const seen_sections = new Set();
  const types = [];
  const imports = [];
  const exports = [];
  let function_type_indices = [];
  let code_bodies = [];
  let start_function_index = null;
  let cursor = 8;
  let function_section_present = false;
  let code_section_present = false;

  while (cursor < buffer.length) {
    if (sections.length >= max_sections) {
      wasm_error('ORIX_WASM_SECTION_LIMIT', 'WebAssembly section count exceeds configured limit', { max_sections });
    }
    const section_offset = cursor;
    const id = reader.u8(cursor, 'section ID');
    if (!SECTION_NAMES.has(id)) {
      wasm_error('ORIX_WASM_UNKNOWN_SECTION', 'WebAssembly section ID is not defined by the supported binary version', {
        offset: cursor, id,
      });
    }
    const size_info = read_varuint(reader, cursor + 1);
    const payload_offset = size_info.next;
    if (size_info.value > buffer.length - payload_offset) {
      wasm_error('ORIX_WASM_SECTION_OUT_OF_RANGE', 'WebAssembly section extends beyond end of file', {
        id, payload_offset, payload_size: size_info.value, file_size: buffer.length,
      });
    }
    const section_end = payload_offset + size_info.value;
    const name = SECTION_NAMES.get(id);
    let custom_name = null;
    let vector_count = null;

    if (id !== 0) {
      if (seen_sections.has(id)) {
        wasm_error('ORIX_WASM_DUPLICATE_SECTION', 'WebAssembly standard section occurs more than once', {
          id, name,
        });
      }
      seen_sections.add(id);
    }

    if (id === 0 && size_info.value > 0) {
      const decoded_name = read_name(reader, payload_offset, section_end, max_name_bytes);
      custom_name = decoded_name.value;
    } else if (id === 1) {
      const parsed = parse_type_section(reader, payload_offset, section_end, limits);
      types.push(...parsed.value);
      vector_count = parsed.value.length;
    } else if (id === 2) {
      const parsed = parse_import_section(reader, payload_offset, section_end, limits);
      imports.push(...parsed.value);
      vector_count = parsed.value.length;
    } else if (id === 3) {
      const parsed = parse_function_section(reader, payload_offset, section_end, limits);
      function_type_indices = parsed.value;
      function_section_present = true;
      vector_count = parsed.value.length;
    } else if (id === 7) {
      const parsed = parse_export_section(reader, payload_offset, section_end, limits);
      exports.push(...parsed.value);
      vector_count = parsed.value.length;
    } else if (id === 8) {
      const parsed = parse_single_index(reader, payload_offset, section_end, 'start');
      start_function_index = parsed.value;
    } else if (id === 10) {
      const parsed = parse_code_section(reader, payload_offset, section_end, limits);
      code_bodies = parsed.value;
      code_section_present = true;
      vector_count = parsed.value.length;
    } else if ([4, 5, 6, 9, 11, 12, 13].includes(id) && size_info.value > 0) {
      const parsed = read_count(reader, payload_offset, section_end, max_vector_entries, name);
      vector_count = parsed.value;
    } else if (id !== 0 && size_info.value === 0) {
      wasm_error('ORIX_WASM_EMPTY_SECTION', 'WebAssembly standard section cannot have an empty payload', {
        id, name,
      });
    }

    sections.push({
      id, name, custom_name, offset: section_offset,
      payload_offset, payload_size: size_info.value,
      ...(vector_count === null ? {} : { vector_count }),
    });
    cursor = section_end;
  }

  if ((function_section_present || code_section_present) && function_type_indices.length !== code_bodies.length) {
    wasm_error('ORIX_WASM_FUNCTION_CODE_MISMATCH', 'WebAssembly function and code section counts differ', {
      function_count: function_type_indices.length, code_count: code_bodies.length,
    });
  }
  {
    for (const item of imports) {
      if (item.kind === 'function' && item.type_index >= types.length) {
        wasm_error('ORIX_WASM_TYPE_INDEX_OUT_OF_RANGE', 'Imported function refers to a missing type entry', {
          module: item.module, name: item.name, type_index: item.type_index, type_count: types.length,
        });
      }
      if (item.kind === 'tag' && item.type_index >= types.length) {
        wasm_error('ORIX_WASM_TYPE_INDEX_OUT_OF_RANGE', 'Imported tag refers to a missing type entry', {
          module: item.module, name: item.name, type_index: item.type_index, type_count: types.length,
        });
      }
    }
    for (const [index, type_index] of function_type_indices.entries()) {
      if (type_index >= types.length) {
        wasm_error('ORIX_WASM_TYPE_INDEX_OUT_OF_RANGE', 'Defined function refers to a missing type entry', {
          function_index: index, type_index, type_count: types.length,
        });
      }
    }
  }

  const imported_functions = imports.filter(item => item.kind === 'function').length;
  const function_count = imported_functions + function_type_indices.length;
  if (start_function_index !== null && start_function_index >= function_count) {
    wasm_error('ORIX_WASM_START_INDEX_OUT_OF_RANGE', 'WebAssembly start function index is outside the declared function index space', {
      start_function_index, function_count,
    });
  }
  for (const item of exports) {
    if (item.kind === 'function' && item.index >= function_count) {
      wasm_error('ORIX_WASM_EXPORT_INDEX_OUT_OF_RANGE', 'WebAssembly function export index is outside the declared function index space', {
        name: item.name, index: item.index, function_count,
      });
    }
  }

  return {
    format: 'WebAssembly',
    version,
    sections,
    types,
    imports,
    exports,
    function_type_indices,
    code_bodies,
    start_function_index,
    counts: {
      types: types.length,
      imports: imports.length,
      imported_functions,
      defined_functions: function_type_indices.length,
      exports: exports.length,
      code_bodies: code_bodies.length,
    },
    notes: [
      'Type, import, function, export, start and code-body framing are structurally indexed.',
      'Table, memory, global, element, data, data-count and tag sections currently expose bounded vector counts only.',
      'Function instruction streams, constant expressions, element/data initializers, typed references and extended proposals are not decoded.',
      'The parser is a bounded structural indexer, not a WebAssembly validator or decompiler.',
    ],
  };
}
