// JavaScript, src/formats/pe.mjs, Node.js 20+, bounded read-only PE parser with RVA, import and export analysis.

import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const MACHINES = new Map([
  [0x014c, 'x86'], [0x8664, 'x86-64'], [0x01c0, 'ARM'], [0x01c4, 'ARMv7'],
  [0xaa64, 'ARM64'], [0x0200, 'IA-64'], [0x5032, 'RISC-V 32'], [0x5064, 'RISC-V 64'],
]);
const SUBSYSTEMS = new Map([
  [1, 'Native'], [2, 'Windows GUI'], [3, 'Windows console'], [7, 'POSIX console'],
  [9, 'Windows CE GUI'], [10, 'EFI application'], [11, 'EFI boot service driver'],
  [12, 'EFI runtime driver'], [13, 'EFI ROM'], [14, 'Xbox'], [16, 'Windows boot application'],
]);
const SECTION_FLAGS = [
  [0x00000020, 'code'], [0x00000040, 'initialized-data'], [0x00000080, 'uninitialized-data'],
  [0x02000000, 'discardable'], [0x10000000, 'shared'], [0x20000000, 'execute'],
  [0x40000000, 'read'], [0x80000000, 'write'],
];
const DIRECTORY_NAMES = [
  'export', 'import', 'resource', 'exception', 'certificate', 'base-relocation', 'debug',
  'architecture', 'global-pointer', 'tls', 'load-config', 'bound-import', 'iat',
  'delay-import', 'clr-runtime', 'reserved',
];

function invalid(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function make_rva_mapper(reader, sections, size_of_headers) {
  return function rva_to_offset(rva, length = 1) {
    if (!Number.isSafeInteger(rva) || !Number.isSafeInteger(length) || rva < 0 || length < 0) return null;
    if (rva < size_of_headers && rva <= reader.buffer.length && length <= reader.buffer.length - rva) {
      return rva;
    }
    for (const section of sections) {
      const extent = Math.max(section.virtual_size, section.raw_size);
      if (rva < section.virtual_address || rva - section.virtual_address >= extent) continue;
      const delta = rva - section.virtual_address;
      if (delta > section.raw_size || length > section.raw_size - delta) return null;
      const offset = section.raw_offset + delta;
      if (offset > reader.buffer.length || length > reader.buffer.length - offset) return null;
      return offset;
    }
    return null;
  };
}

function read_rva_string(reader, map_rva, rva, label) {
  const offset = map_rva(rva, 1);
  if (offset === null) invalid('ORIX_PE_INVALID_RVA', 'PE string RVA cannot be mapped to file data', { rva, label });
  const maximum = Math.min(4096, reader.buffer.length - offset);
  let end = offset;
  while (end < offset + maximum && reader.buffer[end] !== 0) end += 1;
  if (end === offset + maximum) invalid('ORIX_PE_UNTERMINATED_STRING', 'PE string is not terminated within the parser bound', { rva, label, maximum });
  return reader.buffer.toString('utf8', offset, end);
}

function parse_imports(reader, directory, map_rva, is_64_bit, options) {
  if (!directory || directory.address === 0 || directory.size === 0) return { imports: [], truncated: false };
  const descriptor_size = 20;
  if (directory.size < descriptor_size) invalid('ORIX_PE_BAD_IMPORT_DIRECTORY', 'PE import directory is smaller than one descriptor');
  const max_descriptors = options.max_import_descriptors ?? 4096;
  const max_thunks = options.max_thunks_per_import ?? 8192;
  const descriptor_limit = Math.min(Math.floor(directory.size / descriptor_size), max_descriptors);
  const imports = [];
  let terminated = false;
  for (let index = 0; index < descriptor_limit; index += 1) {
    const descriptor_rva = directory.address + index * descriptor_size;
    const descriptor_offset = map_rva(descriptor_rva, descriptor_size);
    if (descriptor_offset === null) invalid('ORIX_PE_INVALID_IMPORT_DESCRIPTOR', 'PE import descriptor is outside mapped file data', { index, descriptor_rva });
    const original_thunk = reader.u32(descriptor_offset, true, 'import lookup table RVA');
    const timestamp = reader.u32(descriptor_offset + 4, true, 'import timestamp');
    const forwarder_chain = reader.u32(descriptor_offset + 8, true, 'import forwarder chain');
    const name_rva = reader.u32(descriptor_offset + 12, true, 'import library name RVA');
    const first_thunk = reader.u32(descriptor_offset + 16, true, 'import address table RVA');
    if (original_thunk === 0 && timestamp === 0 && forwarder_chain === 0 && name_rva === 0 && first_thunk === 0) {
      terminated = true;
      break;
    }
    const library = read_rva_string(reader, map_rva, name_rva, 'import library');
    const lookup_rva = original_thunk || first_thunk;
    const width = is_64_bit ? 8 : 4;
    const symbols = [];
    let thunk_terminated = false;
    for (let thunk_index = 0; thunk_index < max_thunks; thunk_index += 1) {
      const thunk_rva = lookup_rva + thunk_index * width;
      const thunk_offset = map_rva(thunk_rva, width);
      if (thunk_offset === null) invalid('ORIX_PE_INVALID_IMPORT_THUNK', 'PE import thunk is outside mapped file data', { library, thunk_index, thunk_rva });
      const value = is_64_bit
        ? reader.view.getBigUint64(thunk_offset, true)
        : BigInt(reader.u32(thunk_offset, true, 'import thunk'));
      if (value === 0n) {
        thunk_terminated = true;
        break;
      }
      const ordinal_flag = is_64_bit ? 0x8000000000000000n : 0x80000000n;
      if ((value & ordinal_flag) !== 0n) {
        symbols.push({ kind: 'ordinal', ordinal: Number(value & 0xffffn), hint: null, name: null });
      } else {
        const name_rva_value = Number(value & (is_64_bit ? 0x7fffffffffffffffn : 0x7fffffffn));
        if (!Number.isSafeInteger(name_rva_value)) invalid('ORIX_PE_INVALID_IMPORT_NAME', 'PE import name RVA is not safely representable', { library, thunk_index });
        const name_offset = map_rva(name_rva_value, 2);
        if (name_offset === null) invalid('ORIX_PE_INVALID_IMPORT_NAME', 'PE import name RVA is outside mapped file data', { library, thunk_index, name_rva: name_rva_value });
        const hint = reader.u16(name_offset, true, 'import hint');
        const name = read_rva_string(reader, map_rva, name_rva_value + 2, 'import symbol');
        symbols.push({ kind: 'name', ordinal: null, hint, name });
      }
    }
    imports.push({ library, original_first_thunk: original_thunk, first_thunk, timestamp, forwarder_chain, symbols, symbols_truncated: !thunk_terminated });
  }
  return { imports, truncated: !terminated };
}

function parse_delay_imports(reader, directory, map_rva, is_64_bit, image_base, options) {
  if (!directory || directory.address === 0 || directory.size === 0) return { imports: [], truncated: false };
  const descriptor_size = 32;
  if (directory.size < descriptor_size) invalid('ORIX_PE_BAD_DELAY_IMPORT_DIRECTORY', 'PE delay-import directory is smaller than one descriptor');
  const max_descriptors = options.max_delay_import_descriptors ?? options.max_import_descriptors ?? 2048;
  const max_thunks = options.max_thunks_per_import ?? 8192;
  if (!Number.isSafeInteger(max_descriptors) || max_descriptors < 1) invalid('ORIX_PE_DELAY_IMPORT_LIMIT', 'PE delay-import descriptor limit must be a positive safe integer', { max_descriptors });
  if (!Number.isSafeInteger(max_thunks) || max_thunks < 1) invalid('ORIX_PE_DELAY_THUNK_LIMIT', 'PE delay-import thunk limit must be a positive safe integer', { max_thunks });
  const descriptor_limit = Math.min(Math.floor(directory.size / descriptor_size), max_descriptors);
  const imports = [];
  let terminated = false;
  const to_rva = (value, rva_mode, field, index) => {
    if (value === 0 || rva_mode) return value;
    if (typeof image_base !== 'number' || !Number.isSafeInteger(image_base)) {
      invalid('ORIX_PE_DELAY_IMPORT_VA_UNSAFE', 'VA-based delay imports cannot be safely mapped with this image base', { field, index, image_base });
    }
    const converted = BigInt(value) - BigInt(image_base);
    if (converted < 0n || converted > BigInt(Number.MAX_SAFE_INTEGER)) {
      invalid('ORIX_PE_DELAY_IMPORT_VA_RANGE', 'VA-based delay-import field cannot be converted to a safe RVA', { field, index, value, image_base });
    }
    return Number(converted);
  };

  for (let index = 0; index < descriptor_limit; index += 1) {
    const descriptor_rva = directory.address + index * descriptor_size;
    const descriptor_offset = map_rva(descriptor_rva, descriptor_size);
    if (descriptor_offset === null) invalid('ORIX_PE_INVALID_DELAY_IMPORT_DESCRIPTOR', 'PE delay-import descriptor is outside mapped file data', { index, descriptor_rva });
    const fields = Array.from({ length: 8 }, (_, field) => reader.u32(descriptor_offset + field * 4, true, 'delay-import descriptor field'));
    if (fields.every(value => value === 0)) {
      terminated = true;
      break;
    }
    const [attributes, name_value, module_handle_value, iat_value, int_value, bound_iat_value, unload_iat_value, timestamp] = fields;
    const rva_mode = (attributes & 1) !== 0;
    const name_rva = to_rva(name_value, rva_mode, 'name', index);
    const module_handle_rva = to_rva(module_handle_value, rva_mode, 'module_handle', index);
    const iat_rva = to_rva(iat_value, rva_mode, 'iat', index);
    const int_rva = to_rva(int_value, rva_mode, 'int', index);
    const bound_iat_rva = to_rva(bound_iat_value, rva_mode, 'bound_iat', index);
    const unload_iat_rva = to_rva(unload_iat_value, rva_mode, 'unload_iat', index);
    if (name_rva === 0 || (int_rva === 0 && iat_rva === 0)) {
      invalid('ORIX_PE_BAD_DELAY_IMPORT_DESCRIPTOR', 'PE delay-import descriptor is missing its name or thunk table', { index, name_rva, int_rva, iat_rva });
    }
    const library = read_rva_string(reader, map_rva, name_rva, 'delay-import library');
    const lookup_rva = int_rva || iat_rva;
    const width = is_64_bit ? 8 : 4;
    const symbols = [];
    let thunk_terminated = false;
    for (let thunk_index = 0; thunk_index < max_thunks; thunk_index += 1) {
      const thunk_rva = lookup_rva + thunk_index * width;
      const thunk_offset = map_rva(thunk_rva, width);
      if (thunk_offset === null) invalid('ORIX_PE_INVALID_DELAY_IMPORT_THUNK', 'PE delay-import thunk is outside mapped file data', { library, thunk_index, thunk_rva });
      const value = is_64_bit
        ? reader.view.getBigUint64(thunk_offset, true)
        : BigInt(reader.u32(thunk_offset, true, 'delay-import thunk'));
      if (value === 0n) {
        thunk_terminated = true;
        break;
      }
      const ordinal_flag = is_64_bit ? 0x8000000000000000n : 0x80000000n;
      if ((value & ordinal_flag) !== 0n) {
        symbols.push({ kind: 'ordinal', ordinal: Number(value & 0xffffn), hint: null, name: null });
      } else {
        const symbol_rva = Number(value & (is_64_bit ? 0x7fffffffffffffffn : 0x7fffffffn));
        if (!Number.isSafeInteger(symbol_rva)) invalid('ORIX_PE_INVALID_DELAY_IMPORT_NAME', 'Delay-import name RVA is not safely representable', { library, thunk_index });
        const symbol_offset = map_rva(symbol_rva, 2);
        if (symbol_offset === null) invalid('ORIX_PE_INVALID_DELAY_IMPORT_NAME', 'Delay-import name RVA is outside mapped file data', { library, thunk_index, symbol_rva });
        const hint = reader.u16(symbol_offset, true, 'delay-import hint');
        const name = read_rva_string(reader, map_rva, symbol_rva + 2, 'delay-import symbol');
        symbols.push({ kind: 'name', ordinal: null, hint, name });
      }
    }
    imports.push({
      library, attributes, rva_mode, reserved_attributes: attributes & ~1,
      name_rva, module_handle_rva, iat_rva, int_rva, bound_iat_rva, unload_iat_rva,
      timestamp, symbols, symbols_truncated: !thunk_terminated,
    });
  }
  return { imports, truncated: !terminated };
}

function parse_exports(reader, directory, map_rva, options) {
  if (!directory || directory.address === 0 || directory.size === 0) return { exports: [], truncated: false, module_name: null };
  if (directory.size < 40) invalid('ORIX_PE_BAD_EXPORT_DIRECTORY', 'PE export directory is smaller than its fixed header');
  const offset = map_rva(directory.address, 40);
  if (offset === null) invalid('ORIX_PE_INVALID_EXPORT_DIRECTORY', 'PE export directory is outside mapped file data');
  const characteristics = reader.u32(offset, true, 'export characteristics');
  const timestamp = reader.u32(offset + 4, true, 'export timestamp');
  const major_version = reader.u16(offset + 8, true, 'export major version');
  const minor_version = reader.u16(offset + 10, true, 'export minor version');
  const name_rva = reader.u32(offset + 12, true, 'export module name RVA');
  const ordinal_base = reader.u32(offset + 16, true, 'export ordinal base');
  const function_count = reader.u32(offset + 20, true, 'export function count');
  const name_count = reader.u32(offset + 24, true, 'export name count');
  const functions_rva = reader.u32(offset + 28, true, 'export address table RVA');
  const names_rva = reader.u32(offset + 32, true, 'export name pointer table RVA');
  const ordinals_rva = reader.u32(offset + 36, true, 'export ordinal table RVA');
  const maximum = options.max_exports ?? 65536;
  if (function_count > maximum || name_count > maximum) {
    invalid('ORIX_PE_EXPORT_LIMIT', 'PE export table exceeds configured parser limit', { function_count, name_count, maximum });
  }
  const function_bytes = function_count * 4;
  const name_bytes = name_count * 4;
  const ordinal_bytes = name_count * 2;
  const function_offset = map_rva(functions_rva, function_bytes);
  const name_offset = map_rva(names_rva, name_bytes);
  const ordinal_offset = map_rva(ordinals_rva, ordinal_bytes);
  if ((function_count && function_offset === null) || (name_count && (name_offset === null || ordinal_offset === null))) {
    invalid('ORIX_PE_INVALID_EXPORT_TABLE', 'PE export arrays cannot be mapped to file data', { function_count, name_count });
  }
  const names = new Map();
  for (let index = 0; index < name_count; index += 1) {
    const symbol_name_rva = reader.u32(name_offset + index * 4, true, 'export name RVA');
    const function_index = reader.u16(ordinal_offset + index * 2, true, 'export ordinal index');
    if (function_index >= function_count) invalid('ORIX_PE_BAD_EXPORT_ORDINAL', 'PE export ordinal index exceeds function table', { index, function_index, function_count });
    names.set(function_index, read_rva_string(reader, map_rva, symbol_name_rva, 'export symbol'));
  }
  const exports = [];
  for (let index = 0; index < function_count; index += 1) {
    const function_rva = reader.u32(function_offset + index * 4, true, 'export function RVA');
    if (function_rva === 0) continue;
    const forwarded = function_rva >= directory.address && function_rva < directory.address + directory.size;
    exports.push({
      name: names.get(index) ?? null,
      ordinal: ordinal_base + index,
      rva: function_rva,
      forwarded,
      forwarder: forwarded ? read_rva_string(reader, map_rva, function_rva, 'export forwarder') : null,
    });
  }
  return {
    exports,
    truncated: false,
    module_name: name_rva ? read_rva_string(reader, map_rva, name_rva, 'export module name') : null,
    metadata: { characteristics, timestamp, major_version, minor_version, ordinal_base, function_count, name_count },
  };
}


function parse_base_relocations(reader, directory, map_rva, options) {
  if (!directory || directory.address === 0 || directory.size === 0) {
    return { blocks: [], relocations: [], truncated: false };
  }
  if (directory.size < 8) invalid('ORIX_PE_BAD_RELOCATION_DIRECTORY', 'PE base-relocation directory is smaller than one block header');
  const max_blocks = options.max_relocation_blocks ?? 4096;
  const max_relocations = options.max_relocations ?? 1_000_000;
  if (!Number.isSafeInteger(max_blocks) || max_blocks < 1) invalid('ORIX_PE_RELOCATION_BLOCK_LIMIT', 'PE relocation block limit must be a positive safe integer', { max_blocks });
  if (!Number.isSafeInteger(max_relocations) || max_relocations < 1) invalid('ORIX_PE_RELOCATION_LIMIT', 'PE relocation entry limit must be a positive safe integer', { max_relocations });
  const type_names = new Map([
    [0, 'ABSOLUTE'], [1, 'HIGH'], [2, 'LOW'], [3, 'HIGHLOW'], [4, 'HIGHADJ'],
    [5, 'ARCHITECTURE_SPECIFIC_5'], [6, 'ARCHITECTURE_SPECIFIC_6'],
    [7, 'ARCHITECTURE_SPECIFIC_7'], [8, 'ARCHITECTURE_SPECIFIC_8'],
    [9, 'ARCHITECTURE_SPECIFIC_9'], [10, 'DIR64'],
  ]);
  const widths = new Map([[1, 2], [2, 2], [3, 4], [4, 2], [10, 8]]);
  const blocks = [];
  const relocations = [];
  let cursor = 0;
  while (cursor < directory.size) {
    if (blocks.length >= max_blocks) invalid('ORIX_PE_RELOCATION_BLOCK_LIMIT', 'PE relocation block count exceeds configured limit', { maximum: max_blocks });
    if (directory.size - cursor < 8) invalid('ORIX_PE_RELOCATION_BLOCK_TRUNCATED', 'PE relocation directory ends inside a block header', { cursor, remaining: directory.size - cursor });
    const block_rva = directory.address + cursor;
    const block_offset = map_rva(block_rva, 8);
    if (block_offset === null) invalid('ORIX_PE_RELOCATION_BLOCK_RANGE', 'PE relocation block header is outside mapped file data', { block_rva });
    const page_rva = reader.u32(block_offset, true, 'relocation page RVA');
    const block_size = reader.u32(block_offset + 4, true, 'relocation block size');
    if (block_size < 8 || block_size > directory.size - cursor || (block_size - 8) % 2 !== 0) {
      invalid('ORIX_PE_RELOCATION_BLOCK_SIZE', 'PE relocation block has an invalid size', { cursor, block_size, remaining: directory.size - cursor });
    }
    const entry_count = (block_size - 8) / 2;
    if (entry_count > max_relocations - relocations.length) invalid('ORIX_PE_RELOCATION_LIMIT', 'PE relocation entry count exceeds configured limit', { maximum: max_relocations });
    const block = { page_rva, block_size, entry_count, first_relocation_index: relocations.length };
    blocks.push(block);
    for (let index = 0; index < entry_count; index += 1) {
      const encoded = reader.u16(block_offset + 8 + index * 2, true, 'base relocation entry');
      const type = encoded >>> 12;
      const page_offset = encoded & 0x0fff;
      const target_rva = page_rva + page_offset;
      if (!Number.isSafeInteger(target_rva) || target_rva > 0xffffffff) invalid('ORIX_PE_RELOCATION_TARGET_RANGE', 'PE relocation target RVA exceeds the 32-bit address space', { page_rva, page_offset });
      const width = widths.get(type) ?? null;
      const target_offset = width === null ? null : map_rva(target_rva, width);
      const relocation = {
        type, type_name: type_names.get(type) ?? 'UNKNOWN_' + type,
        page_rva, page_offset, target_rva, width,
        file_offset: target_offset, file_range_valid: target_offset !== null,
        paired_addend: null,
      };
      if (type === 4 && index + 1 < entry_count) {
        relocation.paired_addend = reader.u16(block_offset + 8 + (index + 1) * 2, true, 'HIGHADJ paired addend');
        index += 1;
      }
      relocations.push(relocation);
    }
    cursor += block_size;
  }
  return { blocks, relocations, truncated: false };
}

function parse_resources(reader, directory, map_rva, options) {
  if (!directory || directory.address === 0 || directory.size === 0) return { entries: [], directory_count: 0, truncated: false };
  const root_rva = directory.address;
  const root_size = directory.size;
  const max_depth = options.max_resource_depth ?? 8;
  const max_entries = options.max_resource_entries ?? 4096;
  const max_name_units = options.max_resource_name_units ?? 1024;
  let visited_entries = 0;
  let directory_count = 0;
  const visited_directories = new Set();
  function mapped_relative(relative, length, label) {
    if (!Number.isSafeInteger(relative) || relative < 0 || relative > root_size || length > root_size - relative) {
      invalid('ORIX_PE_RESOURCE_RANGE', 'PE resource structure exceeds its declared directory range', { relative, length, root_size, label });
    }
    const offset = map_rva(root_rva + relative, length);
    if (offset === null) invalid('ORIX_PE_RESOURCE_RVA', 'PE resource structure cannot be mapped to file data', { relative, length, label });
    return offset;
  }
  function read_name(name_field) {
    const relative = name_field & 0x7fffffff;
    const offset = mapped_relative(relative, 2, 'resource name length');
    const units = reader.u16(offset, true, 'resource name length');
    if (units > max_name_units) invalid('ORIX_PE_RESOURCE_NAME_LIMIT', 'PE resource name exceeds configured UTF-16 length limit', { units, max_name_units });
    const name_offset = mapped_relative(relative + 2, units * 2, 'resource name');
    return reader.bytes(name_offset, units * 2, 'resource name').toString('utf16le');
  }
  function walk(relative, depth, path_parts) {
    if (depth > max_depth) invalid('ORIX_PE_RESOURCE_DEPTH_LIMIT', 'PE resource tree exceeds configured depth', { depth, max_depth });
    if (visited_directories.has(relative)) invalid('ORIX_PE_RESOURCE_CYCLE', 'PE resource tree contains a directory cycle', { relative });
    visited_directories.add(relative);
    directory_count += 1;
    const header = mapped_relative(relative, 16, 'resource directory header');
    const named_count = reader.u16(header + 12, true, 'resource named entry count');
    const id_count = reader.u16(header + 14, true, 'resource ID entry count');
    const count = named_count + id_count;
    if (visited_entries + count > max_entries) invalid('ORIX_PE_RESOURCE_ENTRY_LIMIT', 'PE resource entries exceed configured limit', { visited_entries, count, max_entries });
    mapped_relative(relative + 16, count * 8, 'resource directory entries');
    const entries = [];
    for (let index = 0; index < count; index += 1) {
      visited_entries += 1;
      const at = mapped_relative(relative + 16 + index * 8, 8, 'resource directory entry');
      const name_field = reader.u32(at, true, 'resource entry name');
      const target_field = reader.u32(at + 4, true, 'resource entry target');
      const key = (name_field & 0x80000000) !== 0
        ? { name: read_name(name_field), id: null }
        : { name: null, id: name_field & 0xffff };
      const next_path = [...path_parts, key.name ?? key.id];
      if ((target_field & 0x80000000) !== 0) {
        entries.push({ ...key, kind: 'directory', entries: walk(target_field & 0x7fffffff, depth + 1, next_path) });
      } else {
        const data_relative = target_field & 0x7fffffff;
        const data_offset = mapped_relative(data_relative, 16, 'resource data entry');
        const data_rva = reader.u32(data_offset, true, 'resource data RVA');
        const data_size = reader.u32(data_offset + 4, true, 'resource data size');
        const codepage = reader.u32(data_offset + 8, true, 'resource code page');
        const reserved = reader.u32(data_offset + 12, true, 'resource reserved');
        const file_offset = map_rva(data_rva, data_size);
        entries.push({ ...key, kind: 'data', path: next_path, data_rva, data_size, codepage, reserved, file_offset, file_range_valid: file_offset !== null });
      }
    }
    visited_directories.delete(relative);
    return entries;
  }
  return { entries: walk(0, 0, []), directory_count, truncated: false };
}

function parse_certificates(reader, directory, buffer, options) {
  if (!directory || directory.address === 0 || directory.size === 0) return { certificates: [], range_valid: true, truncated: false };
  const offset = directory.address;
  const size = directory.size;
  if (offset > buffer.length || size > buffer.length - offset) {
    invalid('ORIX_PE_CERTIFICATE_RANGE', 'PE certificate table is outside the file', { offset, size, file_size: buffer.length });
  }
  const maximum = options.max_certificates ?? 1024;
  const certificates = [];
  const end = offset + size;
  let cursor = offset;
  while (cursor + 8 <= end) {
    if (certificates.length >= maximum) invalid('ORIX_PE_CERTIFICATE_LIMIT', 'PE certificate count exceeds configured limit', { maximum });
    const length = reader.u32(cursor, true, 'WIN_CERTIFICATE length');
    const revision = reader.u16(cursor + 4, true, 'WIN_CERTIFICATE revision');
    const type = reader.u16(cursor + 6, true, 'WIN_CERTIFICATE type');
    if (length < 8 || length > end - cursor) invalid('ORIX_PE_BAD_CERTIFICATE_RECORD', 'PE WIN_CERTIFICATE record has an invalid length', { cursor, length, remaining: end - cursor });
    certificates.push({ offset: cursor, length, revision: '0x' + revision.toString(16), type, payload_size: length - 8 });
    const aligned = Math.ceil(length / 8) * 8;
    if (aligned > end - cursor) {
      if (cursor + length === end) cursor = end;
      else invalid('ORIX_PE_BAD_CERTIFICATE_ALIGNMENT', 'PE certificate alignment exceeds the certificate table', { cursor, length, aligned, remaining: end - cursor });
    } else cursor += aligned;
  }
  if (cursor !== end) invalid('ORIX_PE_CERTIFICATE_TRAILING_BYTES', 'PE certificate table contains an incomplete trailing record', { cursor, end });
  return { certificates, range_valid: true, truncated: false };
}

export function parse_pe(buffer, options = {}) {
  const reader = new BinaryReader(buffer, { label: 'PE image' });
  if (reader.ascii(0, 2, 'DOS signature') !== 'MZ') {
    throw new OrixError('ORIX_PE_BAD_DOS_SIGNATURE', 'Input does not start with an MZ DOS header', { recoverable: true });
  }
  const pe_offset = reader.u32(0x3c, true, 'e_lfanew');
  if (pe_offset < 0x40 || pe_offset > buffer.length - 24) {
    throw new OrixError('ORIX_PE_INVALID_HEADER_OFFSET', 'PE header offset is outside the file', { details: { pe_offset, file_size: buffer.length }, recoverable: true });
  }
  if (reader.ascii(pe_offset, 4, 'PE signature') !== 'PE\0\0') {
    throw new OrixError('ORIX_PE_BAD_SIGNATURE', 'MZ file does not contain a valid PE signature at e_lfanew', { details: { pe_offset }, recoverable: true });
  }
  const coff_offset = pe_offset + 4;
  const machine = reader.u16(coff_offset, true, 'COFF machine');
  const section_count = reader.u16(coff_offset + 2, true, 'COFF section count');
  const timestamp = reader.u32(coff_offset + 4, true, 'COFF timestamp');
  const symbol_table_pointer = reader.u32(coff_offset + 8, true, 'COFF symbol table pointer');
  const symbol_count = reader.u32(coff_offset + 12, true, 'COFF symbol count');
  const optional_size = reader.u16(coff_offset + 16, true, 'optional header size');
  const characteristics = reader.u16(coff_offset + 18, true, 'COFF characteristics');
  const optional_offset = coff_offset + 20;
  if (optional_size < 2) invalid('ORIX_PE_MISSING_OPTIONAL_HEADER', 'PE optional header is missing');
  reader.require(optional_offset, optional_size, 'optional header');
  const magic = reader.u16(optional_offset, true, 'optional header magic');
  const is_64_bit = magic === 0x20b;
  if (magic !== 0x10b && magic !== 0x20b) invalid('ORIX_PE_UNSUPPORTED_OPTIONAL_MAGIC', 'Unsupported PE optional-header magic', { magic });
  const minimum_optional_size = is_64_bit ? 112 : 96;
  if (optional_size < minimum_optional_size) invalid('ORIX_PE_TRUNCATED_OPTIONAL_HEADER', 'PE optional header is smaller than its required fixed fields', { optional_size, minimum_optional_size });

  const image_base = is_64_bit ? reader.u64(optional_offset + 24, true, 'image base') : reader.u32(optional_offset + 28, true, 'image base');
  const entry_rva = reader.u32(optional_offset + 16, true, 'entry point RVA');
  const section_alignment = reader.u32(optional_offset + 32, true, 'section alignment');
  const file_alignment = reader.u32(optional_offset + 36, true, 'file alignment');
  const size_of_image = reader.u32(optional_offset + 56, true, 'size of image');
  const size_of_headers = reader.u32(optional_offset + 60, true, 'size of headers');
  const subsystem_value = reader.u16(optional_offset + 68, true, 'subsystem');
  const dll_characteristics = reader.u16(optional_offset + 70, true, 'DLL characteristics');
  const directory_count_offset = optional_offset + (is_64_bit ? 108 : 92);
  const directory_table_offset = optional_offset + (is_64_bit ? 112 : 96);
  const declared_directories = reader.u32(directory_count_offset, true, 'data directory count');
  const available_directories = Math.floor(Math.max(0, optional_offset + optional_size - directory_table_offset) / 8);
  const directory_count = Math.min(declared_directories, available_directories, 16);
  const directory_entries = Array.from({ length: 16 }, (_, index) => {
    if (index >= directory_count) return { name: DIRECTORY_NAMES[index], address: 0, size: 0, address_kind: index === 4 ? 'file-offset' : 'rva' };
    const offset = directory_table_offset + index * 8;
    return {
      name: DIRECTORY_NAMES[index],
      address: reader.u32(offset, true, 'data directory address'),
      size: reader.u32(offset + 4, true, 'data directory size'),
      address_kind: index === 4 ? 'file-offset' : 'rva',
    };
  });
  const data_directories = directory_entries.filter(entry => entry.address !== 0 || entry.size !== 0);
  const section_table_offset = optional_offset + optional_size;
  const maximum_sections = options.max_sections ?? 4096;
  if (!Number.isSafeInteger(maximum_sections) || maximum_sections < 0 || section_count > maximum_sections) {
    invalid('ORIX_PE_SECTION_LIMIT', 'PE section count exceeds configured parser limit', { section_count, maximum_sections });
  }
  reader.require(section_table_offset, section_count * 40, 'section table');
  const sections = [];
  for (let index = 0; index < section_count; index += 1) {
    const offset = section_table_offset + index * 40;
    const name = reader.bytes(offset, 8, 'section name').toString('ascii').replace(/\0.*$/s, '');
    const virtual_size = reader.u32(offset + 8, true, 'section virtual size');
    const virtual_address = reader.u32(offset + 12, true, 'section virtual address');
    const raw_size = reader.u32(offset + 16, true, 'section raw size');
    const raw_offset = reader.u32(offset + 20, true, 'section raw offset');
    const flags = reader.u32(offset + 36, true, 'section flags');
    sections.push({
      index, name, virtual_size, virtual_address, raw_size, raw_offset,
      raw_range_valid: raw_offset <= buffer.length && raw_size <= buffer.length - raw_offset,
      characteristics: SECTION_FLAGS.filter(([bit]) => (flags & bit) !== 0).map(([, label]) => label),
    });
  }
  const map_rva = make_rva_mapper(reader, sections, size_of_headers);
  const import_result = parse_imports(reader, directory_entries[1], map_rva, is_64_bit, options);
  const export_result = parse_exports(reader, directory_entries[0], map_rva, options);
  const resource_result = parse_resources(reader, directory_entries[2], map_rva, options);
  const delay_import_result = parse_delay_imports(reader, directory_entries[13], map_rva, is_64_bit, image_base, options);
  const relocation_result = parse_base_relocations(reader, directory_entries[5], map_rva, options);
  const certificate_result = parse_certificates(reader, directory_entries[4], buffer, options);

  return {
    format: 'PE',
    bitness: is_64_bit ? 64 : 32,
    architecture: MACHINES.get(machine) ?? 'unknown-0x' + machine.toString(16),
    machine: '0x' + machine.toString(16).padStart(4, '0'),
    header: {
      pe_offset, timestamp, section_count, optional_header_size: optional_size,
      symbol_table_pointer, symbol_count,
      characteristics: {
        executable_image: Boolean(characteristics & 0x0002),
        large_address_aware: Boolean(characteristics & 0x0020),
        dll: Boolean(characteristics & 0x2000),
        system: Boolean(characteristics & 0x1000),
      },
    },
    optional_header: {
      magic: is_64_bit ? 'PE32+' : 'PE32', image_base, entry_point_rva: entry_rva,
      section_alignment, file_alignment, size_of_image, size_of_headers,
      subsystem: SUBSYSTEMS.get(subsystem_value) ?? 'unknown-' + subsystem_value,
      dll_characteristics: {
        high_entropy_va: Boolean(dll_characteristics & 0x0020),
        dynamic_base: Boolean(dll_characteristics & 0x0040),
        force_integrity: Boolean(dll_characteristics & 0x0080),
        nx_compatible: Boolean(dll_characteristics & 0x0100),
        guard_cf: Boolean(dll_characteristics & 0x4000),
      },
      data_directories,
    },
    sections,
    address_mapping: { kind: 'RVA-to-file-offset', header_size: size_of_headers, mapped_sections: sections.filter(section => section.raw_range_valid).length },
    imports: import_result.imports,
    imports_truncated: import_result.truncated,
    delay_imports: delay_import_result.imports,
    delay_imports_truncated: delay_import_result.truncated,
    base_relocation_blocks: relocation_result.blocks,
    base_relocations: relocation_result.relocations,
    base_relocations_truncated: relocation_result.truncated,
    exports: export_result.exports,
    exports_truncated: export_result.truncated,
    export_module_name: export_result.module_name,
    export_metadata: export_result.metadata ?? null,
    resources: resource_result.entries,
    resource_directory_count: resource_result.directory_count,
    certificates: certificate_result.certificates,
    certificate_table_range_valid: certificate_result.range_valid,
    notes: [
      'PE imports, delay imports, exports, base-relocation records and resource trees are decoded from bounded file-backed RVAs; relocations are not applied and forwarded API resolution is not performed.',
      'The certificate directory uses a file offset and WIN_CERTIFICATE framing is decoded; certificate chains, Authenticode hashes and publisher trust are not verified.',
      'A valid PE signature does not prove that the file is safe. Parser output is structural evidence, not an execution verdict.',
    ],
  };
}
