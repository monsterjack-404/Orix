// JavaScript, src/formats/macho.mjs, Node.js 20+, read-only Mach-O header and load-command parser.

import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const MAGIC = new Map([
  ['feedface', { little: false, is_64: false }], ['cefaedfe', { little: true, is_64: false }],
  ['feedfacf', { little: false, is_64: true }], ['cffaedfe', { little: true, is_64: true }],
]);
const CPU = new Map([[7,'x86'],[0x01000007,'x86-64'],[12,'ARM'],[0x0100000c,'ARM64'],[18,'PowerPC'],[0x01000012,'PowerPC64']]);
const FAT_MAGIC = new Map([
  ['cafebabe', { little: false, is_64: false }], ['bebafeca', { little: true, is_64: false }],
  ['cafebabf', { little: false, is_64: true }], ['bfbafeca', { little: true, is_64: true }],
]);
const LC_SEGMENT = 0x1;
const LC_SEGMENT_64 = 0x19;
const LC_CODE_SIGNATURE = 0x1d;

function fixed_name(buffer, offset, length) {
  const bytes = buffer.subarray(offset, offset + length);
  const end = bytes.indexOf(0);
  return bytes.toString('utf8', 0, end < 0 ? bytes.length : end);
}

function decode_code_signature(reader, command_offset, command_size, file_size, little) {
  if (command_size < 16) throw new OrixError('ORIX_MACHO_BAD_CODE_SIGNATURE_COMMAND', 'Mach-O code-signature command is truncated', { recoverable: true });
  const data_offset = reader.u32(command_offset + 8, little, 'code-signature data offset');
  const data_size = reader.u32(command_offset + 12, little, 'code-signature data size');
  const range_valid = data_offset <= file_size && data_size <= file_size - data_offset;
  const result = { data_offset, data_size, range_valid, blob_magic: null, blob_length: null, slot_count: 0, slots: [], code_directories: [] };
  if (!range_valid || data_size < 12) return result;
  const magic = reader.u32(data_offset, false, 'signature blob magic');
  const length = reader.u32(data_offset + 4, false, 'signature blob length');
  result.blob_magic = '0x' + magic.toString(16);
  result.blob_length = length;
  if (magic !== 0xfade0cc0 || length < 12 || length > data_size) return result;
  const count = reader.u32(data_offset + 8, false, 'signature slot count');
  const maximum_slots = 1024;
  if (count > maximum_slots || count > Math.floor((length - 12) / 8)) {
    throw new OrixError('ORIX_MACHO_SIGNATURE_SLOT_LIMIT', 'Mach-O signature slot table exceeds its declared blob', { details: { count, length, maximum_slots }, recoverable: true });
  }
  result.slot_count = count;
  for (let index = 0; index < count; index += 1) {
    const entry = data_offset + 12 + index * 8;
    const slot_type = reader.u32(entry, false, 'signature slot type');
    const slot_offset = reader.u32(entry + 4, false, 'signature slot offset');
    if (slot_offset > length - 8) {
      result.slots.push({ type: slot_type, offset: slot_offset, valid: false });
      continue;
    }
    const blob = data_offset + slot_offset;
    const blob_magic = reader.u32(blob, false, 'signature slot magic');
    const blob_length = reader.u32(blob + 4, false, 'signature slot length');
    const valid = blob_length >= 8 && blob_length <= length - slot_offset;
    result.slots.push({ type: slot_type, offset: slot_offset, magic: '0x' + blob_magic.toString(16), length: blob_length, valid });
    if (!valid || blob_magic !== 0xfade0c02 || blob_length < 44) continue;
    const version = reader.u32(blob + 8, false, 'CodeDirectory version');
    const flags = reader.u32(blob + 12, false, 'CodeDirectory flags');
    const hash_offset = reader.u32(blob + 16, false, 'CodeDirectory hash offset');
    const identifier_offset = reader.u32(blob + 20, false, 'CodeDirectory identifier offset');
    const special_slots = reader.u32(blob + 24, false, 'CodeDirectory special slot count');
    const code_slots = reader.u32(blob + 28, false, 'CodeDirectory code slot count');
    const code_limit = reader.u32(blob + 32, false, 'CodeDirectory code limit');
    const hash_size = reader.u8(blob + 36, 'CodeDirectory hash size');
    const hash_type = reader.u8(blob + 37, 'CodeDirectory hash type');
    const platform = reader.u8(blob + 38, 'CodeDirectory platform');
    const page_size = reader.u8(blob + 39, 'CodeDirectory page size');
    const identifier = identifier_offset >= 44 && identifier_offset < blob_length ? reader.c_string(blob + identifier_offset, blob_length - identifier_offset, 'CodeDirectory identifier') : '';
    result.code_directories.push({ version, flags, hash_offset, identifier, special_slots, code_slots, code_limit, hash_size, hash_type, platform, page_size });
  }
  return result;
}

function parse_symbol_table(reader, command, is_64, little, options) {
  if (!command) return { table: null, symbols: [] };
  if (command.size < 24) throw new OrixError('ORIX_MACHO_BAD_SYMTAB_COMMAND', 'Mach-O LC_SYMTAB command is smaller than its fixed header', { details: { size: command.size }, recoverable: true });
  const symbol_offset = reader.u32(command.offset + 8, little, 'symbol table offset');
  const symbol_count = reader.u32(command.offset + 12, little, 'symbol count');
  const string_offset = reader.u32(command.offset + 16, little, 'symbol string-table offset');
  const string_size = reader.u32(command.offset + 20, little, 'symbol string-table size');
  const maximum_symbols = options.max_symbols ?? 100000;
  const maximum_string_bytes = options.max_symbol_string_bytes ?? 16 * 1024 * 1024;
  if (!Number.isSafeInteger(maximum_symbols) || maximum_symbols < 0 || symbol_count > maximum_symbols) {
    throw new OrixError('ORIX_MACHO_SYMBOL_LIMIT', 'Mach-O symbol count exceeds configured parser limit', { details: { symbol_count, maximum_symbols }, recoverable: true });
  }
  if (!Number.isSafeInteger(maximum_string_bytes) || maximum_string_bytes < 0 || string_size > maximum_string_bytes) {
    throw new OrixError('ORIX_MACHO_STRING_TABLE_LIMIT', 'Mach-O symbol string table exceeds configured parser limit', { details: { string_size, maximum_string_bytes }, recoverable: true });
  }
  const entry_size = is_64 ? 16 : 12;
  const symbol_bytes = symbol_count * entry_size;
  if (!Number.isSafeInteger(symbol_bytes)) throw new OrixError('ORIX_MACHO_SYMBOL_RANGE', 'Mach-O symbol table byte count is not safely representable', { recoverable: true });
  reader.require(symbol_offset, symbol_bytes, 'Mach-O nlist table');
  reader.require(string_offset, string_size, 'Mach-O symbol string table');
  const string_table = reader.bytes(string_offset, string_size, 'Mach-O symbol string table');
  const type_names = new Map([[0, 'UNDEFINED'], [2, 'ABSOLUTE'], [10, 'INDIRECT'], [12, 'PREBOUND_UNDEFINED'], [14, 'SECTION']]);
  const symbols = [];
  for (let index = 0; index < symbol_count; index += 1) {
    const at = symbol_offset + index * entry_size;
    const string_index = reader.u32(at, little, 'nlist string index');
    const raw_type = reader.u8(at + 4, 'nlist type');
    const section_index = reader.u8(at + 5, 'nlist section index');
    const description = reader.u16(at + 6, little, 'nlist description');
    const value = is_64 ? reader.u64(at + 8, little, 'nlist value') : reader.u32(at + 8, little, 'nlist value');
    let name = null;
    if (string_index !== 0) {
      if (string_index >= string_size) throw new OrixError('ORIX_MACHO_SYMBOL_STRING_INDEX', 'Mach-O symbol name index is outside its string table', { details: { index, string_index, string_size }, recoverable: true });
      const terminator = string_table.indexOf(0, string_index);
      if (terminator < 0) throw new OrixError('ORIX_MACHO_SYMBOL_STRING_UNTERMINATED', 'Mach-O symbol name is not NUL-terminated inside the string table', { details: { index, string_index }, recoverable: true });
      name = string_table.toString('utf8', string_index, terminator);
    }
    const type = raw_type & 0x0e;
    symbols.push({
      index,
      name,
      raw_type,
      type: type_names.get(type) ?? 'UNKNOWN_' + type,
      is_external: (raw_type & 0x01) !== 0,
      is_private_external: (raw_type & 0x10) !== 0,
      is_debug_symbol: (raw_type & 0xe0) !== 0,
      section_index,
      description,
      value,
    });
  }
  return {
    table: { symbol_offset, symbol_count, string_offset, string_size, entry_size, range_valid: true },
    symbols,
  };
}

function parse_dynamic_symbol_table(reader, command, is_64, little, symbol_result, options) {
  if (!command) return null;
  if (command.size < 80) throw new OrixError('ORIX_MACHO_BAD_DYSYMTAB_COMMAND', 'Mach-O LC_DYSYMTAB command is smaller than its fixed header', { details: { size: command.size }, recoverable: true });
  const names = [
    'local_symbol_index', 'local_symbol_count',
    'external_symbol_index', 'external_symbol_count',
    'undefined_symbol_index', 'undefined_symbol_count',
    'table_of_contents_offset', 'table_of_contents_count',
    'module_table_offset', 'module_table_count',
    'external_reference_offset', 'external_reference_count',
    'indirect_symbol_offset', 'indirect_symbol_count',
    'external_relocation_offset', 'external_relocation_count',
    'local_relocation_offset', 'local_relocation_count',
  ];
  const fields = {};
  for (let index = 0; index < names.length; index += 1) {
    fields[names[index]] = reader.u32(command.offset + 8 + index * 4, little, 'dynamic symbol table field');
  }
  const symbol_count = symbol_result.table?.symbol_count ?? 0;
  for (const [index_name, count_name] of [
    ['local_symbol_index', 'local_symbol_count'],
    ['external_symbol_index', 'external_symbol_count'],
    ['undefined_symbol_index', 'undefined_symbol_count'],
  ]) {
    const start = fields[index_name];
    const count = fields[count_name];
    if (start > symbol_count || count > symbol_count - start) {
      throw new OrixError('ORIX_MACHO_DYSYMTAB_SYMBOL_RANGE', 'Mach-O dynamic symbol group exceeds LC_SYMTAB symbol count', { details: { index_name, start, count, symbol_count }, recoverable: true });
    }
  }
  const ranges = {};
  const check_table = (name, offset, count, entry_size) => {
    const byte_size = count * entry_size;
    if (!Number.isSafeInteger(byte_size) || offset > reader.buffer.length || byte_size > reader.buffer.length - offset) {
      throw new OrixError('ORIX_MACHO_DYSYMTAB_RANGE', 'Mach-O dynamic symbol table range is outside the file', { details: { name, offset, count, entry_size, file_size: reader.buffer.length }, recoverable: true });
    }
    ranges[name] = { offset, count, entry_size, byte_size, range_valid: true };
  };
  check_table('table_of_contents', fields.table_of_contents_offset, fields.table_of_contents_count, 8);
  check_table('module_table', fields.module_table_offset, fields.module_table_count, is_64 ? 56 : 52);
  check_table('external_references', fields.external_reference_offset, fields.external_reference_count, 4);
  check_table('indirect_symbols', fields.indirect_symbol_offset, fields.indirect_symbol_count, 4);
  check_table('external_relocations', fields.external_relocation_offset, fields.external_relocation_count, 8);
  check_table('local_relocations', fields.local_relocation_offset, fields.local_relocation_count, 8);
  const maximum_indirect = options.max_indirect_symbols ?? 100000;
  if (!Number.isSafeInteger(maximum_indirect) || maximum_indirect < 0 || fields.indirect_symbol_count > maximum_indirect) {
    throw new OrixError('ORIX_MACHO_INDIRECT_SYMBOL_LIMIT', 'Mach-O indirect symbol count exceeds configured parser limit', { details: { count: fields.indirect_symbol_count, maximum_indirect }, recoverable: true });
  }
  const symbols_by_index = new Map(symbol_result.symbols.map(symbol => [symbol.index, symbol]));
  const indirect_symbols = [];
  for (let index = 0; index < fields.indirect_symbol_count; index += 1) {
    const raw_value = reader.u32(fields.indirect_symbol_offset + index * 4, little, 'indirect symbol entry');
    const is_local = (raw_value & 0x80000000) !== 0;
    const is_absolute = !is_local && (raw_value & 0x40000000) !== 0;
    const symbol_index = raw_value & 0x3fffffff;
    if (!is_local && !is_absolute && symbol_index >= symbol_count) {
      throw new OrixError('ORIX_MACHO_INDIRECT_SYMBOL_INDEX', 'Mach-O indirect symbol references an index outside LC_SYMTAB', { details: { index, symbol_index, symbol_count }, recoverable: true });
    }
    const symbol = !is_local && !is_absolute ? symbols_by_index.get(symbol_index) : null;
    indirect_symbols.push({
      index,
      raw_value,
      kind: is_local ? 'LOCAL' : is_absolute ? 'ABSOLUTE' : 'SYMBOL',
      symbol_index: is_local || is_absolute ? null : symbol_index,
      symbol_name: symbol?.name ?? null,
    });
  }
  return { ...fields, table_ranges: ranges, indirect_symbols };
}

export function parse_macho(buffer, options = {}) {
  const reader = new BinaryReader(buffer, { label: 'Mach-O image' });
  const magic = buffer.subarray(0, 4).toString('hex');
  const spec = MAGIC.get(magic);
  if (!spec) throw new OrixError('ORIX_MACHO_BAD_MAGIC', 'Input does not contain a supported thin Mach-O header', { recoverable: true });
  const minimum = spec.is_64 ? 32 : 28;
  reader.require(0, minimum, 'Mach-O header');
  const cpu_type = reader.i32(4, spec.little, 'CPU type');
  const cpu_subtype = reader.i32(8, spec.little, 'CPU subtype');
  const file_type = reader.u32(12, spec.little, 'file type');
  const command_count = reader.u32(16, spec.little, 'load-command count');
  const command_bytes = reader.u32(20, spec.little, 'load-command byte count');
  const flags = reader.u32(24, spec.little, 'Mach-O flags');
  const maximum_commands = options.max_commands ?? 8_192;
  if (command_count > maximum_commands) throw new OrixError('ORIX_MACHO_COMMAND_LIMIT', 'Mach-O load-command count exceeds configured limit', { details: { command_count, maximum_commands }, recoverable: true });
  const command_offset = minimum;
  reader.require(command_offset, command_bytes, 'load-command region');
  const commands = [];
  const segments = [];
  let code_signature = null;
  let symbol_table_command = null;
  let dynamic_symbol_table_command = null;
  let total_sections = 0;
  const maximum_sections = options.max_sections ?? 16384;
  let cursor = command_offset;
  for (let index = 0; index < command_count; index += 1) {
    reader.require(cursor, 8, `load command ${index}`);
    const command = reader.u32(cursor, spec.little, 'load-command ID');
    const size = reader.u32(cursor + 4, spec.little, 'load-command size');
    if (size < 8 || size > command_offset + command_bytes - cursor) {
      throw new OrixError('ORIX_MACHO_BAD_LOAD_COMMAND', 'Mach-O load command has an invalid size', { details: { index, command, size, cursor }, recoverable: true });
    }
    commands.push({ index, command: `0x${command.toString(16)}`, size });
    if (command === LC_SEGMENT || command === LC_SEGMENT_64) {
      const is_64_segment = command === LC_SEGMENT_64;
      const fixed_size = is_64_segment ? 72 : 56;
      const section_size = is_64_segment ? 80 : 68;
      if (size < fixed_size) throw new OrixError('ORIX_MACHO_BAD_SEGMENT_COMMAND', 'Mach-O segment command is smaller than its fixed header', { details: { index, size, fixed_size }, recoverable: true });
      const segment_name = fixed_name(buffer, cursor + 8, 16);
      let vm_address, vm_size, file_offset, file_size, max_protection, initial_protection, section_count, segment_flags;
      if (is_64_segment) {
        vm_address = reader.u64(cursor + 24, spec.little, 'segment VM address');
        vm_size = reader.u64(cursor + 32, spec.little, 'segment VM size');
        file_offset = reader.u64(cursor + 40, spec.little, 'segment file offset');
        file_size = reader.u64(cursor + 48, spec.little, 'segment file size');
        max_protection = reader.u32(cursor + 56, spec.little, 'maximum segment protection');
        initial_protection = reader.u32(cursor + 60, spec.little, 'initial segment protection');
        section_count = reader.u32(cursor + 64, spec.little, 'segment section count');
        segment_flags = reader.u32(cursor + 68, spec.little, 'segment flags');
      } else {
        vm_address = reader.u32(cursor + 24, spec.little, 'segment VM address');
        vm_size = reader.u32(cursor + 28, spec.little, 'segment VM size');
        file_offset = reader.u32(cursor + 32, spec.little, 'segment file offset');
        file_size = reader.u32(cursor + 36, spec.little, 'segment file size');
        max_protection = reader.u32(cursor + 40, spec.little, 'maximum segment protection');
        initial_protection = reader.u32(cursor + 44, spec.little, 'initial segment protection');
        section_count = reader.u32(cursor + 48, spec.little, 'segment section count');
        segment_flags = reader.u32(cursor + 52, spec.little, 'segment flags');
      }
      total_sections += section_count;
      if (total_sections > maximum_sections || section_count > Math.floor((size - fixed_size) / section_size)) {
        throw new OrixError('ORIX_MACHO_SECTION_LIMIT', 'Mach-O segment section table exceeds command bounds or configured limit', { details: { index, section_count, total_sections, maximum_sections, size }, recoverable: true });
      }
      const sections = [];
      for (let section_index = 0; section_index < section_count; section_index += 1) {
        const at = cursor + fixed_size + section_index * section_size;
        const section_name = fixed_name(buffer, at, 16);
        const section_segment = fixed_name(buffer, at + 16, 16);
        let address, section_file_size, section_offset, alignment, relocation_offset, relocation_count, section_flags;
        if (is_64_segment) {
          address = reader.u64(at + 32, spec.little, 'section address');
          section_file_size = reader.u64(at + 40, spec.little, 'section size');
          section_offset = reader.u32(at + 48, spec.little, 'section file offset');
          alignment = reader.u32(at + 52, spec.little, 'section alignment');
          relocation_offset = reader.u32(at + 56, spec.little, 'section relocation offset');
          relocation_count = reader.u32(at + 60, spec.little, 'section relocation count');
          section_flags = reader.u32(at + 64, spec.little, 'section flags');
        } else {
          address = reader.u32(at + 32, spec.little, 'section address');
          section_file_size = reader.u32(at + 36, spec.little, 'section size');
          section_offset = reader.u32(at + 40, spec.little, 'section file offset');
          alignment = reader.u32(at + 44, spec.little, 'section alignment');
          relocation_offset = reader.u32(at + 48, spec.little, 'section relocation offset');
          relocation_count = reader.u32(at + 52, spec.little, 'section relocation count');
          section_flags = reader.u32(at + 56, spec.little, 'section flags');
        }
        const valid_range = section_offset <= buffer.length && typeof section_file_size === 'number' && section_file_size <= buffer.length - section_offset;
        sections.push({ name: section_name, segment: section_segment, address, size: section_file_size, file_offset: section_offset, alignment, relocation_offset, relocation_count, flags: section_flags, file_range_valid: valid_range });
      }
      const numeric_file_offset = typeof file_offset === 'number' ? file_offset : null;
      const numeric_file_size = typeof file_size === 'number' ? file_size : null;
      segments.push({ name: segment_name, vm_address, vm_size, file_offset, file_size, max_protection, initial_protection, flags: segment_flags, file_range_valid: numeric_file_offset !== null && numeric_file_size !== null && numeric_file_offset <= buffer.length && numeric_file_size <= buffer.length - numeric_file_offset, sections });
    } else if (command === 0x2) {
      if (size < 24) throw new OrixError('ORIX_MACHO_BAD_SYMTAB_COMMAND', 'Mach-O LC_SYMTAB command is truncated', { details: { index, size }, recoverable: true });
      symbol_table_command = { offset: cursor, size };
    } else if (command === 0xb) {
      if (size < 80) throw new OrixError('ORIX_MACHO_BAD_DYSYMTAB_COMMAND', 'Mach-O LC_DYSYMTAB command is truncated', { details: { index, size }, recoverable: true });
      dynamic_symbol_table_command = { offset: cursor, size };
    } else if (command === LC_CODE_SIGNATURE) {
      code_signature = decode_code_signature(reader, cursor, size, buffer.length, spec.little);
    }
    cursor += size;
  }
  const symbol_result = parse_symbol_table(reader, symbol_table_command, spec.is_64, spec.little, options);
  const dynamic_symbol_result = parse_dynamic_symbol_table(reader, dynamic_symbol_table_command, spec.is_64, spec.little, symbol_result, options);
  return {
    format: 'Mach-O', bitness: spec.is_64 ? 64 : 32,
    endianness: spec.little ? 'little' : 'big', architecture: CPU.get(cpu_type) ?? `unknown-${cpu_type}`,
    header: { cpu_type, cpu_subtype, file_type, command_count, command_bytes, flags, reserved: spec.is_64 ? reader.u32(28, spec.little, 'reserved') : null },
    load_commands: commands,
    segments,
    symbol_table: symbol_result.table,
    symbols: symbol_result.symbols,
    dynamic_symbol_table: dynamic_symbol_result,
    indirect_symbols: dynamic_symbol_result?.indirect_symbols ?? [],
    code_signature,
    notes: ['Thin Mach-O segment and section commands are decoded with bounded counts and file-range checks.', 'Code-signature superblob and CodeDirectory metadata are structural observations only; cryptographic signature and trust verification are not performed.', 'LC_SYMTAB nlist records and bounded symbol strings are decoded when present. Universal/fat containers are parsed by parse_macho_fat. Other load-command payloads remain opaque.'],
  };
}


export function parse_macho_fat(buffer, options = {}) {
  const reader = new BinaryReader(buffer, { label: 'Universal Mach-O image' });
  const magic = buffer.subarray(0, 4).toString('hex');
  const spec = FAT_MAGIC.get(magic);
  if (!spec) throw new OrixError('ORIX_MACHO_FAT_BAD_MAGIC', 'Input does not contain a supported universal Mach-O signature', { recoverable: true });
  reader.require(0, 8, 'fat header');
  const architecture_count = reader.u32(4, spec.little, 'fat architecture count');
  const maximum = options.max_architectures ?? 128;
  if (!Number.isSafeInteger(maximum) || maximum < 0 || architecture_count > maximum) {
    throw new OrixError('ORIX_MACHO_FAT_ARCH_LIMIT', 'Universal Mach-O architecture count exceeds configured limit', { details: { architecture_count, maximum }, recoverable: true });
  }
  const entry_size = spec.is_64 ? 32 : 20;
  reader.require(8, architecture_count * entry_size, 'fat architecture table');
  const architectures = [];
  const slices = [];
  const ranges = [];
  for (let index = 0; index < architecture_count; index += 1) {
    const at = 8 + index * entry_size;
    const cpu_type = reader.i32(at, false, 'fat CPU type');
    const cpu_subtype = reader.i32(at + 4, false, 'fat CPU subtype');
    const offset_value = spec.is_64 ? reader.u64(at + 8, false, 'fat slice offset') : reader.u32(at + 8, false, 'fat slice offset');
    const size_value = spec.is_64 ? reader.u64(at + 16, false, 'fat slice size') : reader.u32(at + 12, false, 'fat slice size');
    const alignment = reader.u32(at + (spec.is_64 ? 24 : 16), false, 'fat slice alignment');
    if (typeof offset_value !== 'number' || typeof size_value !== 'number') {
      throw new OrixError('ORIX_MACHO_FAT_OFFSET_TOO_LARGE', 'Universal Mach-O slice range exceeds safe integer precision', { details: { index }, recoverable: true });
    }
    if (offset_value < 8 + architecture_count * entry_size || offset_value > buffer.length || size_value > buffer.length - offset_value) {
      throw new OrixError('ORIX_MACHO_FAT_SLICE_RANGE', 'Universal Mach-O slice is outside the file or overlaps its architecture table', { details: { index, offset: offset_value, size: size_value, file_size: buffer.length }, recoverable: true });
    }
    ranges.push({ start: offset_value, end: offset_value + size_value, index });
    const slice_buffer = buffer.subarray(offset_value, offset_value + size_value);
    let parsed = null;
    let parser_error = null;
    try { parsed = parse_macho(slice_buffer, options); }
    catch (error) { parser_error = { code: error.code ?? 'ORIX_MACHO_ERROR', message: error.message }; }
    const architecture = CPU.get(cpu_type) ?? 'unknown-' + cpu_type;
    architectures.push({ index, cpu_type, cpu_subtype, architecture, offset: offset_value, size: size_value, alignment, parser_status: parsed ? 'parsed' : 'rejected' });
    slices.push({ index, architecture, offset: offset_value, size: size_value, parsed, parser_error });
  }
  ranges.sort((a, b) => a.start - b.start);
  for (let index = 1; index < ranges.length; index += 1) {
    if (ranges[index].start < ranges[index - 1].end) {
      throw new OrixError('ORIX_MACHO_FAT_OVERLAPPING_SLICES', 'Universal Mach-O architecture slices overlap', { details: { first: ranges[index - 1].index, second: ranges[index].index }, recoverable: true });
    }
  }
  return { format: 'Mach-O Universal', is_64_bit_fat_header: spec.is_64, endianness: spec.little ? 'little' : 'big', architecture_count, architectures, slices, notes: ['Each architecture slice is parsed as a bounded thin Mach-O image when its header is supported.', 'Code-signature metadata is not cryptographically verified.'] };
}
