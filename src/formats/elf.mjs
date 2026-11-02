// JavaScript, src/formats/elf.mjs, Node.js 20+, endian-aware ELF header/section parser.

import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const MACHINES = new Map([[3,'x86'],[8,'MIPS'],[20,'PowerPC'],[21,'PowerPC64'],[40,'ARM'],[62,'x86-64'],[183,'AArch64'],[243,'RISC-V']]);
const TYPES = new Map([[0,'NONE'],[1,'REL'],[2,'EXEC'],[3,'DYN'],[4,'CORE']]);
const SECTION_TYPES = new Map([[0,'NULL'],[1,'PROGBITS'],[2,'SYMTAB'],[3,'STRTAB'],[4,'RELA'],[5,'HASH'],[6,'DYNAMIC'],[7,'NOTE'],[8,'NOBITS'],[9,'REL'],[11,'DYNSYM'],[14,'INIT_ARRAY'],[15,'FINI_ARRAY'],[16,'PREINIT_ARRAY'],[17,'GROUP'],[18,'SYMTAB_SHNDX']]);


const PROGRAM_TYPES = new Map([[0,'NULL'],[1,'LOAD'],[2,'DYNAMIC'],[3,'INTERP'],[4,'NOTE'],[5,'SHLIB'],[6,'PHDR'],[7,'TLS'],[0x6474e550,'GNU_EH_FRAME'],[0x6474e551,'GNU_STACK'],[0x6474e552,'GNU_RELRO']]);
const SYMBOL_TYPES = new Map([[0,'NOTYPE'],[1,'OBJECT'],[2,'FUNC'],[3,'SECTION'],[4,'FILE'],[5,'COMMON'],[6,'TLS'],[10,'IFUNC']]);
const SYMBOL_BINDINGS = new Map([[0,'LOCAL'],[1,'GLOBAL'],[2,'WEAK'],[10,'GNU_UNIQUE']]);
const DYNAMIC_TAGS = new Map([[0,'NULL'],[1,'NEEDED'],[2,'PLTRELSZ'],[3,'PLTGOT'],[4,'HASH'],[5,'STRTAB'],[6,'SYMTAB'],[7,'RELA'],[8,'RELASZ'],[9,'RELAENT'],[10,'STRSZ'],[11,'SYMENT'],[12,'INIT'],[13,'FINI'],[14,'SONAME'],[15,'RPATH'],[17,'REL'],[18,'RELSZ'],[19,'RELENT'],[20,'PLTREL'],[21,'DEBUG'],[22,'TEXTREL'],[23,'JMPREL'],[24,'BIND_NOW'],[25,'INIT_ARRAY'],[26,'FINI_ARRAY'],[27,'INIT_ARRAYSZ'],[28,'FINI_ARRAYSZ'],[29,'RUNPATH'],[30,'FLAGS'],[0x6ffffffb,'FLAGS_1'],[0x6ffffef5,'GNU_HASH'],[0x6ffffefc,'VERDEF'],[0x6ffffefd,'VERDEFNUM'],[0x6ffffffe,'VERNEED'],[0x6fffffff,'VERNEEDNUM']]);

function number_field(value, label) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new OrixError('ORIX_ELF_OFFSET_TOO_LARGE', label + ' exceeds the safe integer range', { details: { value: String(value) }, recoverable: true });
  }
  return value;
}

function read_elf_string(reader, table, offset, label) {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= table.length) return '';
  let end = offset;
  while (end < table.length && table[end] !== 0) end += 1;
  if (end === table.length) return '';
  return table.toString('utf8', offset, end);
}

function parse_program_headers(reader, buffer, is_64, little, table_offset_value, entry_size, count, options) {
  const maximum = options.max_program_headers ?? 4096;
  if (count > maximum) throw new OrixError('ORIX_ELF_PROGRAM_LIMIT', 'ELF program-header count exceeds configured parser limit', { details: { count, maximum }, recoverable: true });
  const expected = is_64 ? 56 : 32;
  if (count === 0) return { valid: true, segments: [], interpreter: null, build_id: null, dynamic: [] };
  if (entry_size < expected) throw new OrixError('ORIX_ELF_BAD_PROGRAM_ENTRY_SIZE', 'ELF program-header entry size is too small', { details: { entry_size, expected }, recoverable: true });
  const table_offset = number_field(table_offset_value, 'Program-header table offset');
  if (table_offset > buffer.length || entry_size * count > buffer.length - table_offset) {
    throw new OrixError('ORIX_ELF_PROGRAM_TABLE_RANGE', 'ELF program-header table exceeds the input', { details: { table_offset, entry_size, count, file_size: buffer.length }, recoverable: true });
  }
  const segments = [];
  let interpreter = null;
  let build_id = null;
  const dynamic = [];
  const dynamic_limit = options.max_dynamic_entries ?? 8192;
  for (let index = 0; index < count; index += 1) {
    const offset = table_offset + index * entry_size;
    const p_type = reader.u32(offset, little, 'program type');
    let p_flags, p_offset, virtual_address, physical_address, file_size, memory_size, alignment;
    if (is_64) {
      p_flags = reader.u32(offset + 4, little, 'program flags');
      p_offset = reader.u64(offset + 8, little, 'segment file offset');
      virtual_address = reader.u64(offset + 16, little, 'segment virtual address');
      physical_address = reader.u64(offset + 24, little, 'segment physical address');
      file_size = reader.u64(offset + 32, little, 'segment file size');
      memory_size = reader.u64(offset + 40, little, 'segment memory size');
      alignment = reader.u64(offset + 48, little, 'segment alignment');
    } else {
      p_offset = reader.u32(offset + 4, little, 'segment file offset');
      virtual_address = reader.u32(offset + 8, little, 'segment virtual address');
      physical_address = reader.u32(offset + 12, little, 'segment physical address');
      file_size = reader.u32(offset + 16, little, 'segment file size');
      memory_size = reader.u32(offset + 20, little, 'segment memory size');
      p_flags = reader.u32(offset + 24, little, 'program flags');
      alignment = reader.u32(offset + 28, little, 'segment alignment');
    }
    const numeric_offset = typeof p_offset === 'number' ? p_offset : null;
    const numeric_size = typeof file_size === 'number' ? file_size : null;
    const file_range_valid = numeric_offset !== null && numeric_size !== null && numeric_offset <= buffer.length && numeric_size <= buffer.length - numeric_offset;
    const segment = {
      index, type: PROGRAM_TYPES.get(p_type) ?? 'UNKNOWN_' + p_type, type_value: p_type,
      flags: { raw: p_flags, read: Boolean(p_flags & 4), write: Boolean(p_flags & 2), execute: Boolean(p_flags & 1) },
      file_offset: p_offset, virtual_address: virtual_address, physical_address,
      file_size, memory_size, alignment, file_range_valid,
    };
    segments.push(segment);
    if (!file_range_valid || numeric_size === 0) continue;
    if (p_type === 3) {
      const bytes = reader.bytes(numeric_offset, numeric_size, 'PT_INTERP');
      const end = bytes.indexOf(0);
      if (end < 0) throw new OrixError('ORIX_ELF_BAD_INTERPRETER', 'ELF interpreter segment is not NUL terminated', { details: { index, numeric_size }, recoverable: true });
      interpreter = bytes.toString('utf8', 0, end);
    }
    if (p_type === 4) {
      let cursor = numeric_offset;
      const end = numeric_offset + numeric_size;
      while (cursor + 12 <= end) {
        const namesz = reader.u32(cursor, little, 'note name size');
        const descsz = reader.u32(cursor + 4, little, 'note descriptor size');
        const note_type = reader.u32(cursor + 8, little, 'note type');
        const name_start = cursor + 12;
        const padded_name_size = Math.ceil(namesz / 4) * 4;
        const padded_desc_size = Math.ceil(descsz / 4) * 4;
        const desc_start = name_start + padded_name_size;
        const next = desc_start + padded_desc_size;
        if (!Number.isSafeInteger(next) || padded_name_size > end - name_start || padded_desc_size > end - desc_start || next > end) break;
        const note_name = reader.bytes(name_start, namesz, 'note name').toString('ascii').replace(/\0+$/, '');
        if (note_name === 'GNU' && note_type === 3 && descsz > 0 && descsz <= 64) {
          build_id = reader.bytes(desc_start, descsz, 'GNU build ID').toString('hex');
        }
        cursor = next;
      }
    }
    if (p_type === 2) {
      const width = is_64 ? 16 : 8;
      const total = Math.min(Math.floor(numeric_size / width), dynamic_limit);
      for (let item = 0; item < total; item += 1) {
        const at = numeric_offset + item * width;
        const tag = is_64 ? Number(reader.view.getBigInt64(at, little)) : reader.view.getInt32(at, little);
        const value = is_64 ? reader.u64(at + 8, little, 'dynamic value') : reader.u32(at + 4, little, 'dynamic value');
        dynamic.push({ tag, name: DYNAMIC_TAGS.get(tag) ?? 'UNKNOWN_' + tag, value });
        if (tag === 0) break;
      }
    }
  }
  return { valid: true, segments, interpreter, build_id, dynamic };
}



function resolve_dynamic_strings(dynamic, segments, buffer) {
  const string_table_value = dynamic.find(entry => entry.tag === 5)?.value;
  const string_size_value = dynamic.find(entry => entry.tag === 10)?.value;
  if (typeof string_table_value !== 'number' || typeof string_size_value !== 'number') {
    return { status: 'missing-string-table-metadata', needed_libraries: [], soname: null, rpath: null, runpath: null };
  }
  const segment = segments.find(item => item.type === 'LOAD' &&
    typeof item.virtual_address === 'number' && typeof item.file_offset === 'number' &&
    typeof item.file_size === 'number' && string_table_value >= item.virtual_address &&
    string_table_value - item.virtual_address <= item.file_size &&
    string_size_value <= item.file_size - (string_table_value - item.virtual_address));
  if (!segment) return { status: 'unmapped-string-table', needed_libraries: [], soname: null, rpath: null, runpath: null };
  const offset = segment.file_offset + (string_table_value - segment.virtual_address);
  if (offset > buffer.length || string_size_value > buffer.length - offset) {
    return { status: 'out-of-range-string-table', needed_libraries: [], soname: null, rpath: null, runpath: null };
  }
  const strings = buffer.subarray(offset, offset + string_size_value);
  const resolve = value => typeof value === 'number' ? read_elf_string(null, strings, value, 'dynamic string') : '';
  const needed_libraries = dynamic.filter(entry => entry.tag === 1).map(entry => resolve(entry.value));
  const first = tag => {
    const entry = dynamic.find(item => item.tag === tag);
    return entry ? resolve(entry.value) : null;
  };
  return { status: 'parsed', needed_libraries, soname: first(14), rpath: first(15), runpath: first(29) };
}

function parse_relocations(reader, raw_sections, is_64, little, options) {
  const maximum = options.max_relocations ?? 100000;
  const relocations = [];
  const tables = [];
  for (const section of raw_sections) {
    if (section.raw_type !== 4 && section.raw_type !== 9) continue;
    if (!section.raw_range_valid || typeof section.file_offset !== 'number' || typeof section.size !== 'number') {
      tables.push({ section_index: section.index, type: section.type, status: 'invalid-range', relocation_count: 0 });
      continue;
    }
    const rela = section.raw_type === 4;
    const linked_symbols = raw_sections[section.link];
    if (!linked_symbols || (linked_symbols.raw_type !== 2 && linked_symbols.raw_type !== 11) || !linked_symbols.raw_range_valid || typeof linked_symbols.size !== 'number') {
      tables.push({ section_index: section.index, type: section.type, status: 'invalid-symbol-table-link', relocation_count: 0 });
      continue;
    }
    const symbol_entry_size = number_field(linked_symbols.entry_size, 'Linked symbol entry size');
    const symbol_count = symbol_entry_size > 0 ? Math.floor(linked_symbols.size / symbol_entry_size) : 0;
    const expected = is_64 ? (rela ? 24 : 16) : (rela ? 12 : 8);
    const entry_size = number_field(section.entry_size, 'Relocation entry size');
    if (entry_size < expected || section.size % entry_size !== 0) {
      tables.push({ section_index: section.index, type: section.type, status: 'invalid-entry-size', relocation_count: 0 });
      continue;
    }
    const count = section.size / entry_size;
    if (count > maximum || relocations.length + count > maximum) {
      throw new OrixError('ORIX_ELF_RELOCATION_LIMIT', 'ELF relocation count exceeds configured parser limit', { details: { count, accumulated: relocations.length, maximum }, recoverable: true });
    }
    for (let index = 0; index < count; index += 1) {
      const at = section.file_offset + index * entry_size;
      let offset, info, addend = null, symbol_index, relocation_type;
      if (is_64) {
        offset = reader.u64(at, little, 'relocation offset');
        info = reader.view.getBigUint64(at + 8, little);
        symbol_index = Number(info >> 32n);
        relocation_type = Number(info & 0xffffffffn);
        if (rela) {
          const raw_addend = reader.view.getBigInt64(at + 16, little);
          addend = raw_addend <= BigInt(Number.MAX_SAFE_INTEGER) && raw_addend >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(raw_addend) : raw_addend.toString();
        }
      } else {
        offset = reader.u32(at, little, 'relocation offset');
        info = reader.u32(at + 4, little, 'relocation info');
        symbol_index = info >>> 8;
        relocation_type = info & 0xff;
        if (rela) addend = reader.view.getInt32(at + 8, little);
      }
      if (symbol_index >= symbol_count) throw new OrixError('ORIX_ELF_RELOCATION_SYMBOL_INDEX', 'ELF relocation references a symbol outside its linked symbol table', { details: { section_index: section.index, index, symbol_index, symbol_count, symbol_table_index: section.link }, recoverable: true });
      relocations.push({ table_section_index: section.index, index, target_section_index: section.info, symbol_table_index: section.link, offset, symbol_index, type: relocation_type, addend });
    }
    tables.push({ section_index: section.index, type: section.type, status: 'parsed', relocation_count: count, linked_symbol_table_index: section.link, linked_symbol_count: symbol_count, target_section_index: section.info });
  }
  return { relocations, tables };
}

function parse_symbol_tables(reader, buffer, raw_sections, is_64, little, options) {
  const maximum = options.max_symbols ?? 100000;
  const symbols = [];
  const tables = [];
  for (const section of raw_sections) {
    if (section.raw_type !== 2 && section.raw_type !== 11) continue;
    if (!section.raw_range_valid || typeof section.file_offset !== 'number' || typeof section.size !== 'number') {
      tables.push({ section_index: section.index, type: section.type, status: 'invalid-range', symbol_count: 0 });
      continue;
    }
    const expected = is_64 ? 24 : 16;
    const entry_size = number_field(section.entry_size, 'Symbol entry size');
    if (entry_size < expected || section.size % entry_size !== 0) {
      tables.push({ section_index: section.index, type: section.type, status: 'invalid-entry-size', symbol_count: 0 });
      continue;
    }
    const count = section.size / entry_size;
    if (count > maximum || symbols.length + count > maximum) {
      throw new OrixError('ORIX_ELF_SYMBOL_LIMIT', 'ELF symbol count exceeds configured parser limit', { details: { count, accumulated: symbols.length, maximum }, recoverable: true });
    }
    const linked = raw_sections[section.link];
    let strings = Buffer.alloc(0);
    if (linked && linked.type === 'STRTAB' && linked.raw_range_valid && typeof linked.file_offset === 'number' && typeof linked.size === 'number') {
      strings = reader.bytes(linked.file_offset, linked.size, 'symbol string table');
    }
    for (let index = 0; index < count; index += 1) {
      const at = section.file_offset + index * entry_size;
      const name_offset = reader.u32(at, little, 'symbol name offset');
      let info, other, section_index, value, size;
      if (is_64) {
        info = reader.u8(at + 4, 'symbol info');
        other = reader.u8(at + 5, 'symbol visibility');
        section_index = reader.u16(at + 6, little, 'symbol section index');
        value = reader.u64(at + 8, little, 'symbol value');
        size = reader.u64(at + 16, little, 'symbol size');
      } else {
        value = reader.u32(at + 4, little, 'symbol value');
        size = reader.u32(at + 8, little, 'symbol size');
        info = reader.u8(at + 12, 'symbol info');
        other = reader.u8(at + 13, 'symbol visibility');
        section_index = reader.u16(at + 14, little, 'symbol section index');
      }
      const name = read_elf_string(reader, strings, name_offset, 'symbol name');
      symbols.push({
        table_section_index: section.index, index, name,
        binding: SYMBOL_BINDINGS.get(info >> 4) ?? 'UNKNOWN_' + (info >> 4),
        type: SYMBOL_TYPES.get(info & 0x0f) ?? 'UNKNOWN_' + (info & 0x0f),
        visibility: other & 3, section_index, value, size,
      });
    }
    tables.push({ section_index: section.index, type: section.type, status: 'parsed', symbol_count: count, linked_string_table_index: section.link });
  }
  return { symbols, tables };
}

export function parse_elf(buffer, options = {}) {
  const reader = new BinaryReader(buffer, { label: 'ELF image' });
  if (reader.ascii(0, 4, 'ELF magic') !== '\x7fELF') throw new OrixError('ORIX_ELF_BAD_MAGIC', 'Input does not contain an ELF signature', { recoverable: true });
  const elf_class = reader.u8(4, 'ELF class');
  const data_encoding = reader.u8(5, 'ELF data encoding');
  if (![1, 2].includes(elf_class)) throw new OrixError('ORIX_ELF_UNSUPPORTED_CLASS', `Unsupported ELF class ${elf_class}`, { recoverable: true });
  if (![1, 2].includes(data_encoding)) throw new OrixError('ORIX_ELF_UNSUPPORTED_ENDIANNESS', `Unsupported ELF byte order ${data_encoding}`, { recoverable: true });
  reader.require(0, elf_class === 2 ? 64 : 52, 'ELF header');
  const little = data_encoding === 1;
  const is_64 = elf_class === 2;
  const type = reader.u16(16, little, 'ELF type');
  const machine = reader.u16(18, little, 'ELF machine');
  const version = reader.u32(20, little, 'ELF version');
  const entry = is_64 ? reader.u64(24, little, 'ELF entry point') : reader.u32(24, little, 'ELF entry point');
  const program_header_offset = is_64 ? reader.u64(32, little, 'program header offset') : reader.u32(28, little, 'program header offset');
  const section_header_offset = is_64 ? reader.u64(40, little, 'section header offset') : reader.u32(32, little, 'section header offset');
  const flags = reader.u32(is_64 ? 48 : 36, little, 'ELF flags');
  const header_size = reader.u16(is_64 ? 52 : 40, little, 'ELF header size');
  const program_header_entry_size = reader.u16(is_64 ? 54 : 42, little, 'program header entry size');
  const program_header_count = reader.u16(is_64 ? 56 : 44, little, 'program header count');
  const section_header_entry_size = reader.u16(is_64 ? 58 : 46, little, 'section header entry size');
  const section_header_count = reader.u16(is_64 ? 60 : 48, little, 'section header count');
  const section_name_index = reader.u16(is_64 ? 62 : 50, little, 'section name index');

  const maximum_sections = options.max_sections ?? 4_096;
  if (section_header_count > maximum_sections) {
    throw new OrixError('ORIX_ELF_SECTION_LIMIT', 'ELF section count exceeds configured parser limit', { details: { section_header_count, maximum_sections }, recoverable: true });
  }
  const expected_section_size = is_64 ? 64 : 40;
  if (section_header_count > 0 && section_header_entry_size < expected_section_size) {
    throw new OrixError('ORIX_ELF_BAD_SECTION_ENTRY_SIZE', 'ELF section-header entry size is too small', { details: { section_header_entry_size, expected_section_size }, recoverable: true });
  }
  if (section_header_count > 0) {
    if (typeof section_header_offset !== 'number') throw new OrixError('ORIX_ELF_OFFSET_TOO_LARGE', 'ELF section table offset exceeds safe integer range', { recoverable: true });
    reader.require(section_header_offset, section_header_entry_size * section_header_count, 'section header table');
  }

  const raw_sections = [];
  for (let index = 0; index < section_header_count; index += 1) {
    const offset = section_header_offset + index * section_header_entry_size;
    const name_offset = reader.u32(offset, little, 'section name offset');
    const section_type = reader.u32(offset + 4, little, 'section type');
    const section_flags = is_64 ? reader.u64(offset + 8, little, 'section flags') : reader.u32(offset + 8, little, 'section flags');
    const address = is_64 ? reader.u64(offset + 16, little, 'section address') : reader.u32(offset + 12, little, 'section address');
    const file_offset = is_64 ? reader.u64(offset + 24, little, 'section file offset') : reader.u32(offset + 16, little, 'section file offset');
    const size = is_64 ? reader.u64(offset + 32, little, 'section size') : reader.u32(offset + 20, little, 'section size');
    const entry_size = is_64 ? reader.u64(offset + 56, little, 'section entry size') : reader.u32(offset + 36, little, 'section entry size');
    const link = reader.u32(offset + (is_64 ? 40 : 24), little, 'section link');
    const info = reader.u32(offset + (is_64 ? 44 : 28), little, 'section info');
    const alignment = is_64 ? reader.u64(offset + 48, little, 'section alignment') : reader.u32(offset + 32, little, 'section alignment');
    raw_sections.push({ index, name_offset, raw_type: section_type, type: SECTION_TYPES.get(section_type) ?? `UNKNOWN_${section_type}`, flags: section_flags, address, file_offset, size, entry_size, link, info, alignment, raw_range_valid: section_type === 8 || (typeof file_offset === 'number' && typeof size === 'number' && file_offset <= buffer.length && size <= buffer.length - file_offset) });
  }

  let names = Buffer.alloc(0);
  if (section_name_index !== 0 && section_name_index < raw_sections.length) {
    const names_section = raw_sections[section_name_index];
    if (names_section.type === 'STRTAB' && names_section.raw_range_valid && typeof names_section.file_offset === 'number' && typeof names_section.size === 'number') {
      names = reader.bytes(names_section.file_offset, names_section.size, 'section-name string table');
    }
  }
  const sections = raw_sections.map(section => {
    let name = '';
    if (section.name_offset < names.length) {
      let end = section.name_offset;
      while (end < names.length && names[end] !== 0) end += 1;
      name = names.toString('utf8', section.name_offset, end);
    }
    return { index: section.index, name, type: section.type, flags: section.flags, address: section.address, file_offset: section.file_offset, size: section.size, entry_size: section.entry_size, raw_range_valid: section.raw_range_valid };
  });

  const program_result = parse_program_headers(reader, buffer, is_64, little, program_header_offset, program_header_entry_size, program_header_count, options);
  const symbol_result = parse_symbol_tables(reader, buffer, raw_sections, is_64, little, options);
  const relocation_result = parse_relocations(reader, raw_sections, is_64, little, options);
  const dynamic_strings = resolve_dynamic_strings(program_result.dynamic, program_result.segments, buffer);
  return {
    format: 'ELF', bitness: is_64 ? 64 : 32, endianness: little ? 'little' : 'big',
    architecture: MACHINES.get(machine) ?? `unknown-${machine}`,
    header: {
      type: TYPES.get(type) ?? `UNKNOWN_${type}`, machine, version, entry_point: entry,
      program_header_offset, program_header_entry_size, program_header_count,
      program_table_valid: program_result.valid, section_header_offset, section_header_entry_size,
      section_header_count, section_name_index, header_size, flags,
    },
    sections,
    program_headers: program_result.segments,
    interpreter: program_result.interpreter,
    gnu_build_id: program_result.build_id,
    dynamic_entries: program_result.dynamic,
    dynamic_strings,
    symbols: symbol_result.symbols,
    symbol_tables: symbol_result.tables,
    relocations: relocation_result.relocations,
    relocation_tables: relocation_result.tables,
    notes: ['Section names are resolved only when the section-name string table is present and fully in range.', 'Program headers, PT_INTERP, PT_NOTE GNU build IDs, PT_DYNAMIC entries, SHT_SYMTAB/SHT_DYNSYM symbols and SHT_REL/SHT_RELA relocation records are decoded when their file ranges and entry layouts are valid.', 'Extended ELF numbering, relocation application, GNU symbol version resolution and DWARF decoding are not implemented.'],
  };
}
