// JavaScript, src/formats/elf.mjs, Node.js 20+, endian-aware ELF header/section parser.

import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const MACHINES = new Map([[3,'x86'],[8,'MIPS'],[20,'PowerPC'],[21,'PowerPC64'],[40,'ARM'],[62,'x86-64'],[183,'AArch64'],[243,'RISC-V']]);
const TYPES = new Map([[0,'NONE'],[1,'REL'],[2,'EXEC'],[3,'DYN'],[4,'CORE']]);
const SECTION_TYPES = new Map([[0,'NULL'],[1,'PROGBITS'],[2,'SYMTAB'],[3,'STRTAB'],[4,'RELA'],[5,'HASH'],[6,'DYNAMIC'],[7,'NOTE'],[8,'NOBITS'],[9,'REL'],[11,'DYNSYM'],[14,'INIT_ARRAY'],[15,'FINI_ARRAY'],[16,'PREINIT_ARRAY'],[17,'GROUP'],[18,'SYMTAB_SHNDX'],[0x6ffffff6,'GNU_HASH']]);


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
  let total_chain_entries = 0;
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

function parse_gnu_symbol_versions(reader, raw_sections, symbol_result, is_64, little, options) {
  const maximum_records = options.max_version_records ?? 8192;
  const maximum_symbols = options.max_version_symbols ?? 100000;
  if (!Number.isSafeInteger(maximum_records) || maximum_records < 1) {
    throw new OrixError('ORIX_ELF_VERSION_RECORD_LIMIT', 'ELF version-record limit must be a positive safe integer', { recoverable: true });
  }
  if (!Number.isSafeInteger(maximum_symbols) || maximum_symbols < 1) {
    throw new OrixError('ORIX_ELF_VERSION_SYMBOL_LIMIT', 'ELF version-symbol limit must be a positive safe integer', { recoverable: true });
  }
  const version_map = new Map();
  const requirements = [];
  const definitions = [];
  let records_seen = 0;

  const get_strings = section => {
    const linked = raw_sections[section.link];
    if (!linked || linked.raw_type !== 3 || !linked.raw_range_valid || typeof linked.file_offset !== 'number' || typeof linked.size !== 'number') {
      throw new OrixError('ORIX_ELF_VERSION_STRTAB', 'ELF GNU version section does not link to a valid string table', { details: { section_index: section.index, link: section.link }, recoverable: true });
    }
    return reader.bytes(linked.file_offset, linked.size, 'GNU version string table');
  };
  const require_section_range = (section, relative_offset, length, label) => {
    if (!Number.isSafeInteger(relative_offset) || relative_offset < 0 || relative_offset > section.size || length > section.size - relative_offset) {
      throw new OrixError('ORIX_ELF_VERSION_RANGE', 'GNU version structure exceeds its containing section', { details: { section_index: section.index, relative_offset, length, section_size: section.size, label }, recoverable: true });
    }
    return section.file_offset + relative_offset;
  };

  for (const section of raw_sections) {
    if (section.raw_type !== 0x6ffffffe && section.raw_type !== 0x6ffffffd) continue;
    if (!section.raw_range_valid || typeof section.file_offset !== 'number' || typeof section.size !== 'number') {
      throw new OrixError('ORIX_ELF_VERSION_SECTION_RANGE', 'GNU version section is outside the file', { details: { section_index: section.index }, recoverable: true });
    }
    const strings = get_strings(section);
    let cursor = 0;
    const seen_records = new Set();
    while (cursor < section.size) {
      if (records_seen >= maximum_records) throw new OrixError('ORIX_ELF_VERSION_RECORD_LIMIT', 'GNU version record count exceeds configured limit', { details: { maximum_records }, recoverable: true });
      if (seen_records.has(cursor)) throw new OrixError('ORIX_ELF_VERSION_CYCLE', 'GNU version linked-record chain contains a cycle', { details: { section_index: section.index, cursor }, recoverable: true });
      seen_records.add(cursor);
      const is_need = section.raw_type === 0x6ffffffe;
      const header_size = is_need ? 16 : 20;
      const at = require_section_range(section, cursor, header_size, is_need ? 'Verneed' : 'Verdef');
      records_seen += 1;
      if (is_need) {
        const version = reader.u16(at, little, 'Verneed version');
        const count = reader.u16(at + 2, little, 'Verneed auxiliary count');
        const file_name_offset = reader.u32(at + 4, little, 'Verneed file string offset');
        const aux_offset = reader.u32(at + 8, little, 'Verneed auxiliary offset');
        const next_offset = reader.u32(at + 12, little, 'Verneed next offset');
        const library = read_elf_string(reader, strings, file_name_offset, 'Verneed library');
        const record = { section_index: section.index, version, library, auxiliary_count: count, auxiliary: [] };
        if (count > maximum_records - records_seen) throw new OrixError('ORIX_ELF_VERSION_RECORD_LIMIT', 'GNU version auxiliary count exceeds configured limit', { recoverable: true });
        if (count > 0 && aux_offset === 0) throw new OrixError('ORIX_ELF_VERSION_AUX_OFFSET', 'Verneed record has auxiliaries but no auxiliary offset', { details: { section_index: section.index, cursor }, recoverable: true });
        let aux_cursor = cursor + aux_offset;
        const seen_aux = new Set();
        for (let index = 0; index < count; index += 1) {
          if (seen_aux.has(aux_cursor)) throw new OrixError('ORIX_ELF_VERSION_CYCLE', 'Verneed auxiliary chain contains a cycle', { details: { section_index: section.index, aux_cursor }, recoverable: true });
          seen_aux.add(aux_cursor);
          const aux_at = require_section_range(section, aux_cursor, 16, 'Vernaux');
          records_seen += 1;
          if (records_seen > maximum_records) throw new OrixError('ORIX_ELF_VERSION_RECORD_LIMIT', 'GNU version record count exceeds configured limit', { details: { maximum_records }, recoverable: true });
          const hash = reader.u32(aux_at, little, 'Vernaux hash');
          const flags = reader.u16(aux_at + 4, little, 'Vernaux flags');
          const other = reader.u16(aux_at + 6, little, 'Vernaux version index');
          const name_offset = reader.u32(aux_at + 8, little, 'Vernaux name offset');
          const next_aux = reader.u32(aux_at + 12, little, 'Vernaux next offset');
          const name = read_elf_string(reader, strings, name_offset, 'Vernaux version name');
          const version_index = other & 0x7fff;
          const auxiliary = { hash, flags, version_index, hidden: (other & 0x8000) !== 0, name };
          record.auxiliary.push(auxiliary);
          if (version_index > 1) version_map.set(version_index, { name, source: 'need', library });
          if (index + 1 < count) {
            if (next_aux === 0) throw new OrixError('ORIX_ELF_VERSION_AUX_CHAIN', 'Verneed auxiliary chain ends before its declared count', { details: { section_index: section.index, index, count }, recoverable: true });
            aux_cursor += next_aux;
          }
        }
        requirements.push(record);
        if (next_offset === 0) break;
        cursor += next_offset;
      } else {
        const version = reader.u16(at, little, 'Verdef version');
        const flags = reader.u16(at + 2, little, 'Verdef flags');
        const version_index = reader.u16(at + 4, little, 'Verdef index') & 0x7fff;
        const count = reader.u16(at + 6, little, 'Verdef auxiliary count');
        const hash = reader.u32(at + 8, little, 'Verdef hash');
        const aux_offset = reader.u32(at + 12, little, 'Verdef auxiliary offset');
        const next_offset = reader.u32(at + 16, little, 'Verdef next offset');
        if (count === 0 || aux_offset === 0) throw new OrixError('ORIX_ELF_VERSION_AUX_OFFSET', 'Verdef record has no primary auxiliary name', { details: { section_index: section.index, cursor }, recoverable: true });
        if (count > maximum_records - records_seen) throw new OrixError('ORIX_ELF_VERSION_RECORD_LIMIT', 'Verdef auxiliary count exceeds configured limit', { recoverable: true });
        let aux_cursor = cursor + aux_offset;
        const names = [];
        const seen_aux = new Set();
        for (let index = 0; index < count; index += 1) {
          if (seen_aux.has(aux_cursor)) throw new OrixError('ORIX_ELF_VERSION_CYCLE', 'Verdef auxiliary chain contains a cycle', { details: { section_index: section.index, aux_cursor }, recoverable: true });
          seen_aux.add(aux_cursor);
          const aux_at = require_section_range(section, aux_cursor, 8, 'Verdaux');
          records_seen += 1;
          if (records_seen > maximum_records) throw new OrixError('ORIX_ELF_VERSION_RECORD_LIMIT', 'GNU version record count exceeds configured limit', { details: { maximum_records }, recoverable: true });
          const name_offset = reader.u32(aux_at, little, 'Verdaux name offset');
          const next_aux = reader.u32(aux_at + 4, little, 'Verdaux next offset');
          names.push(read_elf_string(reader, strings, name_offset, 'Verdaux version name'));
          if (index + 1 < count) {
            if (next_aux === 0) throw new OrixError('ORIX_ELF_VERSION_AUX_CHAIN', 'Verdef auxiliary chain ends before its declared count', { details: { section_index: section.index, index, count }, recoverable: true });
            aux_cursor += next_aux;
          }
        }
        const name = names[0] ?? '';
        const record = { section_index: section.index, version, flags, version_index, hash, names };
        definitions.push(record);
        if (version_index > 1) version_map.set(version_index, { name, source: 'definition', library: null });
        if (next_offset === 0) break;
        cursor += next_offset;
      }
    }
  }

  const symbol_versions = [];
  const symbols_by_table = new Map();
  for (const symbol of symbol_result.symbols) {
    if (!symbols_by_table.has(symbol.table_section_index)) symbols_by_table.set(symbol.table_section_index, new Map());
    symbols_by_table.get(symbol.table_section_index).set(symbol.index, symbol);
  }
  for (const section of raw_sections) {
    if (section.raw_type !== 0x6fffffff) continue;
    if (!section.raw_range_valid || typeof section.file_offset !== 'number' || typeof section.size !== 'number' || section.size % 2 !== 0) {
      throw new OrixError('ORIX_ELF_VERSYM_RANGE', 'GNU version-symbol table has an invalid file range or byte size', { details: { section_index: section.index, size: section.size }, recoverable: true });
    }
    const symbol_section = raw_sections[section.link];
    if (!symbol_section || symbol_section.raw_type !== 11 || !symbol_section.raw_range_valid || typeof symbol_section.size !== 'number') {
      throw new OrixError('ORIX_ELF_VERSYM_LINK', 'GNU version-symbol table must link to a valid DYNSYM section', { details: { section_index: section.index, link: section.link }, recoverable: true });
    }
    const symbol_entry_size = number_field(symbol_section.entry_size, 'Dynamic symbol entry size');
    const expected_symbol_size = is_64 ? 24 : 16;
    if (symbol_entry_size < expected_symbol_size || symbol_section.size % symbol_entry_size !== 0) {
      throw new OrixError('ORIX_ELF_VERSYM_SYMBOL_LAYOUT', 'Linked dynamic symbol table has an invalid entry layout', { details: { section_index: symbol_section.index }, recoverable: true });
    }
    const symbol_count = symbol_section.size / symbol_entry_size;
    const count = section.size / 2;
    if (count > maximum_symbols || symbol_versions.length + count > maximum_symbols || count !== symbol_count) {
      throw new OrixError('ORIX_ELF_VERSYM_COUNT', 'GNU version-symbol count does not match its linked dynamic symbol table', { details: { section_index: section.index, count, symbol_count, maximum_symbols }, recoverable: true });
    }
    const symbols_by_index = symbols_by_table.get(symbol_section.index) ?? new Map();
    for (let index = 0; index < count; index += 1) {
      const raw_value = reader.u16(section.file_offset + index * 2, little, 'GNU version-symbol entry');
      const version_index = raw_value & 0x7fff;
      const hidden = (raw_value & 0x8000) !== 0;
      const mapped = version_map.get(version_index) ?? null;
      const symbol = symbols_by_index.get(index) ?? null;
      symbol_versions.push({
        version_table_section_index: section.index, symbol_table_section_index: symbol_section.index,
        symbol_index: index, symbol_name: symbol?.name ?? null, version_index, hidden,
        version_name: version_index === 0 ? 'LOCAL' : version_index === 1 ? 'GLOBAL' : mapped?.name ?? null,
        source: mapped?.source ?? (version_index <= 1 ? 'reserved' : 'unresolved'),
        library: mapped?.library ?? null,
      });
    }
  }
  return { requirements, definitions, symbol_versions };
}

function parse_gnu_hash_tables(reader, raw_sections, symbol_result, is_64, little, options) {
  const maximum_buckets = options.max_gnu_hash_buckets ?? 1_000_000;
  const maximum_bloom_words = options.max_gnu_hash_bloom_words ?? 65_536;
  const maximum_chains = options.max_gnu_hash_chains ?? 1_000_000;
  const maximum_total_chain_entries = options.max_gnu_hash_total_entries ?? 2_000_000;
  for (const [name, value] of [['max_gnu_hash_buckets', maximum_buckets], ['max_gnu_hash_bloom_words', maximum_bloom_words], ['max_gnu_hash_chains', maximum_chains], ['max_gnu_hash_total_entries', maximum_total_chain_entries]]) {
    if (!Number.isSafeInteger(value) || value < 1) throw new OrixError('ORIX_ELF_GNU_HASH_LIMIT', name + ' must be a positive safe integer', { details: { name, value }, recoverable: true });
  }
  const tables = [];
  let total_chain_entries = 0;
  for (const section of raw_sections) {
    if (section.raw_type !== 0x6ffffff6) continue;
    if (!section.raw_range_valid) throw new OrixError('ORIX_ELF_GNU_HASH_RANGE', 'GNU hash section is outside file-backed input', { details: { section_index: section.index }, recoverable: true });
    const offset = number_field(section.file_offset, 'GNU hash file offset');
    const size = number_field(section.size, 'GNU hash section size');
    if (size < 16) throw new OrixError('ORIX_ELF_GNU_HASH_HEADER', 'GNU hash section is smaller than its fixed header', { details: { section_index: section.index, size }, recoverable: true });
    const linked = raw_sections[section.link];
    if (!linked || linked.raw_type !== 11 || !linked.raw_range_valid) {
      throw new OrixError('ORIX_ELF_GNU_HASH_LINK', 'GNU hash section must link to a valid DYNSYM section', { details: { section_index: section.index, link: section.link }, recoverable: true });
    }
    const symbol_size = number_field(linked.size, 'GNU hash linked symbol table size');
    const symbol_entry_size = number_field(linked.entry_size, 'GNU hash linked symbol entry size');
    const minimum_symbol_size = is_64 ? 24 : 16;
    if (symbol_entry_size < minimum_symbol_size || symbol_size % symbol_entry_size !== 0) {
      throw new OrixError('ORIX_ELF_GNU_HASH_SYMBOL_LAYOUT', 'GNU hash linked dynamic symbol table has an invalid entry layout', { details: { section_index: section.index, symbol_entry_size, symbol_size }, recoverable: true });
    }
    const symbol_count = symbol_size / symbol_entry_size;
    const bucket_count = reader.u32(offset, little, 'GNU hash bucket count');
    const symbol_offset = reader.u32(offset + 4, little, 'GNU hash symbol offset');
    const bloom_count = reader.u32(offset + 8, little, 'GNU hash bloom word count');
    const bloom_shift = reader.u32(offset + 12, little, 'GNU hash bloom shift');
    if (bloom_shift > 31) throw new OrixError('ORIX_ELF_GNU_HASH_BLOOM_SHIFT', 'GNU hash bloom shift must be between 0 and 31', { details: { bloom_shift }, recoverable: true });
    if (bucket_count < 1 || bucket_count > maximum_buckets) throw new OrixError('ORIX_ELF_GNU_HASH_BUCKET_LIMIT', 'GNU hash bucket count is outside configured bounds', { details: { bucket_count, maximum_buckets }, recoverable: true });
    if (bloom_count < 1 || bloom_count > maximum_bloom_words) throw new OrixError('ORIX_ELF_GNU_HASH_BLOOM_LIMIT', 'GNU hash bloom word count is outside configured bounds', { details: { bloom_count, maximum_bloom_words }, recoverable: true });
    if (symbol_offset > symbol_count) throw new OrixError('ORIX_ELF_GNU_HASH_SYMBOL_OFFSET', 'GNU hash symbol offset exceeds linked dynamic symbol count', { details: { symbol_offset, symbol_count }, recoverable: true });
    const word_size = is_64 ? 8 : 4;
    const bloom_bytes = bloom_count * word_size;
    const bucket_bytes = bucket_count * 4;
    const chain_offset = 16 + bloom_bytes + bucket_bytes;
    if (!Number.isSafeInteger(chain_offset) || chain_offset > size || (size - chain_offset) % 4 !== 0) {
      throw new OrixError('ORIX_ELF_GNU_HASH_LAYOUT', 'GNU hash bloom, bucket and chain arrays exceed or misalign the declared section', { details: { section_index: section.index, size, chain_offset }, recoverable: true });
    }
    const chain_count = (size - chain_offset) / 4;
    if (chain_count > maximum_chains) throw new OrixError('ORIX_ELF_GNU_HASH_CHAIN_LIMIT', 'GNU hash chain array exceeds configured limit', { details: { chain_count, maximum_chains }, recoverable: true });
    reader.require(offset, size, 'GNU hash section');
    const bloom_words = [];
    for (let index = 0; index < bloom_count; index += 1) {
      const value = is_64
        ? reader.view.getBigUint64(offset + 16 + index * word_size, little)
        : BigInt(reader.u32(offset + 16 + index * word_size, little, 'GNU hash bloom word'));
      bloom_words.push(value.toString());
    }
    const bucket_base = offset + 16 + bloom_bytes;
    const buckets = [];
    const chain_cache = new Map();
    for (let index = 0; index < bucket_count; index += 1) {
      const first_symbol = reader.u32(bucket_base + index * 4, little, 'GNU hash bucket');
      if (first_symbol === 0) {
        buckets.push({ index, first_symbol: 0, chain: [] });
        continue;
      }
      if (first_symbol < symbol_offset || first_symbol >= symbol_count) {
        throw new OrixError('ORIX_ELF_GNU_HASH_BUCKET_SYMBOL', 'GNU hash bucket points outside its linked dynamic symbol table', { details: { section_index: section.index, bucket: index, first_symbol, symbol_offset, symbol_count }, recoverable: true });
      }
      let chain = chain_cache.get(first_symbol);
      if (!chain) {
        chain = [];
        let symbol_index = first_symbol;
        while (symbol_index < symbol_count) {
          const chain_index = symbol_index - symbol_offset;
          if (chain_index >= chain_count) throw new OrixError('ORIX_ELF_GNU_HASH_CHAIN_RANGE', 'GNU hash chain is truncated before its terminal bit', { details: { section_index: section.index, bucket: index, symbol_index, chain_index, chain_count }, recoverable: true });
          total_chain_entries += 1;
          if (total_chain_entries > maximum_total_chain_entries) {
            throw new OrixError('ORIX_ELF_GNU_HASH_TOTAL_ENTRY_LIMIT', 'GNU hash chain traversal exceeds the aggregate work limit', { details: { section_index: section.index, maximum_total_chain_entries }, recoverable: true });
          }
          const hash = reader.u32(offset + chain_offset + chain_index * 4, little, 'GNU hash chain entry');
          chain.push({ symbol_index, hash, terminal: (hash & 1) !== 0 });
          if ((hash & 1) !== 0) break;
          symbol_index += 1;
        }
        if (chain.length === 0 || !chain.at(-1).terminal) {
          throw new OrixError('ORIX_ELF_GNU_HASH_CHAIN_UNTERMINATED', 'GNU hash chain does not contain a terminal entry', { details: { section_index: section.index, bucket: index }, recoverable: true });
        }
        chain_cache.set(first_symbol, chain);
      }
      buckets.push({ index, first_symbol, chain });
    }
    tables.push({
      section_index: section.index,
      symbol_table_section_index: linked.index,
      bucket_count,
      symbol_offset,
      bloom_count,
      bloom_shift,
      word_size,
      bloom_words,
      buckets,
      chain_count,
    });
  }
  return tables;
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
  if (version !== 1) throw new OrixError('ORIX_ELF_UNSUPPORTED_VERSION', 'Only the current ELF header version is supported', { details: { version }, recoverable: true });
  const entry = is_64 ? reader.u64(24, little, 'ELF entry point') : reader.u32(24, little, 'ELF entry point');
  const program_header_offset = is_64 ? reader.u64(32, little, 'program header offset') : reader.u32(28, little, 'program header offset');
  const section_header_offset = is_64 ? reader.u64(40, little, 'section header offset') : reader.u32(32, little, 'section header offset');
  const flags = reader.u32(is_64 ? 48 : 36, little, 'ELF flags');
  const header_size = reader.u16(is_64 ? 52 : 40, little, 'ELF header size');
  const program_header_entry_size = reader.u16(is_64 ? 54 : 42, little, 'program header entry size');
  let program_header_count = reader.u16(is_64 ? 56 : 44, little, 'program header count');
  const section_header_entry_size = reader.u16(is_64 ? 58 : 46, little, 'section header entry size');
  let section_header_count = reader.u16(is_64 ? 60 : 48, little, 'section header count');
  let section_name_index = reader.u16(is_64 ? 62 : 50, little, 'section name index');

  const expected_section_size = is_64 ? 64 : 40;
  const has_extended_section_count = section_header_count === 0 && section_header_offset !== 0;
  const has_extended_program_count = program_header_count === 0xffff;
  const has_extended_name_index = section_name_index === 0xffff;
  const uses_extended_numbering = has_extended_section_count || has_extended_program_count || has_extended_name_index;
  if (uses_extended_numbering) {
    if (typeof section_header_offset !== 'number' || section_header_offset === 0) {
      throw new OrixError('ORIX_ELF_EXTENDED_NUMBERING_MISSING', 'ELF extended numbering requires a readable section-header zero entry', { recoverable: true });
    }
    if (section_header_entry_size < expected_section_size) {
      throw new OrixError('ORIX_ELF_BAD_SECTION_ENTRY_SIZE', 'ELF section-header entry size is too small for extended numbering', { details: { section_header_entry_size, expected_section_size }, recoverable: true });
    }
    reader.require(section_header_offset, expected_section_size, 'extended numbering section header zero');
    const section_zero_size = is_64
      ? reader.u64(section_header_offset + 32, little, 'extended section count')
      : reader.u32(section_header_offset + 20, little, 'extended section count');
    const section_zero_link = reader.u32(section_header_offset + (is_64 ? 40 : 24), little, 'extended section-name index');
    const section_zero_info = reader.u32(section_header_offset + (is_64 ? 44 : 28), little, 'extended program-header count');
    if (has_extended_section_count) {
      section_header_count = number_field(section_zero_size, 'Extended section count');
      if (section_header_count === 0) throw new OrixError('ORIX_ELF_EXTENDED_SECTION_COUNT', 'ELF section-header zero declares an empty extended section table', { recoverable: true });
    }
    if (has_extended_name_index) section_name_index = section_zero_link;
    if (has_extended_program_count) program_header_count = section_zero_info;
  }

  const maximum_sections = options.max_sections ?? 4_096;
  if (section_header_count > maximum_sections) {
    throw new OrixError('ORIX_ELF_SECTION_LIMIT', 'ELF section count exceeds configured parser limit', { details: { section_header_count, maximum_sections }, recoverable: true });
  }
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
  const version_result = parse_gnu_symbol_versions(reader, raw_sections, symbol_result, is_64, little, options);
  const gnu_hash_tables = parse_gnu_hash_tables(reader, raw_sections, symbol_result, is_64, little, options);
  const dynamic_strings = resolve_dynamic_strings(program_result.dynamic, program_result.segments, buffer);
  return {
    format: 'ELF', bitness: is_64 ? 64 : 32, endianness: little ? 'little' : 'big',
    architecture: MACHINES.get(machine) ?? `unknown-${machine}`,
    header: {
      type: TYPES.get(type) ?? `UNKNOWN_${type}`, machine, version, entry_point: entry,
      program_header_offset, program_header_entry_size, program_header_count,
      extended_numbering: { section_count: has_extended_section_count, program_header_count: has_extended_program_count, section_name_index: has_extended_name_index },
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
    version_requirements: version_result.requirements,
    version_definitions: version_result.definitions,
    symbol_versions: version_result.symbol_versions,
    gnu_hash_tables,
    notes: ['Section names are resolved only when the section-name string table is present and fully in range.', 'Program headers, PT_INTERP, PT_NOTE GNU build IDs, PT_DYNAMIC entries, SHT_SYMTAB/SHT_DYNSYM symbols and SHT_REL/SHT_RELA relocation records are decoded when their file ranges and entry layouts are valid.', 'Relocation application and DWARF decoding are not implemented.'],
  };
}
