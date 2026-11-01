// JavaScript, src/formats/elf.mjs, Node.js 20+, endian-aware ELF header/section parser.

import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const MACHINES = new Map([[3,'x86'],[8,'MIPS'],[20,'PowerPC'],[21,'PowerPC64'],[40,'ARM'],[62,'x86-64'],[183,'AArch64'],[243,'RISC-V']]);
const TYPES = new Map([[0,'NONE'],[1,'REL'],[2,'EXEC'],[3,'DYN'],[4,'CORE']]);
const SECTION_TYPES = new Map([[0,'NULL'],[1,'PROGBITS'],[2,'SYMTAB'],[3,'STRTAB'],[4,'RELA'],[5,'HASH'],[6,'DYNAMIC'],[7,'NOTE'],[8,'NOBITS'],[9,'REL'],[11,'DYNSYM'],[14,'INIT_ARRAY'],[15,'FINI_ARRAY'],[16,'PREINIT_ARRAY'],[17,'GROUP'],[18,'SYMTAB_SHNDX']]);

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
    raw_sections.push({ index, name_offset, type: SECTION_TYPES.get(section_type) ?? `UNKNOWN_${section_type}`, flags: section_flags, address, file_offset, size, entry_size, raw_range_valid: section_type === 8 || (typeof file_offset === 'number' && typeof size === 'number' && file_offset <= buffer.length && size <= buffer.length - file_offset) });
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

  const expected_program_size = is_64 ? 56 : 32;
  const program_table_valid = program_header_count === 0 || (
    typeof program_header_offset === 'number' && program_header_entry_size >= expected_program_size &&
    program_header_offset <= buffer.length && program_header_entry_size * program_header_count <= buffer.length - program_header_offset
  );
  return {
    format: 'ELF', bitness: is_64 ? 64 : 32, endianness: little ? 'little' : 'big',
    architecture: MACHINES.get(machine) ?? `unknown-${machine}`,
    header: {
      type: TYPES.get(type) ?? `UNKNOWN_${type}`, machine, version, entry_point: entry,
      program_header_offset, program_header_entry_size, program_header_count,
      program_table_valid, section_header_offset, section_header_entry_size,
      section_header_count, section_name_index, header_size, flags,
    },
    sections,
    notes: ['Section names are resolved only when the section-name string table is present and fully in range.', 'Program headers are range-checked but not decoded into load segments in this release.'],
  };
}
