// JavaScript, src/formats/pe.mjs, Node.js 20+, bounded read-only PE/COFF header parser.

import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const MACHINES = new Map([
  [0x014c, 'x86'], [0x8664, 'x86-64'], [0x01c0, 'ARM'], [0x01c4, 'ARMv7'],
  [0xaa64, 'ARM64'], [0x0200, 'IA-64'], [0x5032, 'RISC-V 32'], [0x5064, 'RISC-V 64'],
]);
const SUBSYSTEMS = new Map([[1,'Native'],[2,'Windows GUI'],[3,'Windows console'],[7,'POSIX console'],[9,'Windows CE GUI'],[10,'EFI application'],[11,'EFI boot service driver'],[12,'EFI runtime driver'],[13,'EFI ROM'],[14,'Xbox'],[16,'Windows boot application']]);
const SECTION_FLAGS = [
  [0x00000020, 'code'], [0x00000040, 'initialized-data'], [0x00000080, 'uninitialized-data'],
  [0x02000000, 'discardable'], [0x10000000, 'shared'], [0x20000000, 'execute'],
  [0x40000000, 'read'], [0x80000000, 'write'],
];

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
  if (optional_size < 2) throw new OrixError('ORIX_PE_MISSING_OPTIONAL_HEADER', 'PE optional header is missing', { recoverable: true });
  reader.require(optional_offset, optional_size, 'optional header');

  const magic = reader.u16(optional_offset, true, 'optional header magic');
  const is_64_bit = magic === 0x20b;
  if (magic !== 0x10b && magic !== 0x20b) {
    throw new OrixError('ORIX_PE_UNSUPPORTED_OPTIONAL_MAGIC', `Unsupported PE optional-header magic 0x${magic.toString(16)}`, { recoverable: true });
  }
  const minimum_optional_size = is_64_bit ? 112 : 96;
  if (optional_size < minimum_optional_size) {
    throw new OrixError('ORIX_PE_TRUNCATED_OPTIONAL_HEADER', 'PE optional header is smaller than its required fixed fields', {
      details: { optional_size, minimum_optional_size }, recoverable: true,
    });
  }

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
  const directory_names = ['export','import','resource','exception','certificate','base-relocation','debug','architecture','global-pointer','tls','load-config','bound-import','iat','delay-import','clr-runtime','reserved'];
  const data_directories = [];
  for (let index = 0; index < directory_count; index += 1) {
    const offset = directory_table_offset + index * 8;
    const address = reader.u32(offset, true, 'data directory address');
    const size = reader.u32(offset + 4, true, 'data directory size');
    if (address || size) data_directories.push({ name: directory_names[index], address, size, address_kind: index === 4 ? 'file-offset' : 'rva' });
  }

  const section_table_offset = optional_offset + optional_size;
  const maximum_sections = options.max_sections ?? 4_096;
  if (section_count > maximum_sections) {
    throw new OrixError('ORIX_PE_SECTION_LIMIT', 'PE section count exceeds configured parser limit', { details: { section_count, maximum_sections }, recoverable: true });
  }
  reader.require(section_table_offset, section_count * 40, 'section table');
  const sections = [];
  for (let index = 0; index < section_count; index += 1) {
    const offset = section_table_offset + index * 40;
    const raw_name = reader.bytes(offset, 8, 'section name');
    const name = raw_name.toString('ascii').replace(/\0.*$/s, '');
    const virtual_size = reader.u32(offset + 8, true, 'section virtual size');
    const virtual_address = reader.u32(offset + 12, true, 'section virtual address');
    const raw_size = reader.u32(offset + 16, true, 'section raw size');
    const raw_offset = reader.u32(offset + 20, true, 'section raw offset');
    const flags = reader.u32(offset + 36, true, 'section flags');
    const characteristics_list = SECTION_FLAGS.filter(([bit]) => (flags & bit) !== 0).map(([, label]) => label);
    const raw_range_valid = raw_offset <= buffer.length && raw_size <= buffer.length - raw_offset;
    sections.push({
      index, name, virtual_size, virtual_address, raw_size, raw_offset,
      raw_range_valid,
      characteristics: characteristics_list,
    });
  }

  return {
    format: 'PE',
    bitness: is_64_bit ? 64 : 32,
    architecture: MACHINES.get(machine) ?? `unknown-0x${machine.toString(16)}`,
    machine: `0x${machine.toString(16).padStart(4, '0')}`,
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
      subsystem: SUBSYSTEMS.get(subsystem_value) ?? `unknown-${subsystem_value}`,
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
    notes: [
      'Header fields are parsed from the supplied byte range; a valid signature does not prove the file is safe.',
      'Section raw ranges are checked against the file; virtual address mapping and import resolution are not performed by this parser.',
    ],
  };
}
