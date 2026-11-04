// JavaScript, tests/formats.test.mjs, Node.js 20+, parser boundary and malformed-input coverage.

import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_pe } from '../src/formats/pe.mjs';
import { parse_elf } from '../src/formats/elf.mjs';
import { parse_macho, parse_macho_fat } from '../src/formats/macho.mjs';
import { parse_wasm } from '../src/formats/wasm.mjs';
import { parse_dex } from '../src/formats/dex.mjs';
import { analyze_known_format } from '../src/formats/index.mjs';
import { create_elf_fixture, create_pe_fixture, create_wasm_fixture } from './helpers.mjs';

test('PE32 parser reads machine, subsystem, entry point and section attributes', () => {
  const parsed = parse_pe(create_pe_fixture());
  assert.equal(parsed.bitness, 32);
  assert.equal(parsed.architecture, 'x86');
  assert.equal(parsed.optional_header.entry_point_rva, 0x1000);
  assert.equal(parsed.optional_header.subsystem, 'Windows console');
  assert.equal(parsed.sections[0].name, '.text');
  assert.equal(parsed.sections[0].raw_range_valid, true);
  assert.deepEqual(parsed.sections[0].characteristics, ['code','execute','read']);
});

test('PE32+ parser recognizes 64-bit images without converting image base to an imprecise number', () => {
  const parsed = parse_pe(create_pe_fixture({ is_64: true }));
  assert.equal(parsed.bitness, 64);
  assert.equal(parsed.architecture, 'x86-64');
  assert.equal(parsed.optional_header.image_base, Number(0x140000000n));
});

test('PE parser rejects MZ files without a PE signature', () => {
  const malformed = Buffer.alloc(128);
  malformed.write('MZ');
  malformed.writeUInt32LE(0x40, 0x3c);
  assert.throws(() => parse_pe(malformed), error => error.code === 'ORIX_PE_BAD_SIGNATURE');
});

test('ELF parser reports 64-bit little-endian executable metadata', () => {
  const parsed = parse_elf(create_elf_fixture());
  assert.equal(parsed.bitness, 64);
  assert.equal(parsed.endianness, 'little');
  assert.equal(parsed.architecture, 'x86-64');
  assert.equal(parsed.header.type, 'EXEC');
  assert.equal(parsed.header.entry_point, 0x401000);
  assert.equal(parsed.header.section_header_count, 0);
});

test('ELF parser rejects unsupported header versions', () => {
  const malformed = create_elf_fixture();
  malformed.writeUInt32LE(2, 20);
  assert.throws(() => parse_elf(malformed), error => error.code === 'ORIX_ELF_UNSUPPORTED_VERSION');
});

test('ELF parser rejects an invalid class instead of guessing', () => {
  const malformed = create_elf_fixture();
  malformed[4] = 9;
  assert.throws(() => parse_elf(malformed), error => error.code === 'ORIX_ELF_UNSUPPORTED_CLASS');
});

test('WebAssembly parser indexes bounded sections', () => {
  const parsed = parse_wasm(create_wasm_fixture());
  assert.equal(parsed.version, 1);
  assert.equal(parsed.sections.length, 1);
  assert.equal(parsed.sections[0].name, 'type');
  assert.equal(parsed.sections[0].payload_size, 1);
});

test('WebAssembly parser rejects invalid direct section limits', () => {
  const fixture = create_wasm_fixture();
  for (const max_sections of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 65_536]) {
    assert.throws(() => parse_wasm(fixture, { max_sections }), /max_sections must be an integer/);
  }
});

test('WebAssembly parser rejects unsupported binary versions', () => {
  const malformed = create_wasm_fixture();
  malformed.writeUInt32LE(2, 4);
  assert.throws(() => parse_wasm(malformed), error => error.code === 'ORIX_WASM_UNSUPPORTED_VERSION');
});

test('WebAssembly parser rejects a section that exceeds the file', () => {
  const malformed = Buffer.from([0,97,115,109,1,0,0,0,1,8,0]);
  assert.throws(() => parse_wasm(malformed), error => error.code === 'ORIX_WASM_SECTION_OUT_OF_RANGE');
});

test('WebAssembly parser rejects u32 LEB128 values whose fifth byte overflows', () => {
  const malformed = Buffer.from([0,97,115,109,1,0,0,0,1,0x80,0x80,0x80,0x80,0x10]);
  assert.throws(() => parse_wasm(malformed), error => error.code === 'ORIX_WASM_BAD_LEB128');
});

test('Mach-O parser validates a thin 64-bit header and load command region', () => {
  const buffer = Buffer.alloc(40);
  buffer.set([0xcf,0xfa,0xed,0xfe]);
  buffer.writeInt32LE(0x01000007, 4);
  buffer.writeInt32LE(3, 8);
  buffer.writeUInt32LE(2, 12);
  buffer.writeUInt32LE(1, 16);
  buffer.writeUInt32LE(8, 20);
  buffer.writeUInt32LE(0, 24);
  buffer.writeUInt32LE(0, 28);
  buffer.writeUInt32LE(0x80000022, 32);
  buffer.writeUInt32LE(8, 36);
  const parsed = parse_macho(buffer);
  assert.equal(parsed.bitness, 64);
  assert.equal(parsed.architecture, 'x86-64');
  assert.equal(parsed.load_commands.length, 1);
});

test('format dispatcher retains detection when a parser rejects malformed bytes', () => {
  const malformed = Buffer.alloc(64);
  malformed.write('MZ');
  malformed.writeUInt32LE(0x3c, 0x3c);
  const result = analyze_known_format(malformed);
  assert.equal(result.detection.format, 'PE');
  assert.equal(result.parser_status, 'rejected');
  assert.equal(result.parser_error.code, 'ORIX_PE_INVALID_HEADER_OFFSET');
});

test('ZIP parser reads central-directory entries without extracting content', async () => {
  const { parse_zip } = await import('../src/formats/zip.mjs');
  const { create_zip_fixture } = await import('./helpers.mjs');
  const parsed = parse_zip(create_zip_fixture('docs/readme.txt', 'ORIX archive fixture'));
  assert.equal(parsed.archive.total_entries, 1);
  assert.equal(parsed.entries[0].name, 'docs/readme.txt');
  assert.equal(parsed.entries[0].compression_method, 'stored');
  assert.equal(parsed.entries[0].local_header_valid, true);
  assert.equal(parsed.entries[0].local_data_range_valid, true);
  assert.equal(parsed.entries[0].unsafe_path, false);
});

test('ZIP parser flags parent-traversal paths and rejects ZIP64 sentinels', async () => {
  const { parse_zip } = await import('../src/formats/zip.mjs');
  const { create_zip_fixture } = await import('./helpers.mjs');
  const parsed = parse_zip(create_zip_fixture('../outside.txt'));
  assert.equal(parsed.entries[0].unsafe_path, true);
  const zip64 = create_zip_fixture();
  const eocd = zip64.length - 22;
  zip64.writeUInt16LE(0xffff, eocd + 8);
  zip64.writeUInt16LE(0xffff, eocd + 10);
  assert.throws(() => parse_zip(zip64), error => error.code === 'ORIX_ZIP64_LOCATOR_MISSING');
});


test('PE parser maps RVAs and decodes named imports and exports', () => {
  const buffer = create_pe_fixture();
  const pe = 0x80;
  const optional = pe + 4 + 20;
  const section = optional + 224;
  const raw = section + 40;
  const expanded = Buffer.concat([buffer, Buffer.alloc(0x300)]);
  expanded.writeUInt32LE(0x300, section + 16);

  const directory_table = optional + 96;
  expanded.writeUInt32LE(0x1200, directory_table);
  expanded.writeUInt32LE(0x80, directory_table + 4);
  expanded.writeUInt32LE(0x1100, directory_table + 8);
  expanded.writeUInt32LE(40, directory_table + 12);

  const import_offset = raw + 0x100;
  expanded.writeUInt32LE(0x1160, import_offset);
  expanded.writeUInt32LE(0x1150, import_offset + 12);
  expanded.writeUInt32LE(0x1168, import_offset + 16);
  expanded.write('KERNEL32.dll\0', raw + 0x150, 'ascii');
  expanded.writeUInt32LE(0x1180, raw + 0x160);
  expanded.writeUInt32LE(0, raw + 0x164);
  expanded.writeUInt16LE(7, raw + 0x180);
  expanded.write('CreateFileW\0', raw + 0x182, 'ascii');

  const export_offset = raw + 0x200;
  expanded.writeUInt32LE(0, export_offset);
  expanded.writeUInt32LE(0, export_offset + 4);
  expanded.writeUInt16LE(1, export_offset + 8);
  expanded.writeUInt16LE(0, export_offset + 10);
  expanded.writeUInt32LE(0x1250, export_offset + 12);
  expanded.writeUInt32LE(1, export_offset + 16);
  expanded.writeUInt32LE(1, export_offset + 20);
  expanded.writeUInt32LE(1, export_offset + 24);
  expanded.writeUInt32LE(0x1240, export_offset + 28);
  expanded.writeUInt32LE(0x1244, export_offset + 32);
  expanded.writeUInt32LE(0x1248, export_offset + 36);
  expanded.writeUInt32LE(0x1000, raw + 0x240);
  expanded.writeUInt32LE(0x1260, raw + 0x244);
  expanded.writeUInt16LE(0, raw + 0x248);
  expanded.write('sample.dll\0', raw + 0x250, 'ascii');
  expanded.write('ExportedEntry\0', raw + 0x260, 'ascii');

  const parsed = parse_pe(expanded);
  assert.equal(parsed.imports.length, 1);
  assert.equal(parsed.imports[0].library, 'KERNEL32.dll');
  assert.equal(parsed.imports[0].symbols[0].name, 'CreateFileW');
  assert.equal(parsed.imports[0].symbols[0].hint, 7);
  assert.equal(parsed.exports.length, 1);
  assert.equal(parsed.exports[0].name, 'ExportedEntry');
  assert.equal(parsed.exports[0].ordinal, 1);
  assert.equal(parsed.exports[0].rva, 0x1000);
  assert.equal(parsed.export_module_name, 'sample.dll');
});

test('PE parser rejects import descriptors whose RVA cannot map to file data', () => {
  const buffer = create_pe_fixture();
  const optional = 0x80 + 4 + 20;
  const directories = optional + 96;
  buffer.writeUInt32LE(0xfffffff0, directories + 8);
  buffer.writeUInt32LE(40, directories + 12);
  assert.throws(() => parse_pe(buffer), error => error.code === 'ORIX_PE_INVALID_IMPORT_DESCRIPTOR');
});

test('PE parser enforces configured section and import limits', () => {
  const buffer = create_pe_fixture();
  assert.throws(() => parse_pe(buffer, { max_sections: 0 }), error => error.code === 'ORIX_PE_SECTION_LIMIT');
});


function create_elf_analysis_fixture() {
  const buffer = Buffer.alloc(896);
  buffer.set([0x7f,0x45,0x4c,0x46,2,1,1,0]);
  buffer.writeUInt16LE(2, 16);
  buffer.writeUInt16LE(62, 18);
  buffer.writeUInt32LE(1, 20);
  buffer.writeBigUInt64LE(0x401000n, 24);
  buffer.writeBigUInt64LE(64n, 32);
  buffer.writeBigUInt64LE(256n, 40);
  buffer.writeUInt16LE(64, 52);
  buffer.writeUInt16LE(56, 54);
  buffer.writeUInt16LE(3, 56);
  buffer.writeUInt16LE(64, 58);
  buffer.writeUInt16LE(4, 60);
  buffer.writeUInt16LE(0, 62);

  buffer.writeUInt32LE(1, 64);
  buffer.writeUInt32LE(5, 68);
  buffer.writeBigUInt64LE(0n, 72);
  buffer.writeBigUInt64LE(0x400000n, 80);
  buffer.writeBigUInt64LE(0x400000n, 88);
  buffer.writeBigUInt64LE(896n, 96);
  buffer.writeBigUInt64LE(896n, 104);
  buffer.writeBigUInt64LE(0x1000n, 112);

  buffer.writeUInt32LE(4, 120);
  buffer.writeUInt32LE(4, 124);
  buffer.writeBigUInt64LE(600n, 128);
  buffer.writeBigUInt64LE(0n, 136);
  buffer.writeBigUInt64LE(0n, 144);
  buffer.writeBigUInt64LE(20n, 152);
  buffer.writeBigUInt64LE(20n, 160);
  buffer.writeBigUInt64LE(4n, 168);

  buffer.writeUInt32LE(2, 176);
  buffer.writeUInt32LE(4, 180);
  buffer.writeBigUInt64LE(720n, 184);
  buffer.writeBigUInt64LE(0x4002d0n, 192);
  buffer.writeBigUInt64LE(0x4002d0n, 200);
  buffer.writeBigUInt64LE(80n, 208);
  buffer.writeBigUInt64LE(80n, 216);
  buffer.writeBigUInt64LE(8n, 224);
  buffer.writeBigInt64LE(5n, 720);
  buffer.writeBigUInt64LE(0x400340n, 728);
  buffer.writeBigInt64LE(10n, 736);
  buffer.writeBigUInt64LE(16n, 744);
  buffer.writeBigInt64LE(1n, 752);
  buffer.writeBigUInt64LE(1n, 760);
  buffer.writeBigInt64LE(14n, 768);
  buffer.writeBigUInt64LE(9n, 776);
  buffer.writeBigInt64LE(0n, 784);
  buffer.writeBigUInt64LE(0n, 792);
  buffer.write('\0libc.so\0app.so\0', 832, 'binary');
  buffer.writeUInt32LE(4, 600);
  buffer.writeUInt32LE(4, 604);
  buffer.writeUInt32LE(3, 608);
  buffer.write('GNU\0', 612, 'ascii');
  buffer.set([0xde,0xad,0xbe,0xef], 616);

  const strtab = 320;
  buffer.writeUInt32LE(3, strtab + 4);
  buffer.writeBigUInt64LE(620n, strtab + 24);
  buffer.writeBigUInt64LE(6n, strtab + 32);
  buffer.writeBigUInt64LE(1n, strtab + 48);
  buffer.write('\0func\0', 620, 'binary');

  const symtab = 384;
  buffer.writeUInt32LE(11, symtab + 4);
  buffer.writeBigUInt64LE(640n, symtab + 24);
  buffer.writeBigUInt64LE(48n, symtab + 32);
  buffer.writeUInt32LE(1, symtab + 40);
  buffer.writeBigUInt64LE(8n, symtab + 48);
  buffer.writeBigUInt64LE(24n, symtab + 56);

  const rela = 448;
  buffer.writeUInt32LE(4, rela + 4);
  buffer.writeBigUInt64LE(688n, rela + 24);
  buffer.writeBigUInt64LE(24n, rela + 32);
  buffer.writeUInt32LE(2, rela + 40);
  buffer.writeUInt32LE(1, rela + 44);
  buffer.writeBigUInt64LE(8n, rela + 48);
  buffer.writeBigUInt64LE(24n, rela + 56);
  buffer.writeBigUInt64LE(0x401010n, 688);
  buffer.writeBigUInt64LE((1n << 32n) | 7n, 696);
  buffer.writeBigInt64LE(-4n, 704);
  buffer.writeUInt32LE(1, 664);
  buffer[668] = 0x12;
  buffer.writeUInt16LE(1, 670);
  buffer.writeBigUInt64LE(0x401000n, 672);
  buffer.writeBigUInt64LE(4n, 680);
  return buffer;
}

test('ELF parser decodes load segments, GNU build ID and dynamic symbols', () => {
  const parsed = parse_elf(create_elf_analysis_fixture());
  assert.equal(parsed.program_headers.length, 3);
  assert.equal(parsed.program_headers[0].type, 'LOAD');
  assert.equal(parsed.program_headers[0].flags.execute, true);
  assert.equal(parsed.program_headers[0].file_range_valid, true);
  assert.equal(parsed.gnu_build_id, 'deadbeef');
  assert.equal(parsed.dynamic_entries[2].name, 'NEEDED');
  assert.deepEqual(parsed.dynamic_strings.needed_libraries, ['libc.so']);
  assert.equal(parsed.dynamic_strings.soname, 'app.so');
  assert.equal(parsed.relocations.length, 1);
  assert.equal(parsed.relocations[0].symbol_index, 1);
  assert.equal(parsed.relocations[0].type, 7);
  assert.equal(parsed.relocations[0].addend, -4);
  assert.equal(parsed.symbols.length, 2);
  assert.equal(parsed.symbols[1].name, 'func');
  assert.equal(parsed.symbols[1].binding, 'GLOBAL');
  assert.equal(parsed.symbols[1].type, 'FUNC');
  assert.equal(parsed.symbols[1].value, 0x401000);
});

test('ELF parser rejects program-header ranges outside the input', () => {
  const buffer = create_elf_analysis_fixture();
  buffer.writeBigUInt64LE(0xffffn, 32);
  assert.throws(() => parse_elf(buffer), error => error.code === 'ORIX_ELF_PROGRAM_TABLE_RANGE');
});

test('ELF parser enforces configured program-header and symbol limits', () => {
  const buffer = create_elf_analysis_fixture();
  assert.throws(() => parse_elf(buffer, { max_program_headers: 1 }), error => error.code === 'ORIX_ELF_PROGRAM_LIMIT');
  assert.throws(() => parse_elf(buffer, { max_symbols: 1 }), error => error.code === 'ORIX_ELF_SYMBOL_LIMIT');
});


test('ELF32 big-endian parser decodes program-header field ordering', () => {
  const buffer = Buffer.alloc(128);
  buffer.set([0x7f,0x45,0x4c,0x46,1,2,1,0]);
  buffer.writeUInt16BE(2, 16);
  buffer.writeUInt16BE(3, 18);
  buffer.writeUInt32BE(1, 20);
  buffer.writeUInt32BE(0x08048054, 24);
  buffer.writeUInt32BE(52, 28);
  buffer.writeUInt32BE(0, 32);
  buffer.writeUInt32BE(0, 36);
  buffer.writeUInt16BE(52, 40);
  buffer.writeUInt16BE(32, 42);
  buffer.writeUInt16BE(1, 44);
  buffer.writeUInt16BE(40, 46);
  buffer.writeUInt16BE(0, 48);
  buffer.writeUInt16BE(0, 50);
  buffer.writeUInt32BE(1, 52);
  buffer.writeUInt32BE(0, 56);
  buffer.writeUInt32BE(0x08048000, 60);
  buffer.writeUInt32BE(0x08048000, 64);
  buffer.writeUInt32BE(128, 68);
  buffer.writeUInt32BE(160, 72);
  buffer.writeUInt32BE(5, 76);
  buffer.writeUInt32BE(4096, 80);
  const parsed = parse_elf(buffer);
  assert.equal(parsed.bitness, 32);
  assert.equal(parsed.endianness, 'big');
  assert.equal(parsed.program_headers[0].file_offset, 0);
  assert.equal(parsed.program_headers[0].virtual_address, 0x08048000);
  assert.equal(parsed.program_headers[0].memory_size, 160);
  assert.equal(parsed.program_headers[0].flags.execute, true);
});


test('Mach-O parser decodes segment and section commands with file ranges', () => {
  const buffer = Buffer.alloc(184);
  buffer.set([0xcf,0xfa,0xed,0xfe]);
  buffer.writeInt32LE(0x01000007, 4);
  buffer.writeInt32LE(3, 8);
  buffer.writeUInt32LE(2, 12);
  buffer.writeUInt32LE(1, 16);
  buffer.writeUInt32LE(152, 20);
  buffer.writeUInt32LE(0, 24);
  buffer.writeUInt32LE(0, 28);
  buffer.writeUInt32LE(0x19, 32);
  buffer.writeUInt32LE(152, 36);
  buffer.write('__TEXT', 40, 'ascii');
  buffer.writeBigUInt64LE(0x1000n, 56);
  buffer.writeBigUInt64LE(0x1000n, 64);
  buffer.writeBigUInt64LE(0n, 72);
  buffer.writeBigUInt64LE(184n, 80);
  buffer.writeUInt32LE(7, 88);
  buffer.writeUInt32LE(5, 92);
  buffer.writeUInt32LE(1, 96);
  buffer.writeUInt32LE(0, 100);
  buffer.write('__text', 104, 'ascii');
  buffer.write('__TEXT', 120, 'ascii');
  buffer.writeBigUInt64LE(0x1000n, 136);
  buffer.writeBigUInt64LE(4n, 144);
  buffer.writeUInt32LE(180, 152);
  buffer.writeUInt32LE(2, 156);
  const parsed = parse_macho(buffer);
  assert.equal(parsed.segments.length, 1);
  assert.equal(parsed.segments[0].name, '__TEXT');
  assert.equal(parsed.segments[0].sections[0].name, '__text');
  assert.equal(parsed.segments[0].sections[0].file_range_valid, true);
});

test('Mach-O parser extracts bounded CodeDirectory metadata without claiming trust', () => {
  const buffer = Buffer.alloc(117);
  buffer.set([0xcf,0xfa,0xed,0xfe]);
  buffer.writeInt32LE(0x01000007, 4);
  buffer.writeInt32LE(3, 8);
  buffer.writeUInt32LE(2, 12);
  buffer.writeUInt32LE(1, 16);
  buffer.writeUInt32LE(16, 20);
  buffer.writeUInt32LE(0, 24);
  buffer.writeUInt32LE(0, 28);
  buffer.writeUInt32LE(0x1d, 32);
  buffer.writeUInt32LE(16, 36);
  buffer.writeUInt32LE(48, 40);
  buffer.writeUInt32LE(69, 44);
  buffer.writeUInt32BE(0xfade0cc0, 48);
  buffer.writeUInt32BE(69, 52);
  buffer.writeUInt32BE(1, 56);
  buffer.writeUInt32BE(0, 60);
  buffer.writeUInt32BE(20, 64);
  buffer.writeUInt32BE(0xfade0c02, 68);
  buffer.writeUInt32BE(49, 72);
  buffer.writeUInt32BE(0x20001, 76);
  buffer.writeUInt32BE(2, 80);
  buffer.writeUInt32BE(44, 84);
  buffer.writeUInt32BE(44, 88);
  buffer.writeUInt32BE(0, 92);
  buffer.writeUInt32BE(1, 96);
  buffer.writeUInt32BE(4, 100);
  buffer[104] = 20;
  buffer[105] = 2;
  buffer[106] = 0;
  buffer[107] = 12;
  buffer.write('test\0', 112, 'ascii');
  const parsed = parse_macho(buffer);
  assert.equal(parsed.code_signature.range_valid, true);
  assert.equal(parsed.code_signature.slot_count, 1);
  assert.equal(parsed.code_signature.code_directories[0].identifier, 'test');
  assert.equal(parsed.code_signature.code_directories[0].hash_type, 2);
});

test('Universal Mach-O parser indexes and parses architecture slices', () => {
  const thin = Buffer.alloc(32);
  thin.set([0xcf,0xfa,0xed,0xfe]);
  thin.writeInt32LE(0x01000007, 4);
  thin.writeInt32LE(3, 8);
  thin.writeUInt32LE(2, 12);
  const fat = Buffer.alloc(60);
  fat.writeUInt32BE(0xcafebabe, 0);
  fat.writeUInt32BE(1, 4);
  fat.writeInt32BE(0x01000007, 8);
  fat.writeInt32BE(3, 12);
  fat.writeUInt32BE(28, 16);
  fat.writeUInt32BE(thin.length, 20);
  fat.writeUInt32BE(0, 24);
  thin.copy(fat, 28);
  const parsed = parse_macho_fat(fat);
  assert.equal(parsed.architecture_count, 1);
  assert.equal(parsed.architectures[0].architecture, 'x86-64');
  assert.equal(parsed.slices[0].parsed.bitness, 64);
});

test('Universal Mach-O parser rejects overlapping architecture slices', () => {
  const fat = Buffer.alloc(96);
  fat.writeUInt32BE(0xcafebabe, 0);
  fat.writeUInt32BE(2, 4);
  fat.writeInt32BE(7, 8);
  fat.writeInt32BE(3, 12);
  fat.writeUInt32BE(48, 16);
  fat.writeUInt32BE(32, 20);
  fat.writeUInt32BE(0, 24);
  fat.writeInt32BE(0x01000007, 28);
  fat.writeInt32BE(3, 32);
  fat.writeUInt32BE(64, 36);
  fat.writeUInt32BE(32, 40);
  fat.writeUInt32BE(0, 44);
  assert.throws(() => parse_macho_fat(fat), error => error.code === 'ORIX_MACHO_FAT_OVERLAPPING_SLICES');
});


test('PE parser decodes bounded resource trees and WIN_CERTIFICATE framing', () => {
  const base = create_pe_fixture();
  const pe = 0x80;
  const optional = pe + 4 + 20;
  const section = optional + 224;
  const raw = section + 40;
  const buffer = Buffer.concat([base, Buffer.alloc(0x300)]);
  buffer.writeUInt32LE(0x300, section + 16);
  const directories = optional + 96;
  buffer.writeUInt32LE(0x1100, directories + 16);
  buffer.writeUInt32LE(80, directories + 20);
  buffer.writeUInt32LE(raw + 0x250, directories + 32);
  buffer.writeUInt32LE(16, directories + 36);

  const root = raw + 0x100;
  buffer.writeUInt16LE(1, root + 14);
  buffer.writeUInt32LE(10, root + 16);
  buffer.writeUInt32LE(0x80000020, root + 20);
  buffer.writeUInt16LE(1, root + 32 + 14);
  buffer.writeUInt32LE(1, root + 32 + 16);
  buffer.writeUInt32LE(0x40, root + 32 + 20);
  buffer.writeUInt32LE(0x1180, root + 64);
  buffer.writeUInt32LE(4, root + 68);
  buffer.writeUInt32LE(1200, root + 72);
  buffer.set([0xde,0xad,0xbe,0xef], raw + 0x180);

  const certificate = raw + 0x250;
  buffer.writeUInt32LE(12, certificate);
  buffer.writeUInt16LE(0x0200, certificate + 4);
  buffer.writeUInt16LE(2, certificate + 6);
  buffer.set([1,2,3,4], certificate + 8);

  const parsed = parse_pe(buffer);
  assert.equal(parsed.resources.length, 1);
  assert.equal(parsed.resources[0].id, 10);
  assert.equal(parsed.resources[0].entries[0].id, 1);
  assert.equal(parsed.resources[0].entries[0].data_rva, 0x1180);
  assert.equal(parsed.resources[0].entries[0].file_range_valid, true);
  assert.equal(parsed.certificates.length, 1);
  assert.equal(parsed.certificates[0].revision, '0x200');
  assert.equal(parsed.certificates[0].type, 2);
  assert.equal(parsed.certificates[0].payload_size, 4);
});

test('PE parser rejects cyclic resource trees and out-of-range certificate tables', () => {
  const base = create_pe_fixture();
  const optional = 0x80 + 4 + 20;
  const section = optional + 224;
  const raw = section + 40;
  const buffer = Buffer.concat([base, Buffer.alloc(0x200)]);
  buffer.writeUInt32LE(0x200, section + 16);
  const directories = optional + 96;
  buffer.writeUInt32LE(0x1100, directories + 16);
  buffer.writeUInt32LE(40, directories + 20);
  buffer.writeUInt16LE(1, raw + 0x100 + 14);
  buffer.writeUInt32LE(1, raw + 0x100 + 16);
  buffer.writeUInt32LE(0x80000000, raw + 0x100 + 20);
  assert.throws(() => parse_pe(buffer), error => error.code === 'ORIX_PE_RESOURCE_CYCLE');

  const malformed = create_pe_fixture();
  malformed.writeUInt32LE(0xfffffff0, optional + 96 + 32);
  malformed.writeUInt32LE(32, optional + 96 + 36);
  assert.throws(() => parse_pe(malformed), error => error.code === 'ORIX_PE_CERTIFICATE_RANGE');
});


function create_zip64_fixture() {
  const name = Buffer.from('big.bin', 'ascii');
  const buffer = Buffer.alloc(217);
  buffer.writeUInt32LE(0x04034b50, 0);
  buffer.writeUInt16LE(45, 4);
  buffer.writeUInt16LE(0, 6);
  buffer.writeUInt16LE(0, 8);
  buffer.writeUInt32LE(0, 14);
  buffer.writeUInt32LE(1, 18);
  buffer.writeUInt32LE(1, 22);
  buffer.writeUInt16LE(name.length, 26);
  buffer.writeUInt16LE(0, 28);
  name.copy(buffer, 30);
  buffer[37] = 0x41;

  const central = 38;
  buffer.writeUInt32LE(0x02014b50, central);
  buffer.writeUInt16LE(45, central + 4);
  buffer.writeUInt16LE(45, central + 6);
  buffer.writeUInt16LE(0, central + 8);
  buffer.writeUInt16LE(0, central + 10);
  buffer.writeUInt32LE(0, central + 16);
  buffer.writeUInt32LE(0xffffffff, central + 20);
  buffer.writeUInt32LE(0xffffffff, central + 24);
  buffer.writeUInt16LE(name.length, central + 28);
  buffer.writeUInt16LE(28, central + 30);
  buffer.writeUInt16LE(0, central + 32);
  buffer.writeUInt16LE(0, central + 34);
  buffer.writeUInt32LE(0, central + 38);
  buffer.writeUInt32LE(0xffffffff, central + 42);
  name.copy(buffer, central + 46);
  const extra = central + 46 + name.length;
  buffer.writeUInt16LE(0x0001, extra);
  buffer.writeUInt16LE(24, extra + 2);
  buffer.writeBigUInt64LE(1n, extra + 4);
  buffer.writeBigUInt64LE(1n, extra + 12);
  buffer.writeBigUInt64LE(0n, extra + 20);

  const zip64_eocd = 119;
  buffer.writeUInt32LE(0x06064b50, zip64_eocd);
  buffer.writeBigUInt64LE(44n, zip64_eocd + 4);
  buffer.writeUInt16LE(45, zip64_eocd + 12);
  buffer.writeUInt16LE(45, zip64_eocd + 14);
  buffer.writeUInt32LE(0, zip64_eocd + 16);
  buffer.writeUInt32LE(0, zip64_eocd + 20);
  buffer.writeBigUInt64LE(1n, zip64_eocd + 24);
  buffer.writeBigUInt64LE(1n, zip64_eocd + 32);
  buffer.writeBigUInt64LE(81n, zip64_eocd + 40);
  buffer.writeBigUInt64LE(38n, zip64_eocd + 48);

  const locator = zip64_eocd + 56;
  buffer.writeUInt32LE(0x07064b50, locator);
  buffer.writeUInt32LE(0, locator + 4);
  buffer.writeBigUInt64LE(BigInt(zip64_eocd), locator + 8);
  buffer.writeUInt32LE(1, locator + 16);

  const eocd = locator + 20;
  buffer.writeUInt32LE(0x06054b50, eocd);
  buffer.writeUInt16LE(0, eocd + 4);
  buffer.writeUInt16LE(0, eocd + 6);
  buffer.writeUInt16LE(0xffff, eocd + 8);
  buffer.writeUInt16LE(0xffff, eocd + 10);
  buffer.writeUInt32LE(0xffffffff, eocd + 12);
  buffer.writeUInt32LE(0xffffffff, eocd + 16);
  buffer.writeUInt16LE(0, eocd + 20);
  return buffer;
}

test('ZIP64 parser resolves 64-bit directory and per-entry size/offset fields', async () => {
  const { parse_zip } = await import('../src/formats/zip.mjs');
  const parsed = parse_zip(create_zip64_fixture());
  assert.equal(parsed.archive.zip64, true);
  assert.equal(parsed.archive.total_entries, 1);
  assert.equal(parsed.entries[0].name, 'big.bin');
  assert.equal(parsed.entries[0].compressed_size, 1);
  assert.equal(parsed.entries[0].uncompressed_size, 1);
  assert.equal(parsed.entries[0].local_header_offset, 0);
  assert.equal(parsed.entries[0].local_data_range_valid, true);
});

test('ZIP64 parser rejects missing locators and malformed extended fields', async () => {
  const { parse_zip } = await import('../src/formats/zip.mjs');
  const missing_locator = create_zip64_fixture();
  missing_locator.fill(0, missing_locator.length - 42, missing_locator.length - 22);
  assert.throws(() => parse_zip(missing_locator), error => error.code === 'ORIX_ZIP64_LOCATOR_MISSING');

  const malformed_extra = create_zip64_fixture();
  malformed_extra.writeUInt16LE(8, 38 + 46 + 7 + 2);
  assert.throws(() => parse_zip(malformed_extra), error => error.code === 'ORIX_ZIP64_EXTRA_TRUNCATED');
});


test('ELF parser rejects relocations that reference missing symbols', () => {
  const buffer = create_elf_analysis_fixture();
  buffer.writeBigUInt64LE((9n << 32n) | 7n, 696);
  assert.throws(() => parse_elf(buffer), error => error.code === 'ORIX_ELF_RELOCATION_SYMBOL_INDEX');
});



test('PE parser decodes RVA-based delay imports and named thunks', () => {
  const buffer = create_pe_fixture();
  const pe = 0x80;
  const optional = pe + 4 + 20;
  const section = optional + 224;
  const raw = section + 40;
  const expanded = Buffer.concat([buffer, Buffer.alloc(0x300)]);
  expanded.writeUInt32LE(0x300, section + 16);
  const delay_directory = optional + 96 + 13 * 8;
  expanded.writeUInt32LE(0x1100, delay_directory);
  expanded.writeUInt32LE(64, delay_directory + 4);

  const descriptor = raw + 0x100;
  expanded.writeUInt32LE(1, descriptor);
  expanded.writeUInt32LE(0x1150, descriptor + 4);
  expanded.writeUInt32LE(0, descriptor + 8);
  expanded.writeUInt32LE(0x1168, descriptor + 12);
  expanded.writeUInt32LE(0x1170, descriptor + 16);
  expanded.writeUInt32LE(0, descriptor + 20);
  expanded.writeUInt32LE(0, descriptor + 24);
  expanded.writeUInt32LE(0x65a1b2c3, descriptor + 28);
  expanded.write('TESTDLL.dll\0', raw + 0x150, 'ascii');
  expanded.writeUInt32LE(0x1180, raw + 0x170);
  expanded.writeUInt32LE(0, raw + 0x174);
  expanded.writeUInt16LE(3, raw + 0x180);
  expanded.write('DelayLoadFunc\0', raw + 0x182, 'ascii');

  const parsed = parse_pe(expanded);
  assert.equal(parsed.delay_imports.length, 1);
  assert.equal(parsed.delay_imports_truncated, false);
  assert.equal(parsed.delay_imports[0].library, 'TESTDLL.dll');
  assert.equal(parsed.delay_imports[0].rva_mode, true);
  assert.equal(parsed.delay_imports[0].iat_rva, 0x1168);
  assert.equal(parsed.delay_imports[0].timestamp, 0x65a1b2c3);
  assert.deepEqual(parsed.delay_imports[0].symbols[0], {
    kind: 'name', ordinal: null, hint: 3, name: 'DelayLoadFunc',
  });
});

test('PE parser converts VA-based delay-import fields and rejects invalid thunk mappings', () => {
  const buffer = create_pe_fixture();
  const pe = 0x80;
  const optional = pe + 4 + 20;
  const section = optional + 224;
  const raw = section + 40;
  const expanded = Buffer.concat([buffer, Buffer.alloc(0x300)]);
  expanded.writeUInt32LE(0x300, section + 16);
  const directory = optional + 96 + 13 * 8;
  expanded.writeUInt32LE(0x1100, directory);
  expanded.writeUInt32LE(32, directory + 4);
  const descriptor = raw + 0x100;
  expanded.writeUInt32LE(0, descriptor);
  expanded.writeUInt32LE(0x401150, descriptor + 4);
  expanded.writeUInt32LE(0, descriptor + 8);
  expanded.writeUInt32LE(0x401168, descriptor + 12);
  expanded.writeUInt32LE(0x7ffffff0, descriptor + 16);
  expanded.writeUInt32LE(0, descriptor + 20);
  expanded.writeUInt32LE(0, descriptor + 24);
  expanded.writeUInt32LE(0, descriptor + 28);
  expanded.write('TESTDLL.dll\0', raw + 0x150, 'ascii');
  expanded.writeUInt32LE(0x7ffffff0, raw + 0x170);
  assert.throws(() => parse_pe(expanded), error => error.code === 'ORIX_PE_INVALID_DELAY_IMPORT_THUNK');
});


test('PE parser decodes bounded HIGHLOW and DIR64 base-relocation entries', () => {
  const pe32 = create_pe_fixture();
  const pe_offset = 0x80;
  const optional32 = pe_offset + 4 + 20;
  const section32 = optional32 + 224;
  const raw32 = section32 + 40;
  const image32 = Buffer.concat([pe32, Buffer.alloc(0x300)]);
  image32.writeUInt32LE(0x300, section32 + 16);
  const directory32 = optional32 + 96 + 5 * 8;
  image32.writeUInt32LE(0x1100, directory32);
  image32.writeUInt32LE(12, directory32 + 4);
  image32.writeUInt32LE(0x1000, raw32 + 0x100);
  image32.writeUInt32LE(12, raw32 + 0x104);
  image32.writeUInt16LE(0x3010, raw32 + 0x108);
  image32.writeUInt16LE(0x0000, raw32 + 0x10a);

  const parsed32 = parse_pe(image32);
  assert.equal(parsed32.base_relocation_blocks.length, 1);
  assert.equal(parsed32.base_relocations.length, 2);
  assert.equal(parsed32.base_relocations[0].type_name, 'HIGHLOW');
  assert.equal(parsed32.base_relocations[0].target_rva, 0x1010);
  assert.equal(parsed32.base_relocations[0].file_offset, raw32 + 0x10);
  assert.equal(parsed32.base_relocations[0].file_range_valid, true);
  assert.equal(parsed32.base_relocations[1].type_name, 'ABSOLUTE');
  assert.equal(parsed32.base_relocations_truncated, false);
  assert.throws(() => parse_pe(image32, { max_relocations: 1 }), error => error.code === 'ORIX_PE_RELOCATION_LIMIT');

  const pe64 = create_pe_fixture({ is_64: true });
  const optional64 = pe_offset + 4 + 20;
  const section64 = optional64 + 240;
  const raw64 = section64 + 40;
  const image64 = Buffer.concat([pe64, Buffer.alloc(0x300)]);
  image64.writeUInt32LE(0x300, section64 + 16);
  const directory64 = optional64 + 112 + 5 * 8;
  image64.writeUInt32LE(0x1100, directory64);
  image64.writeUInt32LE(10, directory64 + 4);
  image64.writeUInt32LE(0x1000, raw64 + 0x100);
  image64.writeUInt32LE(10, raw64 + 0x104);
  image64.writeUInt16LE(0xa008, raw64 + 0x108);
  const parsed64 = parse_pe(image64);
  assert.equal(parsed64.base_relocations[0].type_name, 'DIR64');
  assert.equal(parsed64.base_relocations[0].width, 8);
  assert.equal(parsed64.base_relocations[0].target_rva, 0x1008);
});

test('PE parser rejects malformed base-relocation block sizes', () => {
  const buffer = create_pe_fixture();
  const optional = 0x80 + 4 + 20;
  const section = optional + 224;
  const raw = section + 40;
  const expanded = Buffer.concat([buffer, Buffer.alloc(0x300)]);
  expanded.writeUInt32LE(0x300, section + 16);
  const directory = optional + 96 + 5 * 8;
  expanded.writeUInt32LE(0x1100, directory);
  expanded.writeUInt32LE(8, directory + 4);
  expanded.writeUInt32LE(0x1000, raw + 0x100);
  expanded.writeUInt32LE(7, raw + 0x104);
  assert.throws(() => parse_pe(expanded), error => error.code === 'ORIX_PE_RELOCATION_BLOCK_SIZE');
});


function create_elf_version_fixture() {
  const buffer = Buffer.alloc(1024);
  buffer.set([0x7f,0x45,0x4c,0x46,2,1,1,0]);
  buffer.writeUInt16LE(3, 16);
  buffer.writeUInt16LE(62, 18);
  buffer.writeUInt32LE(1, 20);
  buffer.writeBigUInt64LE(0n, 24);
  buffer.writeBigUInt64LE(0n, 32);
  buffer.writeBigUInt64LE(256n, 40);
  buffer.writeUInt16LE(64, 52);
  buffer.writeUInt16LE(56, 54);
  buffer.writeUInt16LE(0, 56);
  buffer.writeUInt16LE(64, 58);
  buffer.writeUInt16LE(5, 60);
  buffer.writeUInt16LE(0, 62);

  const section = index => 256 + index * 64;
  const strtab = section(1);
  buffer.writeUInt32LE(3, strtab + 4);
  buffer.writeBigUInt64LE(800n, strtab + 24);
  buffer.writeBigUInt64LE(28n, strtab + 32);
  buffer.writeBigUInt64LE(1n, strtab + 48);

  const dynsym = section(2);
  buffer.writeUInt32LE(11, dynsym + 4);
  buffer.writeBigUInt64LE(840n, dynsym + 24);
  buffer.writeBigUInt64LE(48n, dynsym + 32);
  buffer.writeUInt32LE(1, dynsym + 40);
  buffer.writeUInt32LE(1, dynsym + 44);
  buffer.writeBigUInt64LE(8n, dynsym + 48);
  buffer.writeBigUInt64LE(24n, dynsym + 56);

  const verneed = section(3);
  buffer.writeUInt32LE(0x6ffffffe, verneed + 4);
  buffer.writeBigUInt64LE(888n, verneed + 24);
  buffer.writeBigUInt64LE(32n, verneed + 32);
  buffer.writeUInt32LE(1, verneed + 40);
  buffer.writeBigUInt64LE(4n, verneed + 48);

  const versym = section(4);
  buffer.writeUInt32LE(0x6fffffff, versym + 4);
  buffer.writeBigUInt64LE(920n, versym + 24);
  buffer.writeBigUInt64LE(4n, versym + 32);
  buffer.writeUInt32LE(2, versym + 40);
  buffer.writeBigUInt64LE(2n, versym + 48);

  Buffer.from('\0func\0libc.so.6\0GLIBC_2.2.5\0', 'ascii').copy(buffer, 800);
  buffer.writeUInt32LE(1, 864);
  buffer[868] = 0x12;
  buffer.writeUInt16LE(1, 870);
  buffer.writeBigUInt64LE(0x401000n, 872);
  buffer.writeBigUInt64LE(4n, 880);

  buffer.writeUInt16LE(1, 888);
  buffer.writeUInt16LE(1, 890);
  buffer.writeUInt32LE(6, 892);
  buffer.writeUInt32LE(16, 896);
  buffer.writeUInt32LE(0, 900);
  buffer.writeUInt32LE(0x1234, 904);
  buffer.writeUInt16LE(0, 908);
  buffer.writeUInt16LE(2, 910);
  buffer.writeUInt32LE(16, 912);
  buffer.writeUInt32LE(0, 916);
  buffer.writeUInt16LE(0, 920);
  buffer.writeUInt16LE(2, 922);
  return buffer;
}

test('ELF parser resolves GNU version requirements onto dynamic symbols', () => {
  const parsed = parse_elf(create_elf_version_fixture());
  assert.equal(parsed.version_requirements.length, 1);
  assert.equal(parsed.version_requirements[0].library, 'libc.so.6');
  assert.equal(parsed.version_requirements[0].auxiliary[0].name, 'GLIBC_2.2.5');
  assert.equal(parsed.symbol_versions.length, 2);
  assert.equal(parsed.symbol_versions[0].version_name, 'LOCAL');
  assert.equal(parsed.symbol_versions[1].symbol_name, 'func');
  assert.equal(parsed.symbol_versions[1].version_index, 2);
  assert.equal(parsed.symbol_versions[1].version_name, 'GLIBC_2.2.5');
  assert.equal(parsed.symbol_versions[1].library, 'libc.so.6');
});

test('ELF parser bounds GNU version chains and rejects malformed auxiliary ranges', () => {
  const fixture = create_elf_version_fixture();
  assert.throws(() => parse_elf(fixture, { max_version_records: 1 }), error => error.code === 'ORIX_ELF_VERSION_RECORD_LIMIT');
  const malformed = create_elf_version_fixture();
  malformed.writeUInt32LE(0xfffffff0, 896);
  assert.throws(() => parse_elf(malformed), error => error.code === 'ORIX_ELF_VERSION_RANGE');
});


test('ELF parser resolves GNU version definitions for exported dynamic symbols', () => {
  const buffer = create_elf_version_fixture();
  buffer.writeUInt16LE(3, 922);
  buffer.writeBigUInt64LE(37n, 256 + 64 + 32);
  Buffer.from('ORIX_1.0\0', 'ascii').copy(buffer, 828);
  buffer.writeUInt16LE(6, 60);

  const verdef = 256 + 5 * 64;
  buffer.writeUInt32LE(0x6ffffffd, verdef + 4);
  buffer.writeBigUInt64LE(928n, verdef + 24);
  buffer.writeBigUInt64LE(28n, verdef + 32);
  buffer.writeUInt32LE(1, verdef + 40);
  buffer.writeBigUInt64LE(4n, verdef + 48);

  buffer.writeUInt16LE(1, 928);
  buffer.writeUInt16LE(0, 930);
  buffer.writeUInt16LE(3, 932);
  buffer.writeUInt16LE(1, 934);
  buffer.writeUInt32LE(0x9876, 936);
  buffer.writeUInt32LE(20, 940);
  buffer.writeUInt32LE(0, 944);
  buffer.writeUInt32LE(28, 948);
  buffer.writeUInt32LE(0, 952);

  const parsed = parse_elf(buffer);
  assert.equal(parsed.version_definitions.length, 1);
  assert.equal(parsed.version_definitions[0].version_index, 3);
  assert.equal(parsed.version_definitions[0].names[0], 'ORIX_1.0');
  assert.equal(parsed.symbol_versions[1].version_index, 3);
  assert.equal(parsed.symbol_versions[1].version_name, 'ORIX_1.0');
  assert.equal(parsed.symbol_versions[1].source, 'definition');
});


test('Mach-O parser decodes bounded 64-bit nlist symbols and names', () => {
  const buffer = Buffer.alloc(88);
  buffer.set([0xcf,0xfa,0xed,0xfe]);
  buffer.writeInt32LE(0x01000007, 4);
  buffer.writeInt32LE(3, 8);
  buffer.writeUInt32LE(2, 12);
  buffer.writeUInt32LE(1, 16);
  buffer.writeUInt32LE(24, 20);
  buffer.writeUInt32LE(0, 24);
  buffer.writeUInt32LE(0, 28);
  buffer.writeUInt32LE(0x2, 32);
  buffer.writeUInt32LE(24, 36);
  buffer.writeUInt32LE(56, 40);
  buffer.writeUInt32LE(1, 44);
  buffer.writeUInt32LE(72, 48);
  buffer.writeUInt32LE(16, 52);
  buffer.writeUInt32LE(1, 56);
  buffer[60] = 0x0f;
  buffer[61] = 1;
  buffer.writeUInt16LE(0, 62);
  buffer.writeBigUInt64LE(0x1000n, 64);
  Buffer.from('\0_main\0_unused\0', 'ascii').copy(buffer, 72);
  const parsed = parse_macho(buffer);
  assert.equal(parsed.symbol_table.symbol_count, 1);
  assert.equal(parsed.symbol_table.entry_size, 16);
  assert.deepEqual(parsed.symbols[0], {
    index: 0,
    name: '_main',
    raw_type: 0x0f,
    type: 'SECTION',
    is_external: true,
    is_private_external: false,
    is_debug_symbol: false,
    section_index: 1,
    description: 0,
    value: 0x1000,
  });
  const indirect = Buffer.from(buffer);
  indirect[60] = 0x0b;
  assert.equal(parse_macho(indirect).symbols[0].type, 'INDIRECT');
  const prebound = Buffer.from(buffer);
  prebound[60] = 0x0d;
  assert.equal(parse_macho(prebound).symbols[0].type, 'PREBOUND_UNDEFINED');
});

test('Mach-O parser bounds symbol count and rejects invalid string indexes', () => {
  const buffer = Buffer.alloc(88);
  buffer.set([0xcf,0xfa,0xed,0xfe]);
  buffer.writeInt32LE(0x01000007, 4);
  buffer.writeInt32LE(3, 8);
  buffer.writeUInt32LE(2, 12);
  buffer.writeUInt32LE(1, 16);
  buffer.writeUInt32LE(24, 20);
  buffer.writeUInt32LE(0x2, 32);
  buffer.writeUInt32LE(24, 36);
  buffer.writeUInt32LE(56, 40);
  buffer.writeUInt32LE(1, 44);
  buffer.writeUInt32LE(72, 48);
  buffer.writeUInt32LE(16, 52);
  buffer.writeUInt32LE(1, 56);
  buffer[60] = 0x0f;
  buffer.writeBigUInt64LE(0x1000n, 64);
  Buffer.from('\0_main\0_unused\0', 'ascii').copy(buffer, 72);
  assert.throws(() => parse_macho(buffer, { max_symbols: 0 }), error => error.code === 'ORIX_MACHO_SYMBOL_LIMIT');
  const malformed = Buffer.from(buffer);
  malformed.writeUInt32LE(0xffff, 56);
  assert.throws(() => parse_macho(malformed), error => error.code === 'ORIX_MACHO_SYMBOL_STRING_INDEX');
});


function create_elf_gnu_hash_fixture() {
  const buffer = create_elf_version_fixture();
  buffer.writeUInt16LE(6, 60);
  const section = 256 + 5 * 64;
  buffer.writeUInt32LE(0x6ffffff6, section + 4);
  buffer.writeBigUInt64LE(944n, section + 24);
  buffer.writeBigUInt64LE(32n, section + 32);
  buffer.writeUInt32LE(2, section + 40);
  buffer.writeBigUInt64LE(8n, section + 48);
  buffer.writeUInt32LE(1, 944);
  buffer.writeUInt32LE(1, 948);
  buffer.writeUInt32LE(1, 952);
  buffer.writeUInt32LE(5, 956);
  buffer.writeBigUInt64LE(0x1001n, 960);
  buffer.writeUInt32LE(1, 968);
  buffer.writeUInt32LE(0x1235, 972);
  return buffer;
}

test('ELF parser decodes GNU hash bloom words, buckets and terminal chain entries', () => {
  const parsed = parse_elf(create_elf_gnu_hash_fixture());
  assert.equal(parsed.gnu_hash_tables.length, 1);
  const table = parsed.gnu_hash_tables[0];
  assert.equal(table.symbol_table_section_index, 2);
  assert.equal(table.bucket_count, 1);
  assert.equal(table.symbol_offset, 1);
  assert.equal(table.bloom_shift, 5);
  assert.deepEqual(table.bloom_words, ['4097']);
  assert.equal(table.buckets[0].first_symbol, 1);
  assert.deepEqual(table.buckets[0].chain, [{ symbol_index: 1, hash: 0x1235, terminal: true }]);
});

test('ELF GNU hash duplicate buckets share bounded chain traversal work', () => {
  const buffer = create_elf_gnu_hash_fixture();
  const section = 256 + 5 * 64;
  buffer.writeBigUInt64LE(36n, section + 32);
  buffer.writeUInt32LE(2, 944);
  buffer.writeUInt32LE(1, 968);
  buffer.writeUInt32LE(1, 972);
  buffer.writeUInt32LE(0x1235, 976);
  const parsed = parse_elf(buffer, { max_gnu_hash_total_entries: 1 });
  assert.equal(parsed.gnu_hash_tables[0].buckets.length, 2);
  assert.deepEqual(parsed.gnu_hash_tables[0].buckets[0].chain, parsed.gnu_hash_tables[0].buckets[1].chain);
  assert.throws(() => parse_elf(buffer, { max_gnu_hash_total_entries: 0 }), error => error.code === 'ORIX_ELF_GNU_HASH_LIMIT');
});

test('ELF GNU hash aggregate work budget spans multiple hash sections', () => {
  const buffer = create_elf_gnu_hash_fixture();
  buffer.writeUInt16LE(7, 60);
  const second = 256 + 6 * 64;
  buffer.writeUInt32LE(0x6ffffff6, second + 4);
  buffer.writeBigUInt64LE(944n, second + 24);
  buffer.writeBigUInt64LE(32n, second + 32);
  buffer.writeUInt32LE(2, second + 40);
  buffer.writeBigUInt64LE(8n, second + 48);
  assert.throws(() => parse_elf(buffer, { max_gnu_hash_total_entries: 1 }), error => error.code === 'ORIX_ELF_GNU_HASH_TOTAL_ENTRY_LIMIT');
});

test('ELF parser rejects GNU hash buckets outside DYNSYM and truncated chains', () => {
  const bad_bucket = create_elf_gnu_hash_fixture();
  bad_bucket.writeUInt32LE(99, 968);
  assert.throws(() => parse_elf(bad_bucket), error => error.code === 'ORIX_ELF_GNU_HASH_BUCKET_SYMBOL');
  const short_chain = create_elf_gnu_hash_fixture();
  short_chain.writeBigUInt64LE(28n, 256 + 5 * 64 + 32);
  assert.throws(() => parse_elf(short_chain), error => error.code === 'ORIX_ELF_GNU_HASH_CHAIN_RANGE');
  assert.throws(() => parse_elf(create_elf_gnu_hash_fixture(), { max_gnu_hash_buckets: 0 }), error => error.code === 'ORIX_ELF_GNU_HASH_LIMIT');
  const bad_shift = create_elf_gnu_hash_fixture();
  bad_shift.writeUInt32LE(32, 956);
  assert.throws(() => parse_elf(bad_shift), error => error.code === 'ORIX_ELF_GNU_HASH_BLOOM_SHIFT');
});


test('Mach-O parser decodes LC_DYSYMTAB symbol groups and indirect-symbol markers', () => {
  const buffer = Buffer.alloc(168);
  buffer.set([0xcf,0xfa,0xed,0xfe]);
  buffer.writeInt32LE(0x01000007, 4);
  buffer.writeInt32LE(3, 8);
  buffer.writeUInt32LE(2, 12);
  buffer.writeUInt32LE(2, 16);
  buffer.writeUInt32LE(104, 20);
  buffer.writeUInt32LE(0, 24);
  buffer.writeUInt32LE(0, 28);
  buffer.writeUInt32LE(0x2, 32);
  buffer.writeUInt32LE(24, 36);
  buffer.writeUInt32LE(136, 40);
  buffer.writeUInt32LE(1, 44);
  buffer.writeUInt32LE(152, 48);
  buffer.writeUInt32LE(8, 52);
  buffer.writeUInt32LE(1, 136);
  buffer[140] = 0x0f;
  buffer[141] = 1;
  buffer.writeBigUInt64LE(0x1000n, 144);
  Buffer.from('\0_main\0', 'ascii').copy(buffer, 152);

  const dynamic = 56;
  buffer.writeUInt32LE(0xb, dynamic);
  buffer.writeUInt32LE(80, dynamic + 4);
  buffer.writeUInt32LE(0, dynamic + 8);
  buffer.writeUInt32LE(0, dynamic + 12);
  buffer.writeUInt32LE(0, dynamic + 16);
  buffer.writeUInt32LE(1, dynamic + 20);
  buffer.writeUInt32LE(1, dynamic + 24);
  buffer.writeUInt32LE(0, dynamic + 28);
  buffer.writeUInt32LE(0, dynamic + 32);
  buffer.writeUInt32LE(0, dynamic + 36);
  buffer.writeUInt32LE(0, dynamic + 40);
  buffer.writeUInt32LE(0, dynamic + 44);
  buffer.writeUInt32LE(0, dynamic + 48);
  buffer.writeUInt32LE(160, dynamic + 56);
  buffer.writeUInt32LE(2, dynamic + 60);
  buffer.writeUInt32LE(0, dynamic + 64);
  buffer.writeUInt32LE(0, dynamic + 68);
  buffer.writeUInt32LE(0, dynamic + 72);
  buffer.writeUInt32LE(0, dynamic + 76);
  buffer.writeUInt32LE(0, 160);
  buffer.writeUInt32LE(0x80000000, 164);

  const parsed = parse_macho(buffer);
  assert.equal(parsed.dynamic_symbol_table.external_symbol_count, 1);
  assert.equal(parsed.dynamic_symbol_table.indirect_symbol_count, 2);
  assert.deepEqual(parsed.indirect_symbols, [
    { index: 0, raw_value: 0, kind: 'SYMBOL', symbol_index: 0, symbol_name: '_main' },
    { index: 1, raw_value: 0x80000000, kind: 'LOCAL', symbol_index: null, symbol_name: null },
  ]);
});

test('Mach-O parser rejects invalid dynamic-symbol index groups and indirect references', () => {
  const buffer = Buffer.alloc(168);
  buffer.set([0xcf,0xfa,0xed,0xfe]);
  buffer.writeInt32LE(0x01000007, 4);
  buffer.writeInt32LE(3, 8);
  buffer.writeUInt32LE(2, 12);
  buffer.writeUInt32LE(2, 16);
  buffer.writeUInt32LE(104, 20);
  buffer.writeUInt32LE(0x2, 32);
  buffer.writeUInt32LE(24, 36);
  buffer.writeUInt32LE(136, 40);
  buffer.writeUInt32LE(1, 44);
  buffer.writeUInt32LE(152, 48);
  buffer.writeUInt32LE(8, 52);
  buffer.writeUInt32LE(1, 136);
  buffer[140] = 0x0f;
  buffer.writeBigUInt64LE(0x1000n, 144);
  Buffer.from('\0_main\0', 'ascii').copy(buffer, 152);
  const dynamic = 56;
  buffer.writeUInt32LE(0xb, dynamic);
  buffer.writeUInt32LE(80, dynamic + 4);
  buffer.writeUInt32LE(2, dynamic + 16);
  buffer.writeUInt32LE(1, dynamic + 20);
  assert.throws(() => parse_macho(buffer), error => error.code === 'ORIX_MACHO_DYSYMTAB_SYMBOL_RANGE');
  buffer.writeUInt32LE(0, dynamic + 16);
  buffer.writeUInt32LE(0, dynamic + 20);
  buffer.writeUInt32LE(160, dynamic + 56);
  buffer.writeUInt32LE(1, dynamic + 60);
  buffer.writeUInt32LE(1, 160);
  assert.throws(() => parse_macho(buffer), error => error.code === 'ORIX_MACHO_INDIRECT_SYMBOL_INDEX');
});


test('ZIP parser rejects invalid direct entry limits', async () => {
  const { parse_zip } = await import('../src/formats/zip.mjs');
  const { create_zip_fixture } = await import('./helpers.mjs');
  const fixture = create_zip_fixture('safe.txt', 'bounded');
  for (const max_entries of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 1_000_001]) {
    assert.throws(() => parse_zip(fixture, { max_entries }), /max_entries must be an integer/);
  }
});


function create_dex_fixture() {
  const buffer = Buffer.alloc(140);
  buffer.write('dex\n035\0', 0, 'ascii');
  buffer.writeUInt32LE(buffer.length, 32); buffer.writeUInt32LE(112, 36); buffer.writeUInt32LE(0x12345678, 40);
  buffer.writeUInt32LE(112, 52); buffer.writeUInt32LE(28, 104); buffer.writeUInt32LE(112, 108);
  buffer.writeUInt32LE(2, 112); buffer.writeUInt16LE(0, 116); buffer.writeUInt32LE(1, 120); buffer.writeUInt32LE(0, 124);
  buffer.writeUInt16LE(0x1000, 128); buffer.writeUInt32LE(1, 132); buffer.writeUInt32LE(112, 136);
  return buffer;
}

test('DEX parser validates header and bounded map metadata', () => {
  const parsed = parse_dex(create_dex_fixture());
  assert.equal(parsed.format, 'DEX'); assert.equal(parsed.version, '035'); assert.equal(parsed.file_size, 140);
  assert.equal(parsed.map_items.length, 2); assert.equal(parsed.map_items[1].name, 'map_list');
  assert.equal(parsed.integrity.adler32_verified, false);
});

test('DEX parser is available through package exports and format dispatch', async () => {
  const fixture = create_dex_fixture();
  assert.equal(analyze_known_format(fixture).detection.format, 'DEX');
  assert.equal(analyze_known_format(fixture).parser_status, 'parsed');
  const exported = await import('@orix/cli/formats/dex'); assert.equal(exported.parse_dex, parse_dex);
});

test('DEX parser rejects malformed magic, endian, map and resource limits', () => {
  const badMagic = create_dex_fixture(); badMagic[0] = 0;
  assert.throws(() => parse_dex(badMagic), error => error.code === 'ORIX_DEX_BAD_MAGIC');
  const badEndian = create_dex_fixture(); badEndian.writeUInt32LE(0x78563412, 40);
  assert.throws(() => parse_dex(badEndian), error => error.code === 'ORIX_DEX_ENDIAN');
  const badMap = create_dex_fixture(); badMap.writeUInt16LE(7, 128);
  assert.throws(() => parse_dex(badMap), error => error.code.startsWith('ORIX_DEX_MAP_'));
  assert.throws(() => parse_dex(create_dex_fixture(), { max_map_items: 1 }), error => error.code === 'ORIX_DEX_MAP_LIMIT');
  assert.throws(() => parse_dex(create_dex_fixture(), { max_file_bytes: 112 }), error => error.code === 'ORIX_DEX_FILE_LIMIT');
});


test('DEX parser rejects inconsistent file and overlapping fixed-table ranges', () => {
  const trailing = create_dex_fixture(); trailing.writeUInt32LE(trailing.length - 1, 32);
  assert.throws(() => parse_dex(trailing), error => error.code === 'ORIX_DEX_FILE_SIZE');
  const overlap = create_dex_fixture();
  overlap.writeUInt32LE(1, 56); overlap.writeUInt32LE(116, 60);
  overlap.writeUInt32LE(1, 64); overlap.writeUInt32LE(116, 68);
  assert.throws(() => parse_dex(overlap), error => error.code === 'ORIX_DEX_TABLE_OVERLAP');
});


function create_dex_class_fixture() {
  const buffer = Buffer.alloc(264);
  buffer.write('dex\n035\0', 0, 'ascii');
  buffer.writeUInt32LE(buffer.length, 32);
  buffer.writeUInt32LE(112, 36);
  buffer.writeUInt32LE(0x12345678, 40);
  buffer.writeUInt32LE(2, 56);
  buffer.writeUInt32LE(112, 60);
  buffer.writeUInt32LE(2, 64);
  buffer.writeUInt32LE(120, 68);
  buffer.writeUInt32LE(1, 96);
  buffer.writeUInt32LE(128, 100);
  buffer.writeUInt32LE(104, 104);
  buffer.writeUInt32LE(160, 108);
  buffer.writeUInt32LE(160, 112);
  buffer.writeUInt32LE(180, 116);
  buffer.writeUInt32LE(0, 120);
  buffer.writeUInt32LE(1, 124);
  buffer.writeUInt32LE(1, 128);
  buffer.writeUInt32LE(1, 132);
  buffer.writeUInt32LE(0, 136);
  buffer.writeUInt32LE(0, 140);
  buffer.writeUInt32LE(0xffffffff, 144);
  buffer.writeUInt32LE(0, 148);
  buffer.writeUInt32LE(0, 152);
  buffer.writeUInt32LE(0, 156);
  const first = Buffer.from('Ljava/lang/Object;', 'ascii');
  buffer[160] = first.length;
  first.copy(buffer, 161);
  buffer[161 + first.length] = 0;
  buffer[180] = 3;
  Buffer.from('Lx;', 'ascii').copy(buffer, 181);
  buffer[184] = 0;
  buffer.writeUInt32LE(6, 188);
  const items = [
    [0x0000, 1, 0],
    [0x0001, 2, 112],
    [0x0002, 2, 120],
    [0x0006, 1, 128],
    [0x2002, 2, 160],
    [0x1000, 1, 188],
  ];
  items.forEach(([type, size, offset], index) => {
    const p = 192 + index * 12;
    buffer.writeUInt16LE(type, p);
    buffer.writeUInt32LE(size, p + 4);
    buffer.writeUInt32LE(offset, p + 8);
  });
  buffer.writeUInt32LE(188, 52);
  return buffer;
}

test('DEX parser resolves bounded strings, type descriptors and class definitions', () => {
  const parsed = parse_dex(create_dex_class_fixture());
  assert.equal(parsed.strings.length, 2);
  assert.equal(parsed.strings[0].value, 'Ljava/lang/Object;');
  assert.equal(parsed.types[1].descriptor, 'Lx;');
  assert.equal(parsed.classes[0].descriptor, 'Lx;');
  assert.equal(parsed.classes[0].superclass, 'Ljava/lang/Object;');
  assert.equal(parsed.classes[0].source_file, null);
});

test('DEX class descriptors remain correct when type output is truncated', () => {
  const parsed = parse_dex(create_dex_class_fixture(), { max_output_items: 1 });
  assert.equal(parsed.types.length, 1);
  assert.equal(parsed.classes[0].descriptor, 'Lx;');
  assert.equal(parsed.classes[0].superclass, 'Ljava/lang/Object;');
  assert.equal(parsed.output_truncated, true);
});
