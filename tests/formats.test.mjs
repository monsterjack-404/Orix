// JavaScript, tests/formats.test.mjs, Node.js 20+, parser boundary and malformed-input coverage.

import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_pe } from '../src/formats/pe.mjs';
import { parse_elf } from '../src/formats/elf.mjs';
import { parse_macho, parse_macho_fat } from '../src/formats/macho.mjs';
import { parse_wasm } from '../src/formats/wasm.mjs';
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

test('WebAssembly parser rejects a section that exceeds the file', () => {
  const malformed = Buffer.from([0,97,115,109,1,0,0,0,1,8,0]);
  assert.throws(() => parse_wasm(malformed), error => error.code === 'ORIX_WASM_SECTION_OUT_OF_RANGE');
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
  assert.throws(() => parse_zip(zip64), error => error.code === 'ORIX_ZIP64_UNSUPPORTED');
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
  const buffer = Buffer.alloc(800);
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
  buffer.writeBigUInt64LE(800n, 96);
  buffer.writeBigUInt64LE(800n, 104);
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
  buffer.writeBigUInt64LE(32n, 208);
  buffer.writeBigUInt64LE(32n, 216);
  buffer.writeBigUInt64LE(8n, 224);
  buffer.writeBigInt64LE(1n, 720);
  buffer.writeBigUInt64LE(1n, 728);
  buffer.writeBigInt64LE(0n, 736);
  buffer.writeBigUInt64LE(0n, 744);
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
  assert.equal(parsed.dynamic_entries[0].name, 'NEEDED');
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
