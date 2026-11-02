// JavaScript, tests/formats.test.mjs, Node.js 20+, parser boundary and malformed-input coverage.

import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_pe } from '../src/formats/pe.mjs';
import { parse_elf } from '../src/formats/elf.mjs';
import { parse_macho } from '../src/formats/macho.mjs';
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
  buffer.writeUInt32LE(0x1d, 32);
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
  expanded.write('KERNEL32.dll\\0', raw + 0x150, 'ascii');
  expanded.writeUInt32LE(0x1180, raw + 0x160);
  expanded.writeUInt32LE(0, raw + 0x164);
  expanded.writeUInt16LE(7, raw + 0x180);
  expanded.write('CreateFileW\\0', raw + 0x182, 'ascii');

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
  expanded.write('sample.dll\\0', raw + 0x250, 'ascii');
  expanded.write('ExportedEntry\\0', raw + 0x260, 'ascii');

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
