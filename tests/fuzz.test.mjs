// JavaScript, tests/fuzz.test.mjs, Node.js 20+, deterministic parser robustness smoke corpus.

import test from 'node:test';
import assert from 'node:assert/strict';
import { OrixError } from '../src/core/errors.mjs';
import { parse_pe } from '../src/formats/pe.mjs';
import { parse_elf } from '../src/formats/elf.mjs';
import { parse_macho, parse_macho_fat } from '../src/formats/macho.mjs';
import { parse_wasm } from '../src/formats/wasm.mjs';
import { parse_zip } from '../src/formats/zip.mjs';
import { parse_pdf } from '../src/formats/pdf.mjs';
import { parse_png } from '../src/formats/png.mjs';
import { parse_dex } from '../src/formats/dex.mjs';
import { create_elf_fixture, create_pe_fixture, create_wasm_fixture, create_zip_fixture, create_pdf_fixture } from './helpers.mjs';

function create_random(seed) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

function make_macho_fixture() {
  const buffer = Buffer.alloc(32);
  buffer.set([0xcf,0xfa,0xed,0xfe]);
  buffer.writeInt32LE(0x01000007, 4);
  buffer.writeInt32LE(3, 8);
  buffer.writeUInt32LE(2, 12);
  return buffer;
}

function make_fat_fixture() {
  const thin = make_macho_fixture();
  const buffer = Buffer.alloc(60);
  buffer.writeUInt32BE(0xcafebabe, 0);
  buffer.writeUInt32BE(1, 4);
  buffer.writeInt32BE(0x01000007, 8);
  buffer.writeInt32BE(3, 12);
  buffer.writeUInt32BE(28, 16);
  buffer.writeUInt32BE(thin.length, 20);
  buffer.writeUInt32BE(0, 24);
  thin.copy(buffer, 28);
  return buffer;
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 1) ? (0xedb88320 ^ (crc >>> 1)) : (crc >>> 1);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function png_chunk(type, data = Buffer.alloc(0)) {
  const type_bytes = Buffer.from(type, 'ascii');
  const body = Buffer.concat([type_bytes, data]);
  const output = Buffer.alloc(12 + data.length);
  output.writeUInt32BE(data.length, 0);
  type_bytes.copy(output, 4);
  data.copy(output, 8);
  output.writeUInt32BE(crc32(body), 8 + data.length);
  return output;
}

function make_dex_fixture() {
  const buffer = Buffer.alloc(140);
  buffer.write('dex\n035\0', 0, 'ascii');
  buffer.writeUInt32LE(buffer.length, 32); buffer.writeUInt32LE(112, 36); buffer.writeUInt32LE(0x12345678, 40);
  buffer.writeUInt32LE(112, 52); buffer.writeUInt32LE(28, 104); buffer.writeUInt32LE(112, 108);
  buffer.writeUInt32LE(2, 112); buffer.writeUInt16LE(0, 116); buffer.writeUInt32LE(1, 120); buffer.writeUInt32LE(0, 124);
  buffer.writeUInt16LE(0x1000, 128); buffer.writeUInt32LE(1, 132); buffer.writeUInt32LE(112, 136);
  return buffer;
}

function make_png_fixture() {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(1, 0);
  ihdr.writeUInt32BE(1, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const idat = Buffer.from([0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]);
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    png_chunk('IHDR', ihdr),
    png_chunk('IDAT', idat),
    png_chunk('IEND'),
  ]);
}

function assert_typed_rejection(parser, input, label) {
  try {
    parser(input);
  } catch (error) {
    assert.ok(error instanceof OrixError, label + ' leaked an unexpected exception: ' + error?.constructor?.name + ': ' + error?.message);
  }
}

test('binary parsers reject malformed and mutated inputs through typed errors', () => {
  const parsers = [
    ['PE', parse_pe, create_pe_fixture()],
    ['ELF', parse_elf, create_elf_fixture()],
    ['Mach-O', parse_macho, make_macho_fixture()],
    ['Mach-O FAT', parse_macho_fat, make_fat_fixture()],
    ['WebAssembly', parse_wasm, create_wasm_fixture()],
    ['ZIP', parse_zip, create_zip_fixture('fuzz.txt', 'bounded fixture')],
    ['PDF', parse_pdf, create_pdf_fixture()],
    ['PNG', parse_png, make_png_fixture()],
    ['DEX', parse_dex, make_dex_fixture()],
  ];
  const random = create_random(0x4f524958);
  for (const [name, parser, fixture] of parsers) {
    assert_typed_rejection(parser, Buffer.alloc(0), name + ' empty input');
    for (let iteration = 0; iteration < 80; iteration += 1) {
      const mutated = Buffer.from(fixture);
      const changes = 1 + (random() % 4);
      for (let change = 0; change < changes; change += 1) {
        const offset = random() % mutated.length;
        mutated[offset] ^= 1 << (random() % 8);
      }
      assert_typed_rejection(parser, mutated, name + ' mutation ' + iteration);
      if (iteration % 8 === 0) {
        const truncated = mutated.subarray(0, random() % mutated.length);
        assert_typed_rejection(parser, truncated, name + ' truncation ' + iteration);
      }
    }
  }
});

test('binary parsers remain bounded on deterministic random byte buffers', () => {
  const random = create_random(0x53454337);
  const parsers = [parse_pe, parse_elf, parse_macho, parse_macho_fat, parse_wasm, parse_zip, parse_pdf, parse_png, parse_dex];
  for (let iteration = 0; iteration < 256; iteration += 1) {
    const length = random() % 1024;
    const input = Buffer.allocUnsafe(length);
    for (let index = 0; index < length; index += 1) input[index] = random() & 0xff;
    for (const parser of parsers) assert_typed_rejection(parser, input, 'random corpus ' + iteration);
  }
});
