// JavaScript, tests/fuzz.test.mjs, Node.js 20+, deterministic parser robustness smoke corpus.

import test from 'node:test';
import assert from 'node:assert/strict';
import { OrixError } from '../src/core/errors.mjs';
import { parse_pe } from '../src/formats/pe.mjs';
import { parse_elf } from '../src/formats/elf.mjs';
import { parse_macho, parse_macho_fat } from '../src/formats/macho.mjs';
import { parse_wasm } from '../src/formats/wasm.mjs';
import { parse_zip } from '../src/formats/zip.mjs';
import { create_elf_fixture, create_pe_fixture, create_wasm_fixture, create_zip_fixture } from './helpers.mjs';

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
  const parsers = [parse_pe, parse_elf, parse_macho, parse_macho_fat, parse_wasm, parse_zip];
  for (let iteration = 0; iteration < 256; iteration += 1) {
    const length = random() % 1024;
    const input = Buffer.allocUnsafe(length);
    for (let index = 0; index < length; index += 1) input[index] = random() & 0xff;
    for (const parser of parsers) assert_typed_rejection(parser, input, 'random corpus ' + iteration);
  }
});
