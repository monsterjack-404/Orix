import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_dex } from '../src/formats/dex.mjs';
import { analyze_known_format } from '../src/formats/index.mjs';
import * as public_api from '../src/index.mjs';

function create_dex_fixture() {
  const buffer = Buffer.alloc(140);
  buffer.write('dex\n035\0', 0, 'ascii');
  buffer.writeUInt32LE(buffer.length, 32);
  buffer.writeUInt32LE(112, 36);
  buffer.writeUInt32LE(0x12345678, 40);
  buffer.writeUInt32LE(112, 52);
  buffer.writeUInt32LE(28, 104);
  buffer.writeUInt32LE(112, 108);
  buffer.writeUInt32LE(2, 112);
  buffer.writeUInt16LE(0, 116);
  buffer.writeUInt32LE(1, 120);
  buffer.writeUInt32LE(0, 124);
  buffer.writeUInt16LE(0x1000, 128);
  buffer.writeUInt32LE(1, 132);
  buffer.writeUInt32LE(112, 136);
  return buffer;
}

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

test('DEX signature dispatch invokes the hardened parser', () => {
  const fixture = create_dex_fixture();
  const result = analyze_known_format(fixture);
  assert.equal(result.detection.format, 'DEX');
  assert.equal(result.parser_status, 'parsed');
  assert.equal(result.parsed.version, '035');
});

test('DEX parser is exported through the public API and package subpath', async () => {
  assert.equal(public_api.parse_dex, parse_dex);
  const exported = await import('@orix/cli/formats/dex');
  assert.equal(exported.parse_dex, parse_dex);
});

test('DEX parser supports only the explicitly listed versions', () => {
  for (const version of ['035', '037', '038', '039']) {
    const fixture = create_dex_fixture();
    fixture.write('dex\n' + version + '\0', 0, 'ascii');
    assert.equal(parse_dex(fixture).version, version);
  }
  const unsupported = create_dex_fixture();
  unsupported.write('dex\n040\0', 0, 'ascii');
  assert.throws(() => parse_dex(unsupported), error => error.code === 'ORIX_DEX_UNSUPPORTED_VERSION');
});

test('DEX parser rejects trailing bytes not included in the declared file_size', () => {
  const fixture = create_dex_fixture();
  fixture.writeUInt32LE(fixture.length - 1, 32);
  assert.throws(() => parse_dex(fixture), error => error.code === 'ORIX_DEX_FILE_SIZE');
});

test('DEX parser rejects overlapping fixed index tables', () => {
  const fixture = create_dex_fixture();
  fixture.writeUInt32LE(1, 56);
  fixture.writeUInt32LE(116, 60);
  fixture.writeUInt32LE(1, 64);
  fixture.writeUInt32LE(116, 68);
  assert.throws(() => parse_dex(fixture), error => error.code === 'ORIX_DEX_TABLE_OVERLAP');
});

test('DEX parser resolves class descriptors even when the public type list is truncated', () => {
  const parsed = parse_dex(create_dex_class_fixture(), { max_output_items: 1 });
  assert.equal(parsed.types.length, 1);
  assert.equal(parsed.classes[0].descriptor, 'Lx;');
  assert.equal(parsed.classes[0].superclass, 'Ljava/lang/Object;');
  assert.equal(parsed.output_truncated, true);
});

test('DEX parser rejects malformed class interface lists before indexing them', () => {
  const fixture = create_dex_class_fixture();
  fixture.writeUInt32LE(161, 140); // Inside the data section but not 4-byte aligned.
  assert.throws(() => parse_dex(fixture), error => error.code === 'ORIX_DEX_INTERFACE_RANGE');
});
