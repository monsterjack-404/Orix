// JavaScript, tests/dotnet-clr.test.mjs, Node.js 20+, bounded CLR metadata inspection.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_pe } from '../src/formats/pe.mjs';
import { create_pe_fixture } from './helpers.mjs';

function create_dotnet_fixture() {
  const buffer = create_pe_fixture();
  const pe = 0x80;
  const coff = pe + 4;
  const optional = coff + 20;
  const section_table = optional + 224;
  const raw = section_table + 40;
  const clr_rva = 0x1010;
  const metadata_rva = clr_rva + 72;
  const metadata = Buffer.alloc(156);
  metadata.write('BSJB', 0, 'ascii');
  metadata.writeUInt16LE(1, 4);
  metadata.writeUInt16LE(1, 6);
  metadata.writeUInt32LE(0, 8);
  metadata.writeUInt32LE(12, 12);
  Buffer.from('v4.0.30319\0', 'ascii').copy(metadata, 16);
  metadata.writeUInt16LE(0, 28);
  metadata.writeUInt16LE(5, 30);
  const streams = [
    { name: '#~', offset: 108, size: 8 },
    { name: '#Strings', offset: 116, size: 8 },
    { name: '#Blob', offset: 124, size: 8 },
    { name: '#GUID', offset: 132, size: 16 },
    { name: '#US', offset: 148, size: 8 },
  ];
  let cursor = 32;
  for (const stream of streams) {
    metadata.writeUInt32LE(stream.offset, cursor);
    metadata.writeUInt32LE(stream.size, cursor + 4);
    Buffer.from(stream.name + '\0', 'ascii').copy(metadata, cursor + 8);
    cursor += 8 + Math.ceil((stream.name.length + 1) / 4) * 4;
  }
  const result = Buffer.concat([buffer, Buffer.alloc(72 + metadata.length)]);
  const clr = raw + 16;
  result.writeUInt32LE(72, clr);
  result.writeUInt16LE(2, clr + 4);
  result.writeUInt16LE(5, clr + 6);
  result.writeUInt32LE(metadata_rva, clr + 8);
  result.writeUInt32LE(metadata.length, clr + 12);
  result.writeUInt32LE(1, clr + 16);
  result.writeUInt32LE(0x06000001, clr + 20);
  metadata.copy(result, clr + 72);
  result.writeUInt32LE(clr_rva, optional + 96 + 14 * 8);
  result.writeUInt32LE(72, optional + 96 + 14 * 8 + 4);
  result.writeUInt32LE(16 + 72 + metadata.length, section_table + 8);
  result.writeUInt32LE(16 + 72 + metadata.length, section_table + 16);
  return {
    buffer: result,
    clr_offset: clr,
    metadata_offset: clr + 72,
    optional_header_offset: optional,
    stream_header_offset: clr + 72 + 32,
  };
}

test('parses bounded CLR header and metadata stream inventory from a PE image', () => {
  const fixture = create_dotnet_fixture();
  const report = parse_pe(fixture.buffer);
  assert.equal(report.clr_runtime.present, true);
  assert.deepEqual(report.clr_runtime.runtime_version, { major: 2, minor: 5 });
  assert.equal(report.clr_runtime.metadata.signature, 'BSJB');
  assert.equal(report.clr_runtime.metadata.version, 'v4.0.30319');
  assert.equal(report.clr_runtime.metadata.tables_stream, '#~');
  assert.equal(report.clr_runtime.metadata.strings_stream, true);
  assert.equal(report.clr_runtime.metadata.blob_stream, true);
  assert.equal(report.clr_runtime.metadata.guid_stream, true);
  assert.equal(report.clr_runtime.metadata.user_strings_stream, true);
  assert.equal(report.clr_runtime.flags.il_only, true);
  assert.equal(report.clr_runtime.entry_point.token, 0x06000001);
  assert.ok(report.clr_runtime.limitations.some(item => item.includes('does not decode metadata tables')));
});

test('keeps native PE files explicitly distinct from CLR assemblies', () => {
  const report = parse_pe(create_pe_fixture());
  assert.equal(report.clr_runtime, null);
});

test('rejects a partially populated CLR runtime directory', () => {
  const fixture = create_dotnet_fixture();
  fixture.buffer.writeUInt32LE(0, fixture.optional_header_offset + 96 + 14 * 8);
  assert.throws(() => parse_pe(fixture.buffer), error => error.code === 'ORIX_PE_BAD_CLR_DIRECTORY');
});

test('rejects a CLR header size smaller than IMAGE_COR20_HEADER', () => {
  const fixture = create_dotnet_fixture();
  fixture.buffer.writeUInt32LE(40, fixture.clr_offset);
  assert.throws(() => parse_pe(fixture.buffer), error => error.code === 'ORIX_PE_BAD_CLR_HEADER_SIZE');
});

test('rejects a CLR metadata root with an invalid signature', () => {
  const fixture = create_dotnet_fixture();
  fixture.buffer.write('NOPE', fixture.metadata_offset, 'ascii');
  assert.throws(() => parse_pe(fixture.buffer), error => error.code === 'ORIX_PE_BAD_CLR_METADATA_SIGNATURE');
});

test('rejects oversized CLR metadata version strings', () => {
  const fixture = create_dotnet_fixture();
  fixture.buffer.writeUInt32LE(260, fixture.metadata_offset + 12);
  assert.throws(() => parse_pe(fixture.buffer), error => error.code === 'ORIX_PE_CLR_VERSION_LIMIT');
});

test('rejects duplicate CLR metadata stream names', () => {
  const fixture = create_dotnet_fixture();
  fixture.buffer.write('#~\0', fixture.stream_header_offset + 20, 'ascii');
  assert.throws(() => parse_pe(fixture.buffer), error => error.code === 'ORIX_PE_CLR_DUPLICATE_STREAM');
});

test('rejects empty CLR metadata stream names', () => {
  const fixture = create_dotnet_fixture();
  fixture.buffer.writeUInt8(0, fixture.stream_header_offset + 8);
  assert.throws(() => parse_pe(fixture.buffer), error => error.code === 'ORIX_PE_CLR_DUPLICATE_STREAM');
});

test('rejects CLR metadata streams that escape the declared metadata root', () => {
  const fixture = create_dotnet_fixture();
  fixture.buffer.writeUInt32LE(0xfffffff0, fixture.stream_header_offset);
  assert.throws(() => parse_pe(fixture.buffer), error => error.code === 'ORIX_PE_CLR_STREAM_RANGE');
});

test('rejects CLR metadata streams that overlap the stream-header table', () => {
  const fixture = create_dotnet_fixture();
  fixture.buffer.writeUInt32LE(32, fixture.stream_header_offset);
  assert.throws(() => parse_pe(fixture.buffer), error => error.code === 'ORIX_PE_CLR_STREAM_OVERLAPS_HEADERS');
});

test('rejects overlapping CLR metadata stream data ranges', () => {
  const fixture = create_dotnet_fixture();
  fixture.buffer.writeUInt32LE(16, fixture.stream_header_offset + 4);
  assert.throws(() => parse_pe(fixture.buffer), error => error.code === 'ORIX_PE_CLR_STREAM_OVERLAP');
});

test('enforces CLR metadata and stream resource limits', () => {
  const fixture = create_dotnet_fixture();
  assert.throws(() => parse_pe(fixture.buffer, { max_clr_metadata_bytes: Infinity }), error => error.code === 'ORIX_PE_CLR_METADATA_LIMIT');
  assert.throws(() => parse_pe(fixture.buffer, { max_clr_metadata_bytes: 128 }), error => error.code === 'ORIX_PE_CLR_METADATA_LIMIT');
  assert.throws(() => parse_pe(fixture.buffer, { max_clr_streams: 0 }), error => error.code === 'ORIX_PE_CLR_STREAM_LIMIT');
  assert.throws(() => parse_pe(fixture.buffer, { max_clr_streams: 2 }), error => error.code === 'ORIX_PE_CLR_STREAM_LIMIT');
});
