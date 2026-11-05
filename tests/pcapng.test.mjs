// JavaScript, tests/pcapng.test.mjs, Node.js 20+, deterministic PCAPNG block fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze_known_format, parse_pcapng } from '../src/formats/index.mjs';

function write16(buffer, offset, value, little) { little ? buffer.writeUInt16LE(value, offset) : buffer.writeUInt16BE(value, offset); }
function write32(buffer, offset, value, little) { little ? buffer.writeUInt32LE(value >>> 0, offset) : buffer.writeUInt32BE(value >>> 0, offset); }
function write64(buffer, offset, value, little) { little ? buffer.writeBigUInt64LE(BigInt(value), offset) : buffer.writeBigUInt64BE(BigInt(value), offset); }
function pad(value) { return Math.ceil(value / 4) * 4; }

function option(code, value, little = true) {
  const data = Buffer.from(value);
  const out = Buffer.alloc(4 + pad(data.length));
  write16(out, 0, code, little);
  write16(out, 2, data.length, little);
  data.copy(out, 4);
  return out;
}
function end_options(little = true) { return option(0, Buffer.alloc(0), little); }
function block(type, body, little = true) {
  const payload = Buffer.from(body);
  assert.equal(payload.length % 4, 0);
  const length = 12 + payload.length;
  const out = Buffer.alloc(length);
  write32(out, 0, type, little);
  write32(out, 4, length, little);
  payload.copy(out, 8);
  write32(out, length - 4, length, little);
  return out;
}
function section(little = true, options = end_options(little)) {
  const body = Buffer.alloc(16);
  write32(body, 0, 0x1a2b3c4d, little);
  write16(body, 4, 1, little);
  write16(body, 6, 0, little);
  little ? body.writeBigInt64LE(-1n, 8) : body.writeBigInt64BE(-1n, 8);
  return block(0x0a0d0d0a, Buffer.concat([body, options]), little);
}
function interface_block(little = true, { link_type = 1, snap_length = 65535, options = end_options(little) } = {}) {
  const body = Buffer.alloc(8);
  write16(body, 0, link_type, little);
  write16(body, 2, 0, little);
  write32(body, 4, snap_length, little);
  return block(1, Buffer.concat([body, options]), little);
}
function enhanced_packet(little, packet, { interface_id = 0, high = 1, low = 2, original_length = packet.length, options = end_options(little) } = {}) {
  const data = Buffer.from(packet);
  const body = Buffer.alloc(20 + pad(data.length));
  write32(body, 0, interface_id, little);
  write32(body, 4, high, little);
  write32(body, 8, low, little);
  write32(body, 12, data.length, little);
  write32(body, 16, original_length, little);
  data.copy(body, 20);
  return block(6, Buffer.concat([body, options]), little);
}
function simple_packet(little, packet, original_length = packet.length) {
  const data = Buffer.from(packet);
  const body = Buffer.alloc(4 + pad(data.length));
  write32(body, 0, original_length, little);
  data.copy(body, 4);
  return block(3, body, little);
}
function ethernet_ipv4_tcp() {
  const packet = Buffer.alloc(38);
  packet.writeUInt16BE(0x0800, 12);
  packet[14] = 0x45;
  packet.writeUInt16BE(24, 16);
  packet[23] = 6;
  packet.set([10, 0, 0, 1], 26);
  packet.set([10, 0, 0, 2], 30);
  packet.writeUInt16BE(12345, 34);
  packet.writeUInt16BE(443, 36);
  return packet;
}

test('PCAPNG parses little-endian section, interface options, enhanced packet and endpoint metadata', () => {
  const little = true;
  const if_options = Buffer.concat([
    option(2, Buffer.from('eth0'), little),
    option(9, Buffer.from([9]), little),
    option(14, Buffer.from([0,0,0,0,0,0,0,0]), little),
    end_options(little),
  ]);
  const capture = Buffer.concat([
    section(little),
    interface_block(little, { options: if_options }),
    enhanced_packet(little, ethernet_ipv4_tcp()),
  ]);
  const report = parse_pcapng(capture);
  assert.equal(report.format, 'PCAPNG');
  assert.equal(report.summary.sections, 1);
  assert.equal(report.interfaces[0].name, 'eth0');
  assert.deepEqual(report.interfaces[0].timestamp_resolution, { base: 10, exponent: 9 });
  assert.equal(report.packets.length, 1);
  assert.equal(report.packets[0].timestamp.ticks, '4294967298');
  assert.equal(report.packets[0].network.protocol, 'IPv4');
  assert.equal(report.packets[0].network.transport.source_port, 12345);
  assert.equal(report.packets[0].network.transport.destination_port, 443);
  assert.equal('payload' in report.packets[0], false);
});

test('PCAPNG supports big-endian sections and resets interface IDs between sections', () => {
  const capture = Buffer.concat([
    section(true),
    interface_block(true, { link_type: 101 }),
    section(false),
    interface_block(false, { link_type: 101 }),
    enhanced_packet(false, Buffer.from([0x45,0,0,20,0,0,0,0,64,1,0,0,192,0,2,1,192,0,2,2]), { interface_id: 0, high: 0, low: 7 }),
  ]);
  const report = parse_pcapng(capture);
  assert.equal(report.sections.length, 2);
  assert.equal(report.interfaces[1].section_index, 1);
  assert.equal(report.packets[0].section_index, 1);
  assert.equal(report.packets[0].network.protocol, 'IPv4');
});

test('PCAPNG parses Simple Packet Blocks without inventing timestamps', () => {
  const packet = ethernet_ipv4_tcp();
  const capture = Buffer.concat([section(), interface_block(true), simple_packet(true, packet)]);
  const report = parse_pcapng(capture);
  assert.equal(report.packets.length, 1);
  assert.equal(report.packets[0].timestamp, null);
  assert.equal(report.packets[0].captured_length, packet.length);
  assert.equal(report.packets[0].network.transport.destination_port, 443);
});

test('PCAPNG inventories name-resolution and interface-statistics blocks without retaining names', () => {
  const little = true;
  const record_value = Buffer.from([127,0,0,1, ...Buffer.from('localhost\0')]);
  const nrb_record = Buffer.alloc(4 + pad(record_value.length));
  write16(nrb_record, 0, 1, little);
  write16(nrb_record, 2, record_value.length, little);
  record_value.copy(nrb_record, 4);
  const nrb_end = Buffer.alloc(4);
  const isb_fixed = Buffer.alloc(12);
  write32(isb_fixed, 0, 0, little);
  write32(isb_fixed, 4, 0, little);
  write32(isb_fixed, 8, 99, little);
  const stats_option = option(4, Buffer.from([1,0,0,0,0,0,0,0]), little);
  const capture = Buffer.concat([
    section(little),
    interface_block(little),
    block(4, Buffer.concat([nrb_record, nrb_end]), little),
    block(5, Buffer.concat([isb_fixed, stats_option, end_options(little)]), little),
  ]);
  const report = parse_pcapng(capture);
  assert.equal(report.name_resolution[0].record_count, 1);
  assert.equal(report.interface_statistics[0].interface_id, 0);
  assert.equal(JSON.stringify(report).includes('localhost'), false);
});

test('PCAPNG inventories decryption secret metadata but never exposes secret bytes', () => {
  const secret = Buffer.from('SENSITIVE-KEY-MATERIAL');
  const fixed = Buffer.alloc(8);
  write32(fixed, 0, 0x544c534b, true);
  write32(fixed, 4, secret.length, true);
  const body = Buffer.concat([fixed, secret, Buffer.alloc(pad(secret.length) - secret.length), end_options()]);
  const report = parse_pcapng(Buffer.concat([section(), block(10, body)]));
  assert.equal(report.decryption_secrets[0].content_exposed, false);
  assert.equal(report.decryption_secrets[0].secret_bytes, secret.length);
  assert.equal(JSON.stringify(report).includes('SENSITIVE-KEY-MATERIAL'), false);
});

test('PCAPNG preserves unknown block metadata without interpreting block payloads', () => {
  const unknown = block(0x12345678, Buffer.from([1,2,3,4]));
  const report = parse_pcapng(Buffer.concat([section(), unknown]));
  assert.equal(report.summary.unsupported_blocks, 1);
  assert.equal(report.blocks[1].supported, false);
});

test('PCAPNG rejects bad byte-order magic, block lengths and trailing-length mismatches', () => {
  const bad_bom = section();
  bad_bom[8] = 0;
  assert.throws(() => parse_pcapng(bad_bom), error => error.code === 'ORIX_PCAPNG_BAD_BYTE_ORDER_MAGIC');
  const bad_length = section();
  bad_length.writeUInt32LE(27, 4);
  assert.throws(() => parse_pcapng(bad_length), error => error.code === 'ORIX_PCAPNG_BAD_BLOCK_LENGTH');
  const bad_trailer = section();
  bad_trailer.writeUInt32LE(0, bad_trailer.length - 4);
  assert.throws(() => parse_pcapng(bad_trailer), error => error.code === 'ORIX_PCAPNG_BLOCK_LENGTH_MISMATCH');
});

test('PCAPNG rejects packets with unknown interfaces, invalid options and malformed packet ranges', () => {
  const packet = ethernet_ipv4_tcp();
  const missing_interface = enhanced_packet(true, packet, { interface_id: 1 });
  assert.throws(() => parse_pcapng(Buffer.concat([section(), interface_block(), missing_interface])), error => error.code === 'ORIX_PCAPNG_UNKNOWN_INTERFACE');
  const invalid_tsresol = interface_block(true, { options: Buffer.concat([option(9, Buffer.from([1,2])), end_options()]) });
  assert.throws(() => parse_pcapng(Buffer.concat([section(), invalid_tsresol])), error => error.code === 'ORIX_PCAPNG_BAD_TSRESOL');
  const too_short = enhanced_packet(true, packet);
  too_short.writeUInt32LE(0xffffffff, 20);
  assert.throws(() => parse_pcapng(Buffer.concat([section(), interface_block(), too_short])), error => error.code === 'ORIX_PCAPNG_PACKET_RANGE');
});

test('PCAPNG enforces packet, byte, block, interface and secret ceilings', () => {
  const packet = ethernet_ipv4_tcp();
  const one_packet = Buffer.concat([section(), interface_block(), enhanced_packet(true, packet)]);
  const two_packets = Buffer.concat([one_packet, enhanced_packet(true, packet, { high: 2, low: 3 })]);
  const two_interfaces = Buffer.concat([section(), interface_block(), interface_block(true, { link_type: 101 })]);
  assert.throws(() => parse_pcapng(two_packets, { max_packets: 1 }), error => error.code === 'ORIX_PCAPNG_PACKET_LIMIT');
  assert.throws(() => parse_pcapng(one_packet, { max_total_packet_bytes: 8 }), error => error.code === 'ORIX_PCAPNG_TOTAL_BYTE_LIMIT');
  assert.throws(() => parse_pcapng(one_packet, { max_packet_bytes: 8 }), error => error.code === 'ORIX_PCAPNG_PACKET_SIZE_LIMIT');
  assert.throws(() => parse_pcapng(one_packet, { max_blocks: 1 }), error => error.code === 'ORIX_PCAPNG_BLOCK_LIMIT');
  assert.throws(() => parse_pcapng(two_interfaces, { max_interfaces: 1 }), error => error.code === 'ORIX_PCAPNG_INTERFACE_LIMIT');
  assert.throws(() => parse_pcapng(one_packet, null), /PCAPNG options must be an object/);
  const secret = Buffer.alloc(16);
  write32(secret, 0, 1, true);
  write32(secret, 4, 8, true);
  assert.throws(() => parse_pcapng(Buffer.concat([section(), block(10, Buffer.concat([secret, Buffer.alloc(8), end_options()]))]), { max_secret_bytes: 4 }), error => error.code === 'ORIX_PCAPNG_SECRET_LIMIT');
});

test('PCAPNG is registered for inspection, package subpath and public API', async () => {
  const capture = Buffer.concat([section(), interface_block()]);
  const result = analyze_known_format(capture);
  assert.equal(result.detection.format, 'PCAPNG');
  assert.equal(result.parser_status, 'parsed');
  const subpath = await import('@orix/cli/formats/pcapng');
  assert.equal(typeof subpath.parse_pcapng, 'function');
  const root = await import('../src/index.mjs');
  assert.equal(typeof root.parse_pcapng, 'function');
});
