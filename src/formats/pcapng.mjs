// JavaScript, src/formats/pcapng.mjs, Node.js 20+, bounded read-only PCAPNG metadata parser.
// Packet payload bytes and decryption secrets are never returned.
import { OrixError } from '../core/errors.mjs';
import { parse_network_metadata } from './pcap.mjs';

const SHB = 0x0a0d0d0a;
const DEFAULTS = Object.freeze({
  max_input_bytes: 128 * 1024 * 1024,
  max_blocks: 200000,
  max_interfaces: 4096,
  max_packets: 100000,
  max_packet_bytes: 1 * 1024 * 1024,
  max_total_packet_bytes: 128 * 1024 * 1024,
  max_options_per_block: 10000,
  max_name_bytes: 4096,
  max_secret_bytes: 1024 * 1024,
});
const LINK_TYPES = new Map([[0, 'NULL'], [1, 'Ethernet'], [12, 'Raw IP (legacy DLT_RAW)'], [101, 'Raw IP'], [113, 'Linux cooked capture']]);

function invalid(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}
function limits_for(options) {
  const limits = {};
  for (const [key, fallback] of Object.entries(DEFAULTS)) {
    const value = options[key] ?? fallback;
    if (!Number.isSafeInteger(value) || value < 1 || value > fallback) throw new TypeError(key + ' must be a positive integer no greater than ' + fallback);
    limits[key] = value;
  }
  return limits;
}
function need(buffer, offset, length, label) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset > buffer.length || length > buffer.length - offset) {
    invalid('ORIX_PCAPNG_TRUNCATED', 'PCAPNG is truncated while reading ' + label, { offset, length, input_size: buffer.length });
  }
}
function u16(buffer, offset, little, label) {
  need(buffer, offset, 2, label);
  return little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
}
function u32(buffer, offset, little, label) {
  need(buffer, offset, 4, label);
  return little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
}
function i64(buffer, offset, little, label) {
  need(buffer, offset, 8, label);
  return (little ? buffer.readBigInt64LE(offset) : buffer.readBigInt64BE(offset)).toString();
}
function decode_text(value, label, offset, max_bytes) {
  if (value.length > max_bytes) invalid('ORIX_PCAPNG_NAME_LIMIT', 'PCAPNG ' + label + ' exceeds configured byte limit', { offset, length: value.length, max_name_bytes: max_bytes });
  const text = value.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(value)) invalid('ORIX_PCAPNG_INVALID_UTF8', 'PCAPNG ' + label + ' is not valid UTF-8', { offset });
  return text;
}
function padded(length) {
  return Math.ceil(length / 4) * 4;
}
function parse_options(buffer, start, end, little, limits) {
  const options = [];
  let cursor = start;
  while (cursor < end) {
    if (options.length >= limits.max_options_per_block) invalid('ORIX_PCAPNG_OPTION_LIMIT', 'PCAPNG option count exceeds configured limit', { limit: limits.max_options_per_block });
    need(buffer, cursor, 4, 'option header');
    const code = u16(buffer, cursor, little, 'option code');
    const length = u16(buffer, cursor + 2, little, 'option length');
    cursor += 4;
    if (code === 0) {
      if (length !== 0) invalid('ORIX_PCAPNG_BAD_END_OPTION', 'PCAPNG end-of-options marker must have zero length', { offset: cursor - 4, length });
      if (cursor !== end && !buffer.subarray(cursor, end).every(byte => byte === 0)) invalid('ORIX_PCAPNG_OPTION_TRAILING_DATA', 'Non-zero bytes follow PCAPNG end-of-options marker', { offset: cursor });
      return options;
    }
    const size = padded(length);
    if (size > end - cursor) invalid('ORIX_PCAPNG_OPTION_RANGE', 'PCAPNG option value or padding exceeds block bounds', { code, length, offset: cursor });
    options.push({ code, value: buffer.subarray(cursor, cursor + length), offset: cursor });
    cursor += size;
  }
  return options;
}
function option_map(options) {
  const map = new Map();
  for (const option of options) map.set(option.code, option.value);
  return map;
}
function parse_tsresol(value, offset) {
  if (!value || value.length !== 1) invalid('ORIX_PCAPNG_BAD_TSRESOL', 'Interface timestamp resolution option must contain one byte', { offset, length: value?.length ?? 0 });
  const byte = value[0];
  return { base: byte & 0x80 ? 2 : 10, exponent: byte & 0x7f };
}
function option_u32(map, code, little, label) {
  const value = map.get(code);
  if (!value) return null;
  if (value.length !== 4) invalid('ORIX_PCAPNG_BAD_OPTION_LENGTH', 'PCAPNG ' + label + ' option must be four bytes', { code, length: value.length });
  return little ? value.readUInt32LE(0) : value.readUInt32BE(0);
}
function option_i64(map, code, little, label) {
  const value = map.get(code);
  if (!value) return null;
  if (value.length !== 8) invalid('ORIX_PCAPNG_BAD_OPTION_LENGTH', 'PCAPNG ' + label + ' option must be eight bytes', { code, length: value.length });
  return (little ? value.readBigInt64LE(0) : value.readBigInt64BE(0)).toString();
}
function parse_interface_options(options, little, limits) {
  const map = option_map(options);
  const name = map.has(2) ? decode_text(map.get(2), 'interface name', 0, limits.max_name_bytes) : null;
  const description = map.has(3) ? decode_text(map.get(3), 'interface description', 0, limits.max_name_bytes) : null;
  const os = map.has(12) ? decode_text(map.get(12), 'interface OS', 0, limits.max_name_bytes) : null;
  const resolution = map.has(9) ? parse_tsresol(map.get(9), 0) : { base: 10, exponent: 6 };
  const fcs_length = map.get(13);
  if (fcs_length && fcs_length.length !== 1) invalid('ORIX_PCAPNG_BAD_OPTION_LENGTH', 'Interface FCS length option must be one byte', { length: fcs_length.length });
  const timezone = option_u32(map, 10, little, 'interface timezone');
  return {
    name,
    description,
    os,
    speed: option_i64(map, 8, little, 'interface speed'),
    timestamp_resolution: resolution,
    timezone_seconds: timezone === null ? null : (timezone | 0),
    timestamp_offset_seconds: option_i64(map, 14, little, 'interface timestamp offset'),
    fcs_length_bits: fcs_length ? fcs_length[0] : null,
    option_count: options.length,
  };
}
function parse_timestamp(high, low) {
  return ((BigInt(high) << 32n) | BigInt(low)).toString();
}
function packet_options(options, little) {
  const map = option_map(options);
  const flags = option_u32(map, 2, little, 'packet flags');
  const drop_count = map.get(4);
  if (drop_count && drop_count.length !== 8) invalid('ORIX_PCAPNG_BAD_OPTION_LENGTH', 'Enhanced packet drop-count option must be eight bytes', { length: drop_count.length });
  return { flags, drop_count: drop_count ? (little ? drop_count.readBigUInt64LE(0) : drop_count.readBigUInt64BE(0)).toString() : null, option_count: options.length };
}
function packet_record(buffer, packet_offset, captured_length, original_length, interface_info, limits, state, timestamp, options = null) {
  if (captured_length > limits.max_packet_bytes) invalid('ORIX_PCAPNG_PACKET_SIZE_LIMIT', 'PCAPNG captured packet exceeds configured packet-size limit', { captured_length, limit: limits.max_packet_bytes });
  if (original_length < captured_length) invalid('ORIX_PCAPNG_INVALID_PACKET_LENGTH', 'Original packet length is smaller than captured packet length', { captured_length, original_length });
  if (interface_info.snap_length > 0 && captured_length > interface_info.snap_length) invalid('ORIX_PCAPNG_SNAPLEN_EXCEEDED', 'Captured packet exceeds its interface snapshot length', { captured_length, snap_length: interface_info.snap_length, interface_id: interface_info.id });
  if (captured_length > limits.max_total_packet_bytes - state.total_packet_bytes) invalid('ORIX_PCAPNG_TOTAL_BYTE_LIMIT', 'PCAPNG packet bytes exceed configured aggregate limit', { total_packet_bytes: state.total_packet_bytes, captured_length, limit: limits.max_total_packet_bytes });
  need(buffer, packet_offset, captured_length, 'packet bytes');
  const packet_data = buffer.subarray(packet_offset, packet_offset + captured_length);
  const network = parse_network_metadata(packet_data, 0, interface_info.link_type);
  state.total_packet_bytes += captured_length;
  state.packet_count += 1;
  return {
    index: state.packet_count - 1,
    section_index: interface_info.section_index,
    interface_id: interface_info.id,
    timestamp,
    captured_length,
    original_length,
    capture_truncated: captured_length < original_length,
    network,
    options,
  };
}
export function parse_pcapng(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_pcapng requires a Buffer');
  if (options === null || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('PCAPNG options must be an object');
  const limits = limits_for(options);
  if (buffer.length > limits.max_input_bytes) invalid('ORIX_PCAPNG_INPUT_LIMIT', 'PCAPNG input exceeds configured byte limit', { size: buffer.length, limit: limits.max_input_bytes });
  if (buffer.length < 28 || buffer.readUInt32BE(0) !== SHB) invalid('ORIX_PCAPNG_BAD_MAGIC', 'PCAPNG input must begin with a Section Header Block');
  const sections = [];
  const interfaces = [];
  const packets = [];
  const blocks = [];
  const block_type_counts = {};
  const name_resolution = [];
  const interface_statistics = [];
  const decryption_secrets = [];
  const state = { packet_count: 0, total_packet_bytes: 0 };
  let cursor = 0;
  let section_index = -1;
  let little = true;
  let current_interfaces = [];
  while (cursor < buffer.length) {
    if (blocks.length >= limits.max_blocks) invalid('ORIX_PCAPNG_BLOCK_LIMIT', 'PCAPNG block count exceeds configured limit', { limit: limits.max_blocks });
    need(buffer, cursor, 12, 'block header');
    const is_section_header = buffer.readUInt32BE(cursor) === SHB;
    let type;
    let length;
    if (is_section_header) {
      need(buffer, cursor, 12, 'section header byte-order magic');
      const bom = buffer.subarray(cursor + 8, cursor + 12).toString('hex');
      if (bom === '4d3c2b1a') little = true;
      else if (bom === '1a2b3c4d') little = false;
      else invalid('ORIX_PCAPNG_BAD_BYTE_ORDER_MAGIC', 'PCAPNG section has an invalid byte-order magic', { offset: cursor, bom });
      type = SHB;
      length = u32(buffer, cursor + 4, little, 'section block length');
    } else {
      if (section_index < 0) invalid('ORIX_PCAPNG_SECTION_REQUIRED', 'PCAPNG data block appears before a Section Header Block', { offset: cursor });
      type = u32(buffer, cursor, little, 'block type');
      length = u32(buffer, cursor + 4, little, 'block length');
    }
    if (length < 12 || length % 4 !== 0 || length > buffer.length - cursor) invalid('ORIX_PCAPNG_BAD_BLOCK_LENGTH', 'PCAPNG block length is invalid or outside input bounds', { offset: cursor, type, length, remaining: buffer.length - cursor });
    const block_end = cursor + length;
    const trailing_length = u32(buffer, block_end - 4, little, 'trailing block length');
    if (trailing_length !== length) invalid('ORIX_PCAPNG_BLOCK_LENGTH_MISMATCH', 'PCAPNG leading and trailing block lengths differ', { offset: cursor, leading: length, trailing: trailing_length });
    block_type_counts[type] = (block_type_counts[type] ?? 0) + 1;
    let summary = { type, length, offset: cursor, section_index: Math.max(section_index, 0) };

    if (type === SHB) {
      if (length < 28) invalid('ORIX_PCAPNG_BAD_SECTION_HEADER', 'PCAPNG Section Header Block is shorter than its fixed fields', { offset: cursor, length });
      section_index += 1;
      current_interfaces = [];
      const major = u16(buffer, cursor + 12, little, 'section major version');
      const minor = u16(buffer, cursor + 14, little, 'section minor version');
      const section_length = i64(buffer, cursor + 16, little, 'section length');
      const shb_options = parse_options(buffer, cursor + 24, block_end - 4, little, limits);
      sections.push({ index: section_index, major, minor, section_length, option_count: shb_options.length });
      summary = { ...summary, version: major + '.' + minor, section_length };
    } else if (type === 1) {
      if (length < 20) invalid('ORIX_PCAPNG_BAD_INTERFACE_BLOCK', 'Interface Description Block is too short', { offset: cursor, length });
      const link_type = u16(buffer, cursor + 8, little, 'interface link type');
      const reserved = u16(buffer, cursor + 10, little, 'interface reserved field');
      if (reserved !== 0) invalid('ORIX_PCAPNG_BAD_INTERFACE_RESERVED', 'Interface Description Block reserved field must be zero', { offset: cursor, reserved });
      const snap_length = u32(buffer, cursor + 12, little, 'interface snapshot length');
      const interface_options = parse_options(buffer, cursor + 16, block_end - 4, little, limits);
      const metadata = parse_interface_options(interface_options, little, limits);
      const info = { id: current_interfaces.length, section_index, link_type, link_type_name: LINK_TYPES.get(link_type) ?? 'unknown', snap_length, ...metadata };
      current_interfaces.push(info);
      interfaces.push(info);
      if (current_interfaces.length > limits.max_interfaces) invalid('ORIX_PCAPNG_INTERFACE_LIMIT', 'PCAPNG interface count exceeds configured limit', { limit: limits.max_interfaces, section_index });
      summary = { ...summary, interface_id: info.id, link_type, snap_length, option_count: interface_options.length };
    } else if (type === 6 || type === 2) {
      const fixed = type === 6 ? 20 : 20;
      if (length < 32) invalid('ORIX_PCAPNG_BAD_PACKET_BLOCK', 'PCAPNG packet block is shorter than fixed fields', { offset: cursor, type, length });
      const interface_id = type === 6 ? u32(buffer, cursor + 8, little, 'enhanced packet interface id') : u16(buffer, cursor + 8, little, 'packet interface id');
      const interface_info = current_interfaces[interface_id];
      if (!interface_info) invalid('ORIX_PCAPNG_UNKNOWN_INTERFACE', 'PCAPNG packet references an unknown interface', { offset: cursor, interface_id, section_index });
      const timestamp_high = type === 6 ? u32(buffer, cursor + 12, little, 'packet timestamp high') : u32(buffer, cursor + 12, little, 'packet timestamp high');
      const timestamp_low = type === 6 ? u32(buffer, cursor + 16, little, 'packet timestamp low') : u32(buffer, cursor + 16, little, 'packet timestamp low');
      const captured_length = u32(buffer, cursor + 20, little, 'packet captured length');
      const original_length = u32(buffer, cursor + 24, little, 'packet original length');
      const data_offset = cursor + 28;
      const padded_length = padded(captured_length);
      const option_offset = data_offset + padded_length;
      if (option_offset > block_end - 4) invalid('ORIX_PCAPNG_PACKET_RANGE', 'PCAPNG packet data or padding exceeds block bounds', { offset: cursor, captured_length, padded_length });
      const packet_opts = parse_options(buffer, option_offset, block_end - 4, little, limits);
      const packet = packet_record(buffer, data_offset, captured_length, original_length, interface_info, limits, state, {
        ticks: parse_timestamp(timestamp_high, timestamp_low),
        resolution: interface_info.timestamp_resolution,
        offset_seconds: interface_info.timestamp_offset_seconds ?? '0',
      }, packet_options(packet_opts, little));
      packets.push(packet);
      summary = { ...summary, interface_id, captured_length, original_length, packet_index: packet.index };
    } else if (type === 3) {
      if (length < 16) invalid('ORIX_PCAPNG_BAD_SIMPLE_PACKET_BLOCK', 'Simple Packet Block is too short', { offset: cursor, length });
      const interface_info = current_interfaces[0];
      if (!interface_info) invalid('ORIX_PCAPNG_UNKNOWN_INTERFACE', 'Simple Packet Block requires interface zero to be declared first', { offset: cursor, section_index });
      const original_length = u32(buffer, cursor + 8, little, 'simple packet original length');
      const captured_length = interface_info.snap_length > 0 ? Math.min(original_length, interface_info.snap_length) : original_length;
      const expected_padded = padded(captured_length);
      if (expected_padded !== length - 16) invalid('ORIX_PCAPNG_SIMPLE_PACKET_RANGE', 'Simple Packet Block data length does not match interface snap length and block bounds', { offset: cursor, captured_length, expected_padded, block_length: length });
      const packet = packet_record(buffer, cursor + 12, captured_length, original_length, interface_info, limits, state, null, null);
      packets.push(packet);
      summary = { ...summary, interface_id: 0, captured_length, original_length, packet_index: packet.index, timestamp_present: false };
    } else if (type === 4) {
      let at = cursor + 8;
      let records = 0;
      const counts = {};
      let terminated = false;
      while (at < block_end - 4) {
        need(buffer, at, 4, 'name-resolution record header');
        const record_type = u16(buffer, at, little, 'name-resolution record type');
        const record_length = u16(buffer, at + 2, little, 'name-resolution record length');
        at += 4;
        if (record_type === 0) {
          if (record_length !== 0) invalid('ORIX_PCAPNG_BAD_NAME_RESOLUTION_END', 'Name-resolution end record must have zero length', { offset: at - 4, record_length });
          terminated = true;
          break;
        }
        const record_padded = padded(record_length);
        if (record_padded > block_end - 4 - at) invalid('ORIX_PCAPNG_NAME_RESOLUTION_RANGE', 'Name-resolution record exceeds block bounds', { offset: at, record_length });
        counts[record_type] = (counts[record_type] ?? 0) + 1;
        records += 1;
        at += record_padded;
      }
      if (!terminated) invalid('ORIX_PCAPNG_NAME_RESOLUTION_UNTERMINATED', 'Name-resolution block lacks an end record', { offset: cursor });
      name_resolution.push({ section_index, record_count: records, record_types: counts });
      summary = { ...summary, record_count: records };
    } else if (type === 5) {
      if (length < 24) invalid('ORIX_PCAPNG_BAD_INTERFACE_STATS', 'Interface Statistics Block is too short', { offset: cursor, length });
      const interface_id = u32(buffer, cursor + 8, little, 'statistics interface id');
      if (!current_interfaces[interface_id]) invalid('ORIX_PCAPNG_UNKNOWN_INTERFACE', 'Interface Statistics Block references an unknown interface', { offset: cursor, interface_id });
      const timestamp_high = u32(buffer, cursor + 12, little, 'statistics timestamp high');
      const timestamp_low = u32(buffer, cursor + 16, little, 'statistics timestamp low');
      const stats_options = parse_options(buffer, cursor + 20, block_end - 4, little, limits);
      interface_statistics.push({ section_index, interface_id, timestamp_ticks: parse_timestamp(timestamp_high, timestamp_low), option_count: stats_options.length });
      summary = { ...summary, interface_id, option_count: stats_options.length };
    } else if (type === 10) {
      if (length < 20) invalid('ORIX_PCAPNG_BAD_DECRYPTION_SECRETS_BLOCK', 'Decryption Secrets Block is too short', { offset: cursor, length });
      const secret_type = u32(buffer, cursor + 8, little, 'decryption secret type');
      const secret_length = u32(buffer, cursor + 12, little, 'decryption secret length');
      if (secret_length > limits.max_secret_bytes) invalid('ORIX_PCAPNG_SECRET_LIMIT', 'Decryption Secrets Block exceeds configured metadata ceiling', { secret_length, limit: limits.max_secret_bytes });
      const data_padded = padded(secret_length);
      const option_offset = cursor + 16 + data_padded;
      if (option_offset > block_end - 4) invalid('ORIX_PCAPNG_SECRET_RANGE', 'Decryption Secrets Block data exceeds block bounds', { offset: cursor, secret_length });
      const secret_options = parse_options(buffer, option_offset, block_end - 4, little, limits);
      decryption_secrets.push({ section_index, secret_type, secret_bytes: secret_length, option_count: secret_options.length, content_exposed: false });
      summary = { ...summary, secret_type, secret_bytes: secret_length, content_exposed: false };
    } else {
      summary = { ...summary, supported: false };
    }
    blocks.push(summary);
    cursor = block_end;
  }
  if (section_index < 0 || sections.length === 0) invalid('ORIX_PCAPNG_SECTION_REQUIRED', 'PCAPNG stream contains no Section Header Block');
  return {
    format: 'PCAPNG',
    sections,
    interfaces,
    packets,
    name_resolution,
    interface_statistics,
    decryption_secrets,
    blocks,
    summary: {
      sections: sections.length,
      blocks: blocks.length,
      interfaces: interfaces.length,
      packets: packets.length,
      captured_packet_bytes: state.total_packet_bytes,
      block_types: block_type_counts,
      decryption_secrets_blocks: decryption_secrets.length,
      unsupported_blocks: blocks.filter(block => block.supported === false).length,
    },
    limits,
    limitations: [
      'Offline PCAPNG block and packet metadata only; this parser does not capture live traffic, replay packets or export packet payloads.',
      'Packet payload bytes and decryption secret contents are never returned; only bounded network endpoint/transport metadata is derived.',
      'Interface timestamp resolution and offset metadata are reported; timestamps are not independently authenticated.',
      'Name-resolution records are counted by type but names/addresses are not retained.',
      'IPv6 extension traversal, IP reassembly, checksum validation and application-protocol dissection are not implemented.',
      'Unknown block types are length-validated and inventoried without interpreting their payloads.',
    ],
  };
}
