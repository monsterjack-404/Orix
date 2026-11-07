// JavaScript, src/formats/pcap.mjs, Node.js 20+, bounded classic PCAP metadata parser.
// Packet payloads are never returned or decoded.

import { OrixError } from '../core/errors.mjs';

const MAGIC = new Map([
  ['d4c3b2a1', { little_endian: true, timestamp_resolution: 'microseconds' }],
  ['a1b2c3d4', { little_endian: false, timestamp_resolution: 'microseconds' }],
  ['4d3cb2a1', { little_endian: true, timestamp_resolution: 'nanoseconds' }],
  ['a1b23c4d', { little_endian: false, timestamp_resolution: 'nanoseconds' }],
]);
const LINK_TYPES = new Map([[0, 'NULL'], [1, 'Ethernet'], [12, 'Raw IP (legacy DLT_RAW)'], [101, 'Raw IP'], [113, 'Linux cooked capture']]);

function invalid(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function read_u16(buffer, offset, little, label) {
  if (offset < 0 || offset > buffer.length - 2) invalid('ORIX_PCAP_TRUNCATED', 'PCAP is truncated while reading ' + label, { offset });
  return little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
}
function read_u32(buffer, offset, little, label) {
  if (offset < 0 || offset > buffer.length - 4) invalid('ORIX_PCAP_TRUNCATED', 'PCAP is truncated while reading ' + label, { offset });
  return little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
}
function ipv4(bytes, offset) {
  return [bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]].join('.');
}
function ipv6(bytes, offset) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(bytes.readUInt16BE(offset + i).toString(16));
  return groups.join(':');
}

function parse_transport(bytes, offset, available, protocol, fragmented) {
  if (![6, 17].includes(protocol) || fragmented || available < 4) return { protocol: protocol === 6 ? 'TCP' : protocol === 17 ? 'UDP' : 'other', source_port: null, destination_port: null };
  const source_port = bytes.readUInt16BE(offset);
  const destination_port = bytes.readUInt16BE(offset + 2);
  return { protocol: protocol === 6 ? 'TCP' : protocol === 17 ? 'UDP' : 'other', source_port, destination_port };
}

export function parse_network_metadata(bytes, offset, link_type) {
  let ether_type = null;
  let ip_offset = offset;
  if (link_type === 1) {
    if (bytes.length - offset < 14) return { layer: 'link', status: 'truncated-header', protocol: null };
    ether_type = bytes.readUInt16BE(offset + 12);
    ip_offset = offset + 14;
    let vlan_depth = 0;
    while ([0x8100, 0x88a8, 0x9100].includes(ether_type) && vlan_depth < 4) {
      if (bytes.length - ip_offset < 4) return { layer: 'link', status: 'truncated-vlan', protocol: null, vlan_depth };
      ether_type = bytes.readUInt16BE(ip_offset + 2);
      ip_offset += 4;
      vlan_depth += 1;
    }
    if ([0x8100, 0x88a8, 0x9100].includes(ether_type)) return { layer: 'link', status: 'vlan-depth-limit', protocol: null, vlan_depth };
  } else if (link_type === 113) {
    if (bytes.length - offset < 16) return { layer: 'link', status: 'truncated-header', protocol: null };
    ether_type = bytes.readUInt16BE(offset + 14);
    ip_offset = offset + 16;
  } else if (link_type === 0) {
    // BSD loopback DLT_NULL stores an OS-specific protocol-family value in
    // the capture host's byte order, which may differ from this reader.
    if (bytes.length - offset < 4) return { layer: 'link', status: 'truncated-null-header', protocol: null };
    const family_little = bytes.readUInt32LE(offset);
    const family_big = bytes.readUInt32BE(offset);
    const families = new Set([family_little, family_big]);
    if (families.has(2)) ether_type = 0x0800; // AF_INET
    else if ([24, 26, 28, 30].some(value => families.has(value))) ether_type = 0x86dd; // common BSD AF_INET6 values
    else return { layer: 'link', status: 'unsupported-null-family', protocol: null };
    ip_offset = offset + 4;
  } else if ([12, 101].includes(link_type)) {
    ether_type = bytes.length > offset ? (bytes[offset] >>> 4) === 4 ? 0x0800 : (bytes[offset] >>> 4) === 6 ? 0x86dd : null : null;
  } else {
    return { layer: 'link', status: 'unsupported-link-type', protocol: null };
  }

  if (ether_type === 0x0800) {
    if (bytes.length - ip_offset < 20) return { layer: 'network', status: 'truncated-ipv4-header', protocol: 'IPv4' };
    const version_ihl = bytes[ip_offset];
    const version = version_ihl >>> 4;
    const header_length = (version_ihl & 0x0f) * 4;
    if (version !== 4 || header_length < 20 || bytes.length - ip_offset < header_length) {
      return { layer: 'network', status: 'invalid-ipv4-header', protocol: 'IPv4' };
    }
    const total_length = bytes.readUInt16BE(ip_offset + 2);
    if (total_length < header_length) return { layer: 'network', status: 'invalid-ipv4-length', protocol: 'IPv4' };
    const fragment = bytes.readUInt16BE(ip_offset + 6);
    const fragmented = Boolean(fragment & 0x3fff);
    const protocol = bytes[ip_offset + 9];
    const transport_offset = ip_offset + header_length;
    const captured_ip_bytes = bytes.length - ip_offset;
    const transport = parse_transport(bytes, transport_offset, Math.min(total_length, captured_ip_bytes) - header_length, protocol, fragmented);
    return {
      layer: 'network', status: captured_ip_bytes < total_length ? 'captured-truncated' : 'parsed',
      protocol: 'IPv4', source: ipv4(bytes, ip_offset + 12), destination: ipv4(bytes, ip_offset + 16),
      ip_protocol_number: protocol, transport, fragmented, declared_length: total_length,
    };
  }
  if (ether_type === 0x86dd) {
    if (bytes.length - ip_offset < 40) return { layer: 'network', status: 'truncated-ipv6-header', protocol: 'IPv6' };
    if ((bytes[ip_offset] >>> 4) !== 6) return { layer: 'network', status: 'invalid-ipv6-header', protocol: 'IPv6' };
    const payload_length = bytes.readUInt16BE(ip_offset + 4);
    const next_header = bytes[ip_offset + 6];
    const transport_offset = ip_offset + 40;
    const available = Math.min(payload_length, bytes.length - transport_offset);
    const transport = [6, 17].includes(next_header)
      ? parse_transport(bytes, transport_offset, available, next_header, false)
      : { protocol: 'other', source_port: null, destination_port: null };
    return {
      layer: 'network', status: bytes.length - ip_offset < 40 + payload_length ? 'captured-truncated' : 'parsed',
      protocol: 'IPv6', source: ipv6(bytes, ip_offset + 8), destination: ipv6(bytes, ip_offset + 24),
      ip_protocol_number: next_header, transport, extension_headers_not_decoded: [0, 43, 44, 50, 51, 60, 135, 139, 140].includes(next_header),
      declared_length: 40 + payload_length,
    };
  }
  return { layer: 'link', status: 'non-ip-or-unsupported-ethertype', ether_type };
}

/**
 * Parse classic PCAP record framing and bounded packet metadata.
 * This is not PCAPNG, a protocol dissector, a capture-integrity verifier or a
 * packet replay engine. Payload bytes are intentionally omitted.
 */
export function parse_pcap(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_pcap requires a Buffer');
  if (options === null || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('PCAP options must be an object');
  const max_packets = options.max_packets ?? 100_000;
  const max_packet_bytes = options.max_packet_bytes ?? 1_048_576;
  const max_total_packet_bytes = options.max_total_packet_bytes ?? 134_217_728;
  if (!Number.isSafeInteger(max_packets) || max_packets < 1 || max_packets > 1_000_000) throw new TypeError('max_packets must be between 1 and 1000000');
  if (!Number.isSafeInteger(max_packet_bytes) || max_packet_bytes < 1 || max_packet_bytes > 16_777_216) throw new TypeError('max_packet_bytes must be between 1 and 16777216');
  if (!Number.isSafeInteger(max_total_packet_bytes) || max_total_packet_bytes < 1 || max_total_packet_bytes > 536_870_912) throw new TypeError('max_total_packet_bytes must be between 1 and 536870912');
  if (buffer.length < 24) invalid('ORIX_PCAP_TRUNCATED_GLOBAL_HEADER', 'PCAP global header is incomplete');
  const magic = buffer.subarray(0, 4).toString('hex');
  const encoding = MAGIC.get(magic);
  if (!encoding) invalid('ORIX_PCAP_BAD_MAGIC', 'Input does not use a supported classic PCAP magic value', { magic });
  const little = encoding.little_endian;
  const major = read_u16(buffer, 4, little, 'version major');
  const minor = read_u16(buffer, 6, little, 'version minor');
  if (major !== 2 || minor !== 4) invalid('ORIX_PCAP_UNSUPPORTED_VERSION', 'Only classic PCAP version 2.4 is supported', { major, minor });
  const snap_length = read_u32(buffer, 16, little, 'snapshot length');
  const network_raw = read_u32(buffer, 20, little, 'link type');
  const link_type = network_raw & 0xffff;
  if (snap_length === 0) invalid('ORIX_PCAP_INVALID_SNAPLEN', 'PCAP snapshot length must be greater than zero');
  const packets = [];
  const protocol_counts = {};
  let cursor = 24;
  let captured_bytes_total = 0;
  while (cursor < buffer.length) {
    if (packets.length >= max_packets) invalid('ORIX_PCAP_PACKET_LIMIT', 'PCAP packet count exceeds configured limit', { max_packets });
    if (buffer.length - cursor < 16) invalid('ORIX_PCAP_TRUNCATED_PACKET_HEADER', 'PCAP packet record header is incomplete', { offset: cursor });
    const seconds = read_u32(buffer, cursor, little, 'packet timestamp seconds');
    const fraction = read_u32(buffer, cursor + 4, little, 'packet timestamp fraction');
    const captured_length = read_u32(buffer, cursor + 8, little, 'captured packet length');
    const original_length = read_u32(buffer, cursor + 12, little, 'original packet length');
    const fraction_limit = encoding.timestamp_resolution === 'microseconds' ? 1_000_000 : 1_000_000_000;
    if (fraction >= fraction_limit) invalid('ORIX_PCAP_INVALID_TIMESTAMP', 'PCAP timestamp fraction exceeds its declared resolution', { packet_index: packets.length, fraction });
    if (captured_length > snap_length || captured_length > max_packet_bytes) invalid('ORIX_PCAP_PACKET_SIZE_LIMIT', 'Captured packet exceeds snapshot or configured packet-size limit', { packet_index: packets.length, captured_length, snap_length, max_packet_bytes });
    if (original_length < captured_length) invalid('ORIX_PCAP_INVALID_PACKET_LENGTH', 'Original packet length is smaller than captured packet length', { packet_index: packets.length, captured_length, original_length });
    const data_offset = cursor + 16;
    if (captured_length > buffer.length - data_offset) invalid('ORIX_PCAP_TRUNCATED_PACKET_DATA', 'PCAP packet data is shorter than its captured length', { packet_index: packets.length, captured_length });
    if (captured_bytes_total + captured_length > max_total_packet_bytes) invalid('ORIX_PCAP_TOTAL_BYTE_LIMIT', 'PCAP captured packet bytes exceed configured aggregate limit', { max_total_packet_bytes });
    const packet_data = buffer.subarray(data_offset, data_offset + captured_length);
    const network = parse_network_metadata(packet_data, 0, link_type);
    const protocol = network.transport?.protocol ?? network.protocol ?? 'other';
    protocol_counts[protocol] = (protocol_counts[protocol] ?? 0) + 1;
    packets.push({
      index: packets.length,
      timestamp_seconds: seconds,
      timestamp_fraction: fraction,
      timestamp_resolution: encoding.timestamp_resolution,
      captured_length,
      original_length,
      capture_truncated: captured_length < original_length,
      network,
    });
    captured_bytes_total += captured_length;
    cursor = data_offset + captured_length;
  }
  return {
    format: 'PCAP',
    capture: {
      version: major + '.' + minor,
      byte_order: little ? 'little-endian' : 'big-endian',
      timestamp_resolution: encoding.timestamp_resolution,
      snap_length,
      link_type,
      link_type_name: LINK_TYPES.get(link_type) ?? 'unknown',
      packet_count: packets.length,
      captured_packet_bytes: captured_bytes_total,
    },
    summary: { protocols: protocol_counts, captured_truncated_packets: packets.filter(packet => packet.capture_truncated).length },
    packets,
    notes: [
      'Classic PCAP 2.4 record metadata only; PCAPNG is handled by the separate bounded PCAPNG parser.',
      'Legacy DLT_RAW (12) and LINKTYPE_RAW (101) are accepted for raw-IP captures.',
      'Packet payload bytes are not returned, decoded, exported or replayed.',
      'IPv4/IPv6 endpoint and TCP/UDP port fields are best-effort metadata, not full protocol dissection.',
      'IPv6 extension headers, IP reassembly, checksum validation and application protocols are not implemented.',
      'Capture timestamps and packet contents are supplied by the capture file and are not independently authenticated.',
    ],
  };
}
