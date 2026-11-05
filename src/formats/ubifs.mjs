// JavaScript, src/formats/ubifs.mjs, Node.js 20+, bounded read-only UBIFS superblock-node analysis.
import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const COMMON_HEADER_SIZE = 24;
const SUPERBLOCK_NODE_SIZE = 4096;
const NODE_MAGIC = 0x06101831;
const SUPERBLOCK_NODE_TYPE = 6;
const DEFAULT_MAX_INPUT = 64 * 1024 * 1024;

const FLAGS = Object.freeze([
  [0x02, 'big_lpt'],
  [0x04, 'space_fixup'],
  [0x08, 'double_hash'],
  [0x10, 'encryption'],
  [0x20, 'authentication'],
]);
const COMPRESSION = Object.freeze({ 0: 'none', 1: 'lzo', 2: 'zlib', 3: 'zstd' });
const MIN_LEB_COUNT = 20;

function reject(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

// Linux UBIFS uses crc32(0xFFFFFFFF, node + 8, node_length - 8).
function ubifs_crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
  }
  return crc >>> 0;
}

function as_safe_number(value, field) {
  if (typeof value === 'string' || !Number.isSafeInteger(value)) {
    reject('ORIX_UBIFS_UNSAFE_INTEGER', 'UBIFS ' + field + ' exceeds the safe integer range', { field, value: String(value) });
  }
  return value;
}

/**
 * Parse one UBIFS superblock node at offset. This is metadata-only: it does not
 * walk master/index/journal nodes, decode LPT structures, or read file payloads.
 */
export function parse_ubifs(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_ubifs requires a Buffer');
  const max_input_bytes = options.max_input_bytes ?? DEFAULT_MAX_INPUT;
  const offset = options.offset ?? 0;
  if (!Number.isSafeInteger(max_input_bytes) || max_input_bytes < SUPERBLOCK_NODE_SIZE || max_input_bytes > DEFAULT_MAX_INPUT) {
    throw new TypeError('max_input_bytes must be an integer between 4096 and ' + DEFAULT_MAX_INPUT);
  }
  if (buffer.length > max_input_bytes) {
    reject('ORIX_UBIFS_INPUT_LIMIT', 'UBIFS input exceeds the configured byte limit', { size: buffer.length, limit: max_input_bytes });
  }
  if (!Number.isSafeInteger(offset) || offset < 0 || offset % 8 !== 0 || offset + COMMON_HEADER_SIZE > buffer.length) {
    throw new TypeError('offset must be a non-negative 8-byte-aligned offset inside the input');
  }

  const reader = new BinaryReader(buffer, { label: 'UBIFS superblock node' });
  const magic = reader.u32(offset, true, 'node magic');
  if (magic !== NODE_MAGIC) {
    reject('ORIX_UBIFS_BAD_MAGIC', 'Input does not begin with a UBIFS node magic value at the selected offset', { offset, magic: '0x' + magic.toString(16).padStart(8, '0') });
  }
  const stored_crc = reader.u32(offset + 4, true, 'node CRC');
  const sequence_number = reader.u64(offset + 8, true, 'node sequence number');
  const node_length = reader.u32(offset + 16, true, 'node length');
  const node_type = reader.u8(offset + 20, 'node type');
  const group_type = reader.u8(offset + 21, 'node group type');
  const common_padding = reader.bytes(offset + 22, 2, 'common header padding');

  if (node_type !== SUPERBLOCK_NODE_TYPE) {
    reject('ORIX_UBIFS_NOT_SUPERBLOCK', 'UBIFS node is not a superblock node', { node_type, expected: SUPERBLOCK_NODE_TYPE });
  }
  if (group_type > 2) reject('ORIX_UBIFS_INVALID_GROUP_TYPE', 'UBIFS node group type is outside the defined range', { group_type });
  if (common_padding.some(byte => byte !== 0)) {
    reject('ORIX_UBIFS_NONZERO_COMMON_PADDING', 'UBIFS common-header reserved padding must be zero', { common_padding: common_padding.toString('hex') });
  }
  if (node_length !== SUPERBLOCK_NODE_SIZE) {
    reject('ORIX_UBIFS_INVALID_NODE_LENGTH', 'UBIFS superblock node must be exactly 4096 bytes', { node_length, expected: SUPERBLOCK_NODE_SIZE });
  }
  if (offset + node_length > buffer.length) {
    reject('ORIX_UBIFS_TRUNCATED_NODE', 'UBIFS superblock node extends beyond the supplied input', { offset, node_length, available: buffer.length - offset });
  }
  const calculated_crc = ubifs_crc32(buffer.subarray(offset + 8, offset + node_length));
  if (stored_crc !== calculated_crc) {
    reject('ORIX_UBIFS_CRC_MISMATCH', 'UBIFS superblock node CRC does not match', { stored_crc, calculated_crc, offset });
  }

  const base = offset + COMMON_HEADER_SIZE;
  const u8 = (relative, field) => reader.u8(base + relative, field);
  const u16 = (relative, field) => reader.u16(base + relative, true, field);
  const u32 = (relative, field) => reader.u32(base + relative, true, field);
  const u64 = (relative, field) => reader.u64(base + relative, true, field);

  const padding = reader.bytes(base, 2, 'superblock padding');
  const key_hash_id = u8(2, 'key hash algorithm');
  const key_format_id = u8(3, 'key format');
  const flags_value = u32(4, 'filesystem flags');
  const min_io_size = u32(8, 'minimum I/O size');
  const leb_size = u32(12, 'logical eraseblock size');
  const leb_count = u32(16, 'logical eraseblock count');
  const max_leb_count = u32(20, 'maximum logical eraseblock count');
  const max_bud_bytes = as_safe_number(u64(24, 'maximum bud bytes'), 'maximum bud bytes');
  const log_lebs = u32(32, 'log LEB count');
  const lpt_lebs = u32(36, 'LPT LEB count');
  const orphan_lebs = u32(40, 'orphan LEB count');
  const journal_head_count = u32(44, 'journal head count');
  const fanout = u32(48, 'index fanout');
  const lsave_count = u32(52, 'LPT save count');
  const format_version = u32(56, 'format version');
  const default_compression_id = u16(60, 'default compression');
  const padding1 = reader.bytes(base + 62, 2, 'superblock padding 1');
  const reserve_pool_uid = u32(64, 'reserve pool UID');
  const reserve_pool_gid = u32(68, 'reserve pool GID');
  const reserve_pool_size = as_safe_number(u64(72, 'reserve pool size'), 'reserve pool size');
  const time_granularity_ns = u32(80, 'time granularity');
  const uuid = reader.bytes(base + 84, 16, 'filesystem UUID').toString('hex');
  const read_only_compat_version = u32(100, 'read-only compatibility version');
  const hmac_present = reader.bytes(base + 104, 64, 'superblock HMAC').some(byte => byte !== 0);
  const hmac_well_known_present = reader.bytes(base + 168, 64, 'well-known-message HMAC').some(byte => byte !== 0);
  const hash_algorithm = u16(232, 'hash algorithm');
  const master_hash_present = reader.bytes(base + 234, 64, 'master-node hash').some(byte => byte !== 0);
  const padding2 = reader.bytes(base + 298, 3774, 'superblock trailing padding');

  if (padding.some(byte => byte !== 0) || padding1.some(byte => byte !== 0) || padding2.some(byte => byte !== 0)) {
    reject('ORIX_UBIFS_NONZERO_SUPERBLOCK_PADDING', 'UBIFS superblock reserved padding contains non-zero bytes');
  }
  if (key_hash_id > 1) reject('ORIX_UBIFS_INVALID_KEY_HASH', 'UBIFS key hash algorithm is not recognized', { key_hash_id });
  if (key_format_id !== 0) reject('ORIX_UBIFS_INVALID_KEY_FORMAT', 'Only the UBIFS simple key format is supported', { key_format_id });
  const known_flags = FLAGS.reduce((mask, [bit]) => mask | bit, 0);
  if (min_io_size < 8 || (min_io_size & (min_io_size - 1)) !== 0) {
    reject('ORIX_UBIFS_INVALID_MIN_IO_SIZE', 'UBIFS minimum I/O size must be a power of two of at least 8 bytes', { min_io_size });
  }
  if (leb_size < 15 * 1024 || leb_size % min_io_size !== 0) {
    reject('ORIX_UBIFS_INVALID_LEB_SIZE', 'UBIFS LEB size must be at least 15 KiB and divisible by minimum I/O size', { leb_size, min_io_size });
  }
  if (leb_count < MIN_LEB_COUNT || max_leb_count < leb_count) {
    reject('ORIX_UBIFS_INVALID_LEB_COUNT', 'UBIFS LEB counts are below the media minimum or maximum is smaller than current count', { leb_count, max_leb_count, minimum: MIN_LEB_COUNT });
  }
  if (log_lebs < 2 || lpt_lebs < 2 || orphan_lebs < 1 || journal_head_count < 1 || fanout < 3) {
    reject('ORIX_UBIFS_INVALID_LAYOUT_COUNTS', 'UBIFS log/LPT/orphan/journal/fanout values are below format minimums', { log_lebs, lpt_lebs, orphan_lebs, journal_head_count, fanout });
  }
  if (format_version < 4 || format_version > 5) {
    reject('ORIX_UBIFS_UNSUPPORTED_FORMAT_VERSION', 'UBIFS format version is outside the supported on-flash versions 4 through 5', { format_version });
  }
  if (!Object.hasOwn(COMPRESSION, default_compression_id)) {
    reject('ORIX_UBIFS_UNKNOWN_COMPRESSION', 'UBIFS default compression identifier is not recognized', { default_compression_id });
  }
  if (time_granularity_ns === 0 || time_granularity_ns > 1_000_000_000) {
    reject('ORIX_UBIFS_INVALID_TIME_GRANULARITY', 'UBIFS time granularity must be between 1 and 1,000,000,000 nanoseconds', { time_granularity_ns });
  }

  const enabled_flags = FLAGS.filter(([bit]) => (flags_value & bit) !== 0).map(([, name]) => name);
  return {
    format: 'UBIFS',
    variant: 'superblock-node',
    analysis_scope: 'single-superblock-node-metadata-only',
    node: {
      magic: '0x06101831',
      offset,
      length: node_length,
      type: node_type,
      type_name: 'superblock',
      group_type,
      sequence_number: String(sequence_number),
      stored_crc,
      calculated_crc,
      crc_valid: true,
    },
    superblock: {
      key_hash: key_hash_id === 0 ? 'r5' : 'test',
      key_hash_id,
      key_format: 'simple',
      key_format_id,
      flags: { value: flags_value, enabled: enabled_flags, unknown_bits: (flags_value & ~known_flags) >>> 0 },
      min_io_size,
      leb_size,
      leb_count,
      max_leb_count,
      max_bud_bytes,
      log_lebs,
      lpt_lebs,
      orphan_lebs,
      journal_head_count,
      fanout,
      lsave_count,
      format_version,
      default_compression: COMPRESSION[default_compression_id],
      default_compression_id,
      reserve_pool_uid,
      reserve_pool_gid,
      reserve_pool_size,
      time_granularity_ns,
      uuid,
      read_only_compat_version,
      authentication: {
        hmac_present,
        well_known_message_hmac_present: hmac_well_known_present,
        hash_algorithm,
        master_hash_present,
      },
    },
    validation: {
      common_header_valid: true,
      superblock_node_type_valid: true,
      node_length_valid: true,
      node_crc_valid: true,
      reserved_padding_zero: true,
      geometry_and_layout_fields_plausible: true,
      hmac_verified: false,
      master_hash_verified: false,
      volume_contents_scanned: false,
    },
    limitations: [
      'Only one UBIFS superblock node is decoded; master nodes, index trees, journal, LPT and orphan structures are not traversed.',
      'HMAC, well-known-message HMAC and master-node hash are inventoried but not cryptographically verified.',
      'No file inode, directory entry, data node or payload is decoded or decompressed.',
      'No file is extracted, written, mounted or executed; UBI volume geometry is not inferred.',
      'A valid superblock CRC does not establish filesystem-wide integrity or authenticity.',
    ],
  };
}
