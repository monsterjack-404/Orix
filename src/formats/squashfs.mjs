// JavaScript, src/formats/squashfs.mjs, Node.js 20+, bounded read-only SquashFS v4 superblock analysis.
import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const SUPERBLOCK_SIZE = 96;
const U64_SENTINEL = '18446744073709551615';
const DEFAULTS = Object.freeze({ max_input_bytes: 128 * 1024 * 1024 });

const COMPRESSION = Object.freeze({
  1: 'gzip', 2: 'lzma', 3: 'lzo', 4: 'xz', 5: 'lz4', 6: 'zstd',
});
const FLAGS = Object.freeze([
  [0x0001, 'uncompressed_inodes'], [0x0002, 'uncompressed_data'],
  [0x0004, 'check_data'], [0x0008, 'no_fragments'],
  [0x0010, 'always_fragments'], [0x0020, 'duplicates'],
  [0x0040, 'exportable'], [0x0080, 'uncompressed_xattrs'],
  [0x0100, 'no_xattrs'], [0x0200, 'compressor_options'],
  [0x0400, 'no_ids'],
]);

function reject(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}
function as_safe_number(value, field) {
  if (typeof value === 'string' || !Number.isSafeInteger(value)) {
    reject('ORIX_SQUASHFS_UNSAFE_INTEGER', 'SquashFS ' + field + ' exceeds the safe integer range', { field, value: String(value) });
  }
  return value;
}
function table_offset(reader, offset, field, bytes_used, little_endian) {
  const value = reader.u64(offset, little_endian, field);
  if (value === U64_SENTINEL) return { offset: null, present: false, sentinel: true, in_bounds: true };
  const numeric = as_safe_number(value, field);
  if (numeric < SUPERBLOCK_SIZE || numeric >= bytes_used) {
    reject('ORIX_SQUASHFS_TABLE_RANGE', 'SquashFS ' + field + ' points outside the declared filesystem data area', { field, offset: numeric, bytes_used });
  }
  return { offset: numeric, present: true, sentinel: false, in_bounds: true };
}

/**
 * Parse the fixed SquashFS v4 superblock only. Metadata tables are indexed as
 * offsets; no decompression, inode traversal, file extraction or execution occurs.
 */
export function parse_squashfs(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_squashfs requires a Buffer');
  const max_input_bytes = options.max_input_bytes ?? DEFAULTS.max_input_bytes;
  if (!Number.isSafeInteger(max_input_bytes) || max_input_bytes < SUPERBLOCK_SIZE || max_input_bytes > DEFAULTS.max_input_bytes) {
    throw new TypeError('max_input_bytes must be an integer between 96 and ' + DEFAULTS.max_input_bytes);
  }
  if (buffer.length > max_input_bytes) reject('ORIX_SQUASHFS_INPUT_LIMIT', 'SquashFS input exceeds the configured byte limit', { size: buffer.length, limit: max_input_bytes });
  if (buffer.length < SUPERBLOCK_SIZE) reject('ORIX_SQUASHFS_TRUNCATED_SUPERBLOCK', 'SquashFS v4 superblock requires 96 bytes', { available: buffer.length, required: SUPERBLOCK_SIZE });

  const magic = buffer.subarray(0, 4).toString('ascii');
  let little_endian;
  if (magic === 'hsqs') little_endian = true;
  else if (magic === 'sqsh') little_endian = false;
  else reject('ORIX_SQUASHFS_BAD_MAGIC', 'Input does not have a SquashFS superblock signature', { magic });

  const reader = new BinaryReader(buffer, { label: 'SquashFS superblock' });
  const u16 = (offset, field) => reader.u16(offset, little_endian, field);
  const u32 = (offset, field) => reader.u32(offset, little_endian, field);
  const u64 = (offset, field) => reader.u64(offset, little_endian, field);
  const major = u16(28, 'major version');
  const minor = u16(30, 'minor version');
  if (major !== 4 || minor > 0) reject('ORIX_SQUASHFS_UNSUPPORTED_VERSION', 'Only SquashFS version 4.0 superblocks are currently supported', { major, minor });

  const inode_count = u32(4, 'inode count');
  const mkfs_time = u32(8, 'creation time');
  const block_size = u32(12, 'block size');
  const fragment_count = u32(16, 'fragment count');
  const compression_id = u16(20, 'compression ID');
  const block_log = u16(22, 'block log');
  const flags_value = u16(24, 'flags');
  const id_count = u16(26, 'ID count');
  const root_inode_reference = u64(32, 'root inode reference');
  const bytes_used = as_safe_number(u64(40, 'bytes used'), 'bytes used');

  if (inode_count === 0) reject('ORIX_SQUASHFS_INVALID_INODE_COUNT', 'SquashFS inode count must be non-zero', { inode_count });
  if (block_size < 4096 || block_size > 1048576 || (block_size & (block_size - 1)) !== 0) {
    reject('ORIX_SQUASHFS_INVALID_BLOCK_SIZE', 'SquashFS block size must be a power of two from 4096 through 1048576', { block_size });
  }
  const expected_log = Math.log2(block_size);
  if (block_log !== expected_log) reject('ORIX_SQUASHFS_BLOCK_LOG_MISMATCH', 'SquashFS block log does not match block size', { block_size, block_log, expected: expected_log });
  if (bytes_used < SUPERBLOCK_SIZE || bytes_used > buffer.length) {
    reject('ORIX_SQUASHFS_BYTES_USED_RANGE', 'SquashFS bytes_used must cover the superblock and fit inside the supplied input', { bytes_used, available: buffer.length });
  }
  if (id_count === 0 && (flags_value & 0x0400) === 0) {
    reject('ORIX_SQUASHFS_INVALID_ID_COUNT', 'SquashFS ID count is zero without the no_ids flag', { id_count, flags: flags_value });
  }
  if (id_count > 0 && (flags_value & 0x0400) !== 0) {
    reject('ORIX_SQUASHFS_ID_FLAG_MISMATCH', 'SquashFS no_ids flag conflicts with a non-zero ID count', { id_count, flags: flags_value });
  }

  const offsets = {
    id_table: table_offset(reader, 48, 'ID table', bytes_used, little_endian),
    xattr_id_table: table_offset(reader, 56, 'xattr ID table', bytes_used, little_endian),
    inode_table: table_offset(reader, 64, 'inode table', bytes_used, little_endian),
    directory_table: table_offset(reader, 72, 'directory table', bytes_used, little_endian),
    fragment_table: table_offset(reader, 80, 'fragment table', bytes_used, little_endian),
    export_table: table_offset(reader, 88, 'export table', bytes_used, little_endian),
  };
  const present = Object.entries(offsets).filter(([, item]) => item.present).map(([name, item]) => ({ name, offset: item.offset })).sort((a, b) => a.offset - b.offset);
  const duplicate_offsets = [];
  for (let i = 1; i < present.length; i += 1) {
    if (present[i].offset === present[i - 1].offset) duplicate_offsets.push({ offset: present[i].offset, tables: [present[i - 1].name, present[i].name] });
  }
  const known_flags = FLAGS.reduce((mask, [bit]) => mask | bit, 0);
  const enabled_flags = FLAGS.filter(([bit]) => (flags_value & bit) !== 0).map(([, name]) => name);

  return {
    format: 'SquashFS',
    variant: 'v4.0-superblock',
    analysis_scope: 'superblock-and-table-offsets-only',
    byte_order: little_endian ? 'little-endian' : 'big-endian',
    superblock: {
      magic, major, minor, inode_count, creation_time_unix: mkfs_time,
      block_size, block_log, fragment_count, compression_id,
      compression: COMPRESSION[compression_id] ?? 'unknown',
      compression_supported_by_metadata_parser: Object.hasOwn(COMPRESSION, compression_id),
      flags: { value: flags_value, enabled: enabled_flags, unknown_bits: flags_value & ~known_flags },
      id_count, root_inode_reference: String(root_inode_reference),
      bytes_used, input_bytes: buffer.length,
    },
    tables: offsets,
    table_offsets_sorted: present,
    duplicate_table_offsets: duplicate_offsets,
    validation: {
      superblock_complete: true,
      declared_filesystem_within_input: true,
      table_offsets_within_declared_filesystem: true,
      block_size_and_log_consistent: true,
      root_inode_reference_decoded: false,
      metadata_tables_decompressed: false,
    },
    limitations: [
      'Only the fixed SquashFS v4.0 superblock and top-level table offsets are validated.',
      'Metadata table contents, inode records, directory entries and file data are not decoded.',
      'No compression stream is decompressed; no file is extracted or executed.',
      'A structurally plausible superblock is not proof that the complete filesystem is valid or authentic.',
    ],
  };
}
