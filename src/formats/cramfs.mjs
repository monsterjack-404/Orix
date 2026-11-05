// JavaScript, src/formats/cramfs.mjs, Node.js 20+, bounded read-only cramfs superblock analysis.
import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const SUPERBLOCK_SIZE = 76;
const MAGIC_LE = 0x28cd3d45;
const MAGIC_BE = 0x28cd3d45;
const DEFAULT_MAX_INPUT = 128 * 1024 * 1024;
const FLAGS = Object.freeze([
  [0x0001, 'fsid_version_2'], [0x0002, 'sorted_directories'],
  [0x0004, 'holes'], [0x0008, 'wrong_signature'],
  [0x0010, 'shifted_root_offset'], [0x0020, 'extended_block_pointers'],
]);

function reject(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

/**
 * Parse cramfs superblock and embedded root inode only.
 * This parser never decompresses blocks, traverses directories, extracts files or executes content.
 */
export function parse_cramfs(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_cramfs requires a Buffer');
  const max_input_bytes = options.max_input_bytes ?? DEFAULT_MAX_INPUT;
  if (!Number.isSafeInteger(max_input_bytes) || max_input_bytes < SUPERBLOCK_SIZE || max_input_bytes > DEFAULT_MAX_INPUT) {
    throw new TypeError('max_input_bytes must be an integer between 76 and ' + DEFAULT_MAX_INPUT);
  }
  if (buffer.length > max_input_bytes) reject('ORIX_CRAMFS_INPUT_LIMIT', 'cramfs input exceeds the configured byte limit', { size: buffer.length, limit: max_input_bytes });
  if (buffer.length < SUPERBLOCK_SIZE) reject('ORIX_CRAMFS_TRUNCATED_SUPERBLOCK', 'cramfs superblock and root inode require 76 bytes', { available: buffer.length, required: SUPERBLOCK_SIZE });

  const magic_bytes = buffer.subarray(0, 4).toString('hex');
  const reader = new BinaryReader(buffer, { label: 'cramfs image' });
  const raw_le = reader.u32(0, true, 'magic');
  const raw_be = reader.u32(0, false, 'magic');
  let little_endian;
  if (raw_le === MAGIC_LE) little_endian = true;
  else if (raw_be === MAGIC_BE) little_endian = false;
  else reject('ORIX_CRAMFS_BAD_MAGIC', 'Input does not have a recognized cramfs magic value', { magic_bytes });

  const u32 = (offset, field) => reader.u32(offset, little_endian, field);
  const u16 = (offset, field) => reader.u16(offset, little_endian, field);
  const declared_size = u32(4, 'filesystem size');
  const flags_value = u32(8, 'flags');
  const future = u32(12, 'future field');
  const signature = reader.ascii(16, 16, 'filesystem signature').replace(/\0+$/u, '');
  const crc = u32(32, 'filesystem CRC');
  const edition = u32(36, 'edition');
  const block_count = u32(40, 'block count');
  const file_count = u32(44, 'file count');
  const name = reader.ascii(48, 16, 'filesystem name').replace(/\0+$/u, '');

  if (signature !== 'Compressed ROMFS') {
    reject('ORIX_CRAMFS_BAD_SIGNATURE', 'cramfs signature field is not Compressed ROMFS', { signature });
  }
  if (declared_size < SUPERBLOCK_SIZE || declared_size > buffer.length) {
    reject('ORIX_CRAMFS_SIZE_RANGE', 'cramfs declared size must cover the superblock and fit in the supplied input', { declared_size, available: buffer.length });
  }
  if (block_count > Math.ceil(declared_size / 4096)) {
    reject('ORIX_CRAMFS_BLOCK_COUNT_RANGE', 'cramfs block count is implausible for the declared filesystem size', { block_count, declared_size });
  }

  // cramfs inode is 12 bytes: mode/uid, 24-bit size + gid, 6-bit name length + 26-bit word offset.
  const root_mode = u16(64, 'root inode mode');
  const root_uid = u16(66, 'root inode uid');
  const size_gid = u32(68, 'root inode size and gid');
  const name_offset = u32(72, 'root inode name length and offset');
  const root_size = size_gid & 0x00ffffff;
  const root_gid = size_gid >>> 24;
  const root_name_words = name_offset & 0x3f;
  const root_data_offset = (name_offset >>> 6) * 4;
  const root_file_type = root_mode & 0xf000;
  const known_flags = FLAGS.reduce((mask, [bit]) => mask | bit, 0);
  const enabled_flags = FLAGS.filter(([bit]) => (flags_value & bit) !== 0).map(([, label]) => label);

  if (root_file_type !== 0x4000) {
    reject('ORIX_CRAMFS_ROOT_NOT_DIRECTORY', 'cramfs root inode is not marked as a directory', { mode: root_mode, file_type: root_file_type });
  }
  if (root_data_offset >= declared_size && root_data_offset !== 0) {
    reject('ORIX_CRAMFS_ROOT_OFFSET_RANGE', 'cramfs root inode data offset is outside the declared filesystem', { root_data_offset, declared_size });
  }

  return {
    format: 'cramfs',
    variant: 'classic-cramfs-superblock',
    analysis_scope: 'superblock-and-root-inode-only',
    byte_order: little_endian ? 'little-endian' : 'big-endian',
    superblock: {
      magic_bytes, declared_size, input_bytes: buffer.length,
      flags: { value: flags_value, enabled: enabled_flags, unknown_bits: flags_value & ~known_flags },
      future, signature, crc, edition, block_count, file_count, name,
    },
    root_inode: {
      mode: root_mode, uid: root_uid, gid: root_gid, size: root_size,
      name_length_words: root_name_words, data_offset: root_data_offset,
      file_type: root_file_type === 0x4000 ? 'directory' : 'unknown',
      offset_in_declared_filesystem: root_data_offset === 0 || root_data_offset < declared_size,
    },
    validation: {
      superblock_complete: true,
      signature_valid: true,
      declared_filesystem_within_input: true,
      root_inode_is_directory: true,
      root_data_offset_in_bounds: true,
      compressed_blocks_decoded: false,
      directory_entries_traversed: false,
    },
    limitations: [
      'Only the fixed cramfs superblock and embedded root inode are decoded.',
      'Compressed block pointers, directory entries, file inodes, fragments and payloads are not traversed or decompressed.',
      'No file is extracted, written or executed.',
      'A structurally plausible header is not proof that all filesystem contents are valid or authentic.',
    ],
  };
}
