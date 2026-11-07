// JavaScript, src/formats/cpio.mjs, Node.js 20+, bounded CPIO newc archive metadata parser.
import path from 'node:path';
import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const HEADER_BYTES = 110;
const DEFAULTS = Object.freeze({
  max_input_bytes: 128 * 1024 * 1024,
  max_entries: 100000,
  max_name_bytes: 4096,
  max_entry_bytes: 32 * 1024 * 1024,
  max_total_data_bytes: 64 * 1024 * 1024,
});

function invalid(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function limits_for(options) {
  const limits = {};
  for (const [key, fallback] of Object.entries(DEFAULTS)) {
    const value = options[key] ?? fallback;
    if (!Number.isSafeInteger(value) || value < 1 || value > fallback) {
      throw new TypeError(key + ' must be a positive integer no greater than ' + fallback);
    }
    limits[key] = value;
  }
  return limits;
}

function align4(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - 3) {
    invalid('ORIX_CPIO_OFFSET_OVERFLOW', 'CPIO alignment offset exceeds safe integer bounds', { value });
  }
  return Math.ceil(value / 4) * 4;
}

function hex32(reader, offset, label) {
  const raw = reader.ascii(offset, 8, label);
  if (!/^[0-9a-fA-F]{8}$/.test(raw)) invalid('ORIX_CPIO_BAD_HEX_FIELD', 'CPIO header field is not eight hexadecimal digits', { offset, field: label, value: raw });
  return Number.parseInt(raw, 16);
}

function entry_type(mode) {
  switch (mode & 0xf000) {
    case 0x8000: return 'regular';
    case 0x4000: return 'directory';
    case 0xa000: return 'symlink';
    case 0x2000: return 'character-device';
    case 0x6000: return 'block-device';
    case 0x1000: return 'fifo';
    case 0xc000: return 'socket';
    default: return 'unknown';
  }
}

function path_safety(name, name_encoding_valid = true) {
  if (!name_encoding_valid) return { safe: false, reason: 'non-utf8-name' };
  const slash_name = name.replace(/\\/g, '/');
  const segments = slash_name.split('/');
  const normalized = path.posix.normalize(slash_name);
  if (name.startsWith('/') || name.startsWith('\\') || /^[a-zA-Z]:/.test(name) || segments.includes('..') || normalized === '..' || normalized.startsWith('../')) {
    return { safe: false, reason: 'path-traversal-or-absolute' };
  }
  if (!name || name.includes('\0')) return { safe: false, reason: 'empty-or-nul-path' };
  return { safe: true, reason: null };
}

function byte_sum(buffer, offset, length) {
  let sum = 0;
  const end = offset + length;
  for (let index = offset; index < end; index += 1) sum = (sum + buffer[index]) >>> 0;
  return sum;
}

export function parse_cpio(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_cpio requires a Buffer');
  const limits = limits_for(options);
  if (buffer.length > limits.max_input_bytes) invalid('ORIX_CPIO_INPUT_LIMIT', 'CPIO input exceeds the configured byte limit', { size: buffer.length, limit: limits.max_input_bytes });
  if (buffer.length < HEADER_BYTES) invalid('ORIX_CPIO_HEADER_TRUNCATED', 'CPIO input is too short to contain a newc header', { size: buffer.length });
  const reader = new BinaryReader(buffer, { label: 'CPIO newc archive' });
  const magic = reader.ascii(0, 6, 'CPIO magic');
  if (magic !== '070701' && magic !== '070702') invalid('ORIX_CPIO_BAD_MAGIC', 'CPIO parser supports only newc (070701) and CRC newc (070702)', { magic });
  const variant = magic === '070702' ? 'newc-crc' : 'newc';
  const entries = [];
  const duplicates = [];
  const unsafe_entries = [];
  const known = new Set();
  let offset = 0;
  let total_data_bytes = 0;
  let regular_files = 0;
  let directories = 0;
  let symlinks = 0;
  let trailer_found = false;
  let trailing_bytes = 0;
  while (offset < buffer.length) {
    if (offset % 4 !== 0) invalid('ORIX_CPIO_HEADER_ALIGNMENT', 'CPIO entry header is not four-byte aligned', { offset });
    reader.require(offset, HEADER_BYTES, 'CPIO newc entry header');
    const entry_magic = reader.ascii(offset, 6, 'CPIO entry magic');
    if (entry_magic !== magic) invalid('ORIX_CPIO_MIXED_VARIANT', 'CPIO archive changes newc variant within one stream', { offset, expected: magic, actual: entry_magic });
    const fields = {
      ino: hex32(reader, offset + 6, 'ino'),
      mode: hex32(reader, offset + 14, 'mode'),
      uid: hex32(reader, offset + 22, 'uid'),
      gid: hex32(reader, offset + 30, 'gid'),
      nlink: hex32(reader, offset + 38, 'nlink'),
      mtime: hex32(reader, offset + 46, 'mtime'),
      filesize: hex32(reader, offset + 54, 'filesize'),
      devmajor: hex32(reader, offset + 62, 'devmajor'),
      devminor: hex32(reader, offset + 70, 'devminor'),
      rdevmajor: hex32(reader, offset + 78, 'rdevmajor'),
      rdevminor: hex32(reader, offset + 86, 'rdevminor'),
      namesize: hex32(reader, offset + 94, 'namesize'),
      check: hex32(reader, offset + 102, 'check'),
    };
    if (fields.namesize < 1 || fields.namesize > limits.max_name_bytes) invalid('ORIX_CPIO_NAME_LIMIT', 'CPIO filename length is outside the configured limit', { offset, namesize: fields.namesize, limit: limits.max_name_bytes });
    const name_offset = offset + HEADER_BYTES;
    reader.require(name_offset, fields.namesize, 'CPIO filename');
    const name_bytes = reader.bytes(name_offset, fields.namesize, 'CPIO filename');
    if (name_bytes[name_bytes.length - 1] !== 0 || name_bytes.subarray(0, -1).includes(0)) invalid('ORIX_CPIO_BAD_NAME_TERMINATOR', 'CPIO filename must contain exactly one trailing NUL byte', { offset, namesize: fields.namesize });
    const raw_name = name_bytes.subarray(0, -1);
    const name = raw_name.toString('utf8');
    const name_encoding_valid = Buffer.from(name, 'utf8').equals(raw_name);
    const data_offset = align4(name_offset + fields.namesize);
    if (fields.filesize > limits.max_entry_bytes) invalid('ORIX_CPIO_ENTRY_LIMIT', 'CPIO entry exceeds the configured per-entry data limit', { name, size: fields.filesize, limit: limits.max_entry_bytes });
    if (fields.filesize > limits.max_total_data_bytes - total_data_bytes) invalid('ORIX_CPIO_TOTAL_DATA_LIMIT', 'CPIO declared file data exceeds the aggregate byte limit', { name, total_data_bytes, size: fields.filesize, limit: limits.max_total_data_bytes });
    reader.require(data_offset, fields.filesize, 'CPIO entry data');
    const next_offset = align4(data_offset + fields.filesize);
    if (next_offset > buffer.length) invalid('ORIX_CPIO_ENTRY_PADDING_TRUNCATED', 'CPIO entry padding extends beyond the input', { name, next_offset, size: buffer.length });
    if (name === 'TRAILER!!!') {
      if (fields.filesize !== 0) invalid('ORIX_CPIO_BAD_TRAILER', 'CPIO trailer entry must not contain file data', { filesize: fields.filesize });
      trailer_found = true;
      trailing_bytes = buffer.length - next_offset;
      offset = next_offset;
      break;
    }
    if (entries.length >= limits.max_entries) invalid('ORIX_CPIO_ENTRY_COUNT_LIMIT', 'CPIO archive exceeds the configured entry count', { limit: limits.max_entries });
    if (variant === 'newc-crc') {
      const actual = byte_sum(buffer, data_offset, fields.filesize);
      if (actual !== fields.check) invalid('ORIX_CPIO_CHECKSUM_MISMATCH', 'CPIO CRC variant entry byte-sum does not match the header check field', { name, expected: fields.check, actual });
    }
    const safety = path_safety(name, name_encoding_valid);
    if (!safety.safe) unsafe_entries.push({ name, reason: safety.reason });
    if (known.has(name)) duplicates.push(name);
    known.add(name);
    const type = entry_type(fields.mode);
    if (type === 'regular') regular_files += 1;
    if (type === 'directory') directories += 1;
    if (type === 'symlink') symlinks += 1;
    entries.push({
      name,
      name_encoding_valid,
      normalized_path: path.posix.normalize(name.replace(/\\/g, '/')),
      safe_path: safety.safe,
      unsafe_reason: safety.reason,
      type,
      mode: fields.mode,
      permissions: (fields.mode & 0x0fff).toString(8).padStart(4, '0'),
      uid: fields.uid,
      gid: fields.gid,
      inode: fields.ino,
      links: fields.nlink,
      hardlink_candidate: type === 'regular' && fields.nlink > 1,
      mtime: fields.mtime,
      size_bytes: fields.filesize,
      device: { major: fields.devmajor, minor: fields.devminor },
      special_device: { major: fields.rdevmajor, minor: fields.rdevminor },
      data_offset,
      checksum: variant === 'newc-crc' ? { expected: fields.check, verified: true } : null,
    });
    total_data_bytes += fields.filesize;
    offset = next_offset;
  }
  return {
    format: 'CPIO newc',
    variant,
    header_bytes: HEADER_BYTES,
    entries,
    duplicates,
    unsafe_entries,
    trailer_found,
    trailing_bytes,
    complete: trailer_found,
    summary: {
      entries: entries.length,
      regular_files,
      directories,
      symlinks,
      total_data_bytes,
      unsafe_paths: unsafe_entries.length,
      duplicate_paths: duplicates.length,
    },
    limits,
    limitations: [
      'The parser inventories raw newc/CRC-newc metadata and file ranges; it does not extract, decompress or execute archive contents.',
      'Concatenated archives and compressed wrappers such as gzip are not decoded; bytes after the first trailer are reported as trailing data.',
      'CRC-newc check fields are verified as the format byte-sum; newc entries have no per-entry content checksum.',
      'Symlink targets, hardlink relationships, filesystem semantics and device installation state are not resolved.',
    ],
  };
}
