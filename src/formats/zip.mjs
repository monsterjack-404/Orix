// JavaScript, src/formats/zip.mjs, Node.js 20+, bounded ZIP central-directory parser (no extraction).

import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const EOCD = 0x06054b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;
const COMPRESSION = new Map([[0,'stored'],[8,'deflate'],[9,'deflate64'],[12,'bzip2'],[14,'lzma'],[93,'zstandard'],[95,'xpress'],[99,'aes-wrapper']]);

function find_eocd(reader) {
  const minimum_eocd_size = 22;
  if (reader.buffer.length < minimum_eocd_size) throw new OrixError('ORIX_ZIP_EOCD_MISSING', 'ZIP file is too short to contain an end-of-central-directory record', { recoverable: true });
  const maximum_comment = 65_535;
  const start = Math.max(0, reader.buffer.length - minimum_eocd_size - maximum_comment);
  for (let offset = reader.buffer.length - minimum_eocd_size; offset >= start; offset -= 1) {
    if (reader.u32(offset, true, 'EOCD search') !== EOCD) continue;
    const comment_length = reader.u16(offset + 20, true, 'ZIP comment length');
    if (offset + minimum_eocd_size + comment_length === reader.buffer.length) return offset;
  }
  throw new OrixError('ORIX_ZIP_EOCD_MISSING', 'ZIP end-of-central-directory record was not found in the permitted trailing window', { recoverable: true });
}

function decode_name(bytes, utf8) {
  return bytes.toString(utf8 ? 'utf8' : 'latin1');
}

function is_unsafe_archive_path(name) {
  const normalized = name.replaceAll('\\', '/');
  return normalized.startsWith('/') || /^[a-zA-Z]:/.test(normalized) || normalized.split('/').some(segment => segment === '..');
}

export function parse_zip(buffer, options = {}) {
  const reader = new BinaryReader(buffer, { label: 'ZIP archive' });
  const eocd_offset = find_eocd(reader);
  const disk_number = reader.u16(eocd_offset + 4, true, 'ZIP disk number');
  const central_disk = reader.u16(eocd_offset + 6, true, 'ZIP central-directory disk');
  const entries_on_disk = reader.u16(eocd_offset + 8, true, 'ZIP entries on disk');
  const total_entries = reader.u16(eocd_offset + 10, true, 'ZIP total entries');
  const central_size = reader.u32(eocd_offset + 12, true, 'ZIP central-directory size');
  const central_offset = reader.u32(eocd_offset + 16, true, 'ZIP central-directory offset');
  const comment_length = reader.u16(eocd_offset + 20, true, 'ZIP archive comment length');
  if (disk_number !== 0 || central_disk !== 0 || entries_on_disk !== total_entries) {
    throw new OrixError('ORIX_ZIP_MULTIDISK_UNSUPPORTED', 'Multi-disk ZIP archives are not supported by this parser', { details: { disk_number, central_disk, entries_on_disk, total_entries }, recoverable: true });
  }
  if (total_entries === 0xffff || central_size === 0xffffffff || central_offset === 0xffffffff) {
    throw new OrixError('ORIX_ZIP64_UNSUPPORTED', 'ZIP64 sentinel values are present; ZIP64 parsing is not implemented yet', { recoverable: true });
  }
  if (total_entries > (options.max_entries ?? 100_000)) {
    throw new OrixError('ORIX_ZIP_ENTRY_LIMIT', 'ZIP entry count exceeds configured parser limit', { details: { total_entries, max_entries: options.max_entries ?? 100_000 }, recoverable: true });
  }
  if (central_offset > eocd_offset || central_size > eocd_offset - central_offset || central_offset + central_size > eocd_offset) {
    throw new OrixError('ORIX_ZIP_CENTRAL_DIRECTORY_RANGE', 'ZIP central directory lies outside the valid archive range', { details: { central_offset, central_size, eocd_offset }, recoverable: true });
  }

  const entries = [];
  let cursor = central_offset;
  const central_end = central_offset + central_size;
  for (let index = 0; index < total_entries; index += 1) {
    if (cursor > central_end || 46 > central_end - cursor) throw new OrixError('ORIX_ZIP_TRUNCATED_CENTRAL_ENTRY', 'ZIP central-directory entry header is truncated', { details: { index, cursor, central_end }, recoverable: true });
    if (reader.u32(cursor, true, 'central-directory signature') !== CENTRAL) {
      throw new OrixError('ORIX_ZIP_BAD_CENTRAL_SIGNATURE', 'ZIP central-directory entry has an invalid signature', { details: { index, cursor }, recoverable: true });
    }
    const version_made_by = reader.u16(cursor + 4, true, 'version made by');
    const version_needed = reader.u16(cursor + 6, true, 'version needed');
    const flags = reader.u16(cursor + 8, true, 'general-purpose flags');
    const method = reader.u16(cursor + 10, true, 'compression method');
    const crc32 = reader.u32(cursor + 16, true, 'entry CRC32');
    const compressed_size = reader.u32(cursor + 20, true, 'compressed size');
    const uncompressed_size = reader.u32(cursor + 24, true, 'uncompressed size');
    const name_length = reader.u16(cursor + 28, true, 'file-name length');
    const extra_length = reader.u16(cursor + 30, true, 'extra-field length');
    const entry_comment_length = reader.u16(cursor + 32, true, 'entry comment length');
    const disk_start = reader.u16(cursor + 34, true, 'entry disk start');
    const external_attributes = reader.u32(cursor + 38, true, 'external file attributes');
    const local_header_offset = reader.u32(cursor + 42, true, 'local header offset');
    const variable_length = name_length + extra_length + entry_comment_length;
    if (variable_length > central_end - cursor - 46) throw new OrixError('ORIX_ZIP_TRUNCATED_CENTRAL_ENTRY', 'ZIP entry name, extra data or comment extends beyond central directory', { details: { index, variable_length }, recoverable: true });
    const name_bytes = reader.bytes(cursor + 46, name_length, 'ZIP entry name');
    const name = decode_name(name_bytes, Boolean(flags & 0x0800));
    const extra_offset = cursor + 46 + name_length;
    const unix_mode = version_made_by >>> 8 === 3 ? (external_attributes >>> 16) & 0xffff : null;
    const file_type = unix_mode === null ? null : unix_mode & 0xf000;
    const is_symlink = file_type === 0xa000;
    const local_header_valid = local_header_offset <= buffer.length - 30 && reader.u32(local_header_offset, true, 'local header signature') === LOCAL;
    let local_data_range_valid = false;
    if (local_header_valid) {
      const local_name_length = reader.u16(local_header_offset + 26, true, 'local file-name length');
      const local_extra_length = reader.u16(local_header_offset + 28, true, 'local extra-field length');
      const data_offset = local_header_offset + 30 + local_name_length + local_extra_length;
      local_data_range_valid = data_offset <= buffer.length && compressed_size <= buffer.length - data_offset;
    }
    entries.push({
      index, name, unsafe_path: is_unsafe_archive_path(name), is_directory: name.endsWith('/'), is_symlink,
      compression_method: COMPRESSION.get(method) ?? `unknown-${method}`,
      encrypted: Boolean(flags & 0x0001), data_descriptor: Boolean(flags & 0x0008), utf8_name: Boolean(flags & 0x0800),
      crc32: `0x${crc32.toString(16).padStart(8, '0')}`,
      compressed_size, uncompressed_size, compression_ratio: compressed_size === 0 ? null : Number((uncompressed_size / compressed_size).toFixed(4)),
      local_header_offset, local_header_valid, local_data_range_valid, disk_start,
      extra_field_offset: extra_offset, extra_field_length: extra_length,
      unix_mode: unix_mode === null ? null : `0${unix_mode.toString(8)}`,
    });
    cursor += 46 + variable_length;
  }
  if (cursor !== central_end) {
    throw new OrixError('ORIX_ZIP_CENTRAL_DIRECTORY_SIZE_MISMATCH', 'Parsed ZIP entries do not consume the declared central-directory size', { details: { parsed_end: cursor, central_end }, recoverable: true });
  }
  const unsafe_entries = entries.filter(entry => entry.unsafe_path || entry.is_symlink).length;
  const encrypted_entries = entries.filter(entry => entry.encrypted).length;
  return {
    format: 'ZIP',
    archive: { total_entries, central_directory_offset: central_offset, central_directory_size: central_size, eocd_offset, comment_length },
    summary: { directory_entries: entries.filter(entry => entry.is_directory).length, encrypted_entries, unsafe_or_symlink_entries: unsafe_entries },
    entries,
    notes: [
      'Archive entries are indexed from the central directory; ORIX does not extract or decompress archive contents.',
      'ZIP64 and multi-disk archives are rejected explicitly.',
      'Entry CRC values are reported but not recomputed in this metadata-only parser.',
    ],
  };
}
