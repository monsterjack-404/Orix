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


const ZIP64_EOCD = 0x06064b50;
const ZIP64_LOCATOR = 0x07064b50;

function safe_zip64(value, label) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new OrixError('ORIX_ZIP64_OFFSET_TOO_LARGE', label + ' exceeds safe integer precision', { details: { value: String(value) }, recoverable: true });
  }
  return value;
}

function resolve_zip64_directory(reader, eocd_offset, legacy) {
  const has_sentinels = legacy.total_entries === 0xffff || legacy.entries_on_disk === 0xffff ||
    legacy.central_size === 0xffffffff || legacy.central_offset === 0xffffffff;
  const locator_offset = eocd_offset - 20;
  const has_locator = locator_offset >= 0 && reader.u32(locator_offset, true, 'ZIP64 locator probe') === ZIP64_LOCATOR;
  if (!has_sentinels && !has_locator) {
    return { ...legacy, zip64: false };
  }
  if (!has_locator) throw new OrixError('ORIX_ZIP64_LOCATOR_MISSING', 'ZIP64 sentinel values require an end-of-central-directory locator', { recoverable: true });
  const disk_with_record = reader.u32(locator_offset + 4, true, 'ZIP64 locator disk');
  const record_offset = safe_zip64(reader.u64(locator_offset + 8, true, 'ZIP64 EOCD offset'), 'ZIP64 EOCD offset');
  const total_disks = reader.u32(locator_offset + 16, true, 'ZIP64 locator disk count');
  if (disk_with_record !== 0 || total_disks !== 1) {
    throw new OrixError('ORIX_ZIP_MULTIDISK_UNSUPPORTED', 'Multi-disk ZIP64 archives are not supported', { details: { disk_with_record, total_disks }, recoverable: true });
  }
  reader.require(record_offset, 56, 'ZIP64 end-of-central-directory record');
  if (reader.u32(record_offset, true, 'ZIP64 EOCD signature') !== ZIP64_EOCD) {
    throw new OrixError('ORIX_ZIP64_EOCD_BAD_SIGNATURE', 'ZIP64 locator does not point to a ZIP64 end-of-central-directory record', { recoverable: true });
  }
  const record_size = safe_zip64(reader.u64(record_offset + 4, true, 'ZIP64 EOCD record size'), 'ZIP64 EOCD record size');
  if (record_size < 44 || record_size > locator_offset - record_offset - 12) {
    throw new OrixError('ORIX_ZIP64_EOCD_RANGE', 'ZIP64 end-of-central-directory record has an invalid declared size', { details: { record_offset, record_size, locator_offset }, recoverable: true });
  }
  const disk_number = reader.u32(record_offset + 16, true, 'ZIP64 disk number');
  const central_disk = reader.u32(record_offset + 20, true, 'ZIP64 central disk');
  const entries_on_disk = safe_zip64(reader.u64(record_offset + 24, true, 'ZIP64 entries on disk'), 'ZIP64 entries on disk');
  const total_entries = safe_zip64(reader.u64(record_offset + 32, true, 'ZIP64 total entries'), 'ZIP64 total entries');
  const central_size = safe_zip64(reader.u64(record_offset + 40, true, 'ZIP64 central-directory size'), 'ZIP64 central-directory size');
  const central_offset = safe_zip64(reader.u64(record_offset + 48, true, 'ZIP64 central-directory offset'), 'ZIP64 central-directory offset');
  if (disk_number !== 0 || central_disk !== 0 || entries_on_disk !== total_entries) {
    throw new OrixError('ORIX_ZIP_MULTIDISK_UNSUPPORTED', 'Multi-disk ZIP64 directory metadata is not supported', { details: { disk_number, central_disk, entries_on_disk, total_entries }, recoverable: true });
  }
  return { disk_number, central_disk, entries_on_disk, total_entries, central_size, central_offset, zip64: true, zip64_eocd_offset: record_offset };
}

function resolve_zip64_entry(reader, extra_offset, extra_length, raw, index) {
  const needs = raw.uncompressed_size === 0xffffffff || raw.compressed_size === 0xffffffff ||
    raw.local_header_offset === 0xffffffff || raw.disk_start === 0xffff;
  let cursor = extra_offset;
  const end = extra_offset + extra_length;
  let resolved = { ...raw };
  let found = false;
  while (cursor + 4 <= end) {
    const id = reader.u16(cursor, true, 'ZIP extra-field ID');
    const length = reader.u16(cursor + 2, true, 'ZIP extra-field length');
    cursor += 4;
    if (length > end - cursor) throw new OrixError('ORIX_ZIP_BAD_EXTRA_FIELD', 'ZIP extra field extends beyond its declared entry bounds', { details: { index, id, length }, recoverable: true });
    if (id === 0x0001) {
      found = true;
      let at = cursor;
      const field_end = cursor + length;
      const read64 = label => {
        if (8 > field_end - at) throw new OrixError('ORIX_ZIP64_EXTRA_TRUNCATED', 'ZIP64 extra field is missing a required 64-bit value', { details: { index, label }, recoverable: true });
        const value = safe_zip64(reader.u64(at, true, label), label);
        at += 8;
        return value;
      };
      if (raw.uncompressed_size === 0xffffffff) resolved.uncompressed_size = read64('ZIP64 uncompressed size');
      if (raw.compressed_size === 0xffffffff) resolved.compressed_size = read64('ZIP64 compressed size');
      if (raw.local_header_offset === 0xffffffff) resolved.local_header_offset = read64('ZIP64 local-header offset');
      if (raw.disk_start === 0xffff) {
        if (4 > field_end - at) throw new OrixError('ORIX_ZIP64_EXTRA_TRUNCATED', 'ZIP64 extra field is missing the disk-start value', { details: { index }, recoverable: true });
        resolved.disk_start = reader.u32(at, true, 'ZIP64 disk start');
      }
      break;
    }
    cursor += length;
  }
  if (needs && !found) throw new OrixError('ORIX_ZIP64_EXTRA_MISSING', 'ZIP64 sentinel fields require a ZIP64 extended-information extra field', { details: { index }, recoverable: true });
  return resolved;
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
  const directory = resolve_zip64_directory(reader, eocd_offset, { disk_number, central_disk, entries_on_disk, total_entries, central_size, central_offset });
  const resolved_entries = directory.total_entries;
  const resolved_central_size = directory.central_size;
  const resolved_central_offset = directory.central_offset;
  if (resolved_entries > (options.max_entries ?? 100_000)) {
    throw new OrixError('ORIX_ZIP_ENTRY_LIMIT', 'ZIP entry count exceeds configured parser limit', { details: { total_entries, max_entries: options.max_entries ?? 100_000 }, recoverable: true });
  }
  const directory_boundary = directory.zip64 ? directory.zip64_eocd_offset : eocd_offset;
  if (resolved_central_offset > directory_boundary || resolved_central_size > directory_boundary - resolved_central_offset || resolved_central_offset + resolved_central_size > directory_boundary) {
    throw new OrixError('ORIX_ZIP_CENTRAL_DIRECTORY_RANGE', 'ZIP central directory lies outside the valid archive range', { details: { central_offset: resolved_central_offset, central_size: resolved_central_size, eocd_offset }, recoverable: true });
  }

  const entries = [];
  let cursor = resolved_central_offset;
  const central_end = resolved_central_offset + resolved_central_size;
  for (let index = 0; index < resolved_entries; index += 1) {
    if (cursor > central_end || 46 > central_end - cursor) throw new OrixError('ORIX_ZIP_TRUNCATED_CENTRAL_ENTRY', 'ZIP central-directory entry header is truncated', { details: { index, cursor, central_end }, recoverable: true });
    if (reader.u32(cursor, true, 'central-directory signature') !== CENTRAL) {
      throw new OrixError('ORIX_ZIP_BAD_CENTRAL_SIGNATURE', 'ZIP central-directory entry has an invalid signature', { details: { index, cursor }, recoverable: true });
    }
    const version_made_by = reader.u16(cursor + 4, true, 'version made by');
    const version_needed = reader.u16(cursor + 6, true, 'version needed');
    const flags = reader.u16(cursor + 8, true, 'general-purpose flags');
    const method = reader.u16(cursor + 10, true, 'compression method');
    const crc32 = reader.u32(cursor + 16, true, 'entry CRC32');
    const raw_compressed_size = reader.u32(cursor + 20, true, 'compressed size');
    const raw_uncompressed_size = reader.u32(cursor + 24, true, 'uncompressed size');
    const name_length = reader.u16(cursor + 28, true, 'file-name length');
    const extra_length = reader.u16(cursor + 30, true, 'extra-field length');
    const entry_comment_length = reader.u16(cursor + 32, true, 'entry comment length');
    const raw_disk_start = reader.u16(cursor + 34, true, 'entry disk start');
    const external_attributes = reader.u32(cursor + 38, true, 'external file attributes');
    const raw_local_header_offset = reader.u32(cursor + 42, true, 'local header offset');
    const variable_length = name_length + extra_length + entry_comment_length;
    if (variable_length > central_end - cursor - 46) throw new OrixError('ORIX_ZIP_TRUNCATED_CENTRAL_ENTRY', 'ZIP entry name, extra data or comment extends beyond central directory', { details: { index, variable_length }, recoverable: true });
    const name_bytes = reader.bytes(cursor + 46, name_length, 'ZIP entry name');
    const name = decode_name(name_bytes, Boolean(flags & 0x0800));
    const extra_offset = cursor + 46 + name_length;
    const resolved = resolve_zip64_entry(reader, extra_offset, extra_length, { compressed_size: raw_compressed_size, uncompressed_size: raw_uncompressed_size, local_header_offset: raw_local_header_offset, disk_start: raw_disk_start }, index);
    const compressed_size = resolved.compressed_size;
    const uncompressed_size = resolved.uncompressed_size;
    const local_header_offset = resolved.local_header_offset;
    const disk_start = resolved.disk_start;
    if (disk_start !== 0) throw new OrixError('ORIX_ZIP_MULTIDISK_UNSUPPORTED', 'ZIP entry references a non-zero disk', { details: { index, disk_start }, recoverable: true });
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
    archive: { total_entries: resolved_entries, central_directory_offset: resolved_central_offset, central_directory_size: resolved_central_size, eocd_offset, comment_length, zip64: directory.zip64, zip64_eocd_offset: directory.zip64_eocd_offset ?? null },
    summary: { directory_entries: entries.filter(entry => entry.is_directory).length, encrypted_entries, unsafe_or_symlink_entries: unsafe_entries },
    entries,
    notes: [
      'Archive entries are indexed from the central directory; ORIX does not extract or decompress archive contents.',
      'ZIP64 end records and extended per-entry sizes/offsets are decoded with safe-integer checks; multi-disk archives remain unsupported.',
      'Entry CRC values are reported but not recomputed in this metadata-only parser.',
    ],
  };
}
