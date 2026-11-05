// JavaScript, src/formats/tar.mjs, Node.js 20+, bounded read-only USTAR/PAX/GNU TAR metadata analysis.
import path from 'node:path';
import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const BLOCK = 512;
const DEFAULTS = Object.freeze({
  max_input_bytes: 128 * 1024 * 1024,
  max_entries: 100000,
  max_entry_bytes: 64 * 1024 * 1024,
  max_total_data_bytes: 128 * 1024 * 1024,
  max_metadata_bytes: 1024 * 1024,
  max_total_metadata_bytes: 4 * 1024 * 1024,
  max_pax_records: 10000,
  max_name_bytes: 4096,
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

function decode_field(buffer, offset, length) {
  const raw = buffer.subarray(offset, offset + length);
  const end = raw.indexOf(0);
  const bytes = end === -1 ? raw : raw.subarray(0, end);
  const value = bytes.toString('utf8');
  return { value, valid_utf8: Buffer.from(value, 'utf8').equals(bytes) };
}

function parse_number(buffer, offset, length, label) {
  const field = buffer.subarray(offset, offset + length);
  if (field.length !== length) invalid('ORIX_TAR_TRUNCATED_NUMBER', 'TAR numeric field is truncated', { label, offset, length });
  if (field[0] & 0x80) {
    if (field[0] & 0x40) invalid('ORIX_TAR_NEGATIVE_NUMBER', 'Negative base-256 TAR values are not supported for bounded offsets or sizes', { label, offset });
    let value = field[0] & 0x7f;
    for (let i = 1; i < field.length; i += 1) {
      value = value * 256 + field[i];
      if (!Number.isSafeInteger(value)) invalid('ORIX_TAR_NUMBER_RANGE', 'TAR base-256 numeric field exceeds safe integer range', { label, offset });
    }
    return value;
  }
  const text = field.toString('ascii').replace(/\0.*$/s, '').trim();
  if (text === '') return 0;
  if (!/^[0-7]+$/.test(text)) invalid('ORIX_TAR_BAD_OCTAL', 'TAR numeric field is not valid octal or positive base-256', { label, offset, value: text });
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) invalid('ORIX_TAR_NUMBER_RANGE', 'TAR numeric field exceeds safe integer range', { label, offset, value: text });
  return value;
}

function header_checksum(buffer, offset) {
  let unsigned = 0;
  let signed = 0;
  for (let i = 0; i < BLOCK; i += 1) {
    const byte = i >= 148 && i < 156 ? 0x20 : buffer[offset + i];
    unsigned += byte;
    signed += byte > 127 ? byte - 256 : byte;
  }
  const expected = parse_number(buffer, offset + 148, 8, 'checksum');
  if (expected !== unsigned && expected !== signed) {
    invalid('ORIX_TAR_CHECKSUM_MISMATCH', 'TAR header checksum does not match its contents', { offset, expected, unsigned, signed });
  }
  return { expected, actual: unsigned, variant: expected === unsigned ? 'unsigned' : 'signed', verified: true };
}

function path_safety(value, valid_utf8) {
  if (!valid_utf8) return { safe: false, reason: 'non-utf8-path' };
  const normalized_input = value.replace(/\\/g, '/');
  const segments = normalized_input.split('/');
  const normalized = path.posix.normalize(normalized_input);
  if (!value || value.includes('\0')) return { safe: false, reason: 'empty-or-nul-path' };
  if (normalized_input.startsWith('/') || /^[a-zA-Z]:/.test(value) || segments.includes('..') || normalized === '..' || normalized.startsWith('../')) {
    return { safe: false, reason: 'path-traversal-or-absolute' };
  }
  return { safe: true, reason: null };
}

function strict_utf8(bytes, label, offset) {
  const value = bytes.toString('utf8');
  if (!Buffer.from(value, 'utf8').equals(bytes)) invalid('ORIX_TAR_INVALID_UTF8', 'TAR ' + label + ' is not valid UTF-8', { offset });
  return value;
}

function parse_pax_records(payload, limits, prior_count) {
  const records = {};
  let offset = 0;
  let count = 0;
  while (offset < payload.length) {
    if (++count > limits.max_pax_records || prior_count + count > limits.max_pax_records) invalid('ORIX_TAR_PAX_RECORD_LIMIT', 'TAR PAX record count exceeds configured limit', { limit: limits.max_pax_records });
    const space = payload.indexOf(0x20, offset);
    if (space < 0) invalid('ORIX_TAR_BAD_PAX_RECORD', 'TAR PAX record is missing its length separator', { offset });
    const length_text = payload.toString('ascii', offset, space);
    if (!/^[1-9][0-9]*$/.test(length_text)) invalid('ORIX_TAR_BAD_PAX_RECORD', 'TAR PAX record length is invalid', { offset, length_text });
    const length = Number(length_text);
    if (!Number.isSafeInteger(length) || length <= space - offset + 2 || length > payload.length - offset) invalid('ORIX_TAR_BAD_PAX_RECORD', 'TAR PAX record length exceeds its payload bounds', { offset, length, remaining: payload.length - offset });
    const record_end = offset + length;
    if (payload[record_end - 1] !== 0x0a) invalid('ORIX_TAR_BAD_PAX_RECORD', 'TAR PAX record must end with a newline', { offset, length });
    const equals = payload.indexOf(0x3d, space + 1);
    if (equals < 0 || equals >= record_end - 1) invalid('ORIX_TAR_BAD_PAX_RECORD', 'TAR PAX record is missing key/value separator', { offset, length });
    const key = strict_utf8(payload.subarray(space + 1, equals), 'PAX key', offset);
    const value = strict_utf8(payload.subarray(equals + 1, record_end - 1), 'PAX value', offset);
    if (!key || key.includes('\0')) invalid('ORIX_TAR_BAD_PAX_RECORD', 'TAR PAX record key is invalid', { offset });
    records[key] = value;
    offset = record_end;
  }
  return { records, count };
}

function pax_size(value, label) {
  if (value === undefined) return null;
  if (!/^(0|[1-9][0-9]*)$/.test(value)) invalid('ORIX_TAR_BAD_PAX_SIZE', 'TAR PAX size value must be a non-negative integer', { label, value });
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) invalid('ORIX_TAR_BAD_PAX_SIZE', 'TAR PAX size exceeds safe integer range', { label, value });
  return parsed;
}

function all_zero(buffer, offset, length) {
  for (let i = offset; i < offset + length; i += 1) if (buffer[i] !== 0) return false;
  return true;
}

function entry_type(flag) {
  switch (flag) {
    case '\0': case '0': return 'regular';
    case '1': return 'hardlink';
    case '2': return 'symlink';
    case '3': return 'character-device';
    case '4': return 'block-device';
    case '5': return 'directory';
    case '6': return 'fifo';
    case '7': return 'contiguous';
    case 'S': return 'gnu-sparse';
    default: return 'unknown';
  }
}

export function parse_tar(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_tar requires a Buffer');
  const limits = limits_for(options);
  if (buffer.length > limits.max_input_bytes) invalid('ORIX_TAR_INPUT_LIMIT', 'TAR input exceeds configured byte limit', { size: buffer.length, limit: limits.max_input_bytes });
  if (buffer.length < BLOCK) invalid('ORIX_TAR_HEADER_TRUNCATED', 'TAR input is shorter than one 512-byte header', { size: buffer.length });
  const reader = new BinaryReader(buffer, { label: 'TAR archive' });
  const entries = [];
  const unsafe_entries = [];
  const duplicates = [];
  const known = new Set();
  const global_pax = {};
  let local_pax = {};
  let long_name = null;
  let long_link = null;
  let offset = 0;
  let total_data_bytes = 0;
  let total_metadata_bytes = 0;
  let pax_records = 0;
  let extension_headers = 0;
  let zero_blocks = 0;
  let complete = false;
  let trailing_bytes = 0;

  while (offset + BLOCK <= buffer.length) {
    if (all_zero(buffer, offset, BLOCK)) {
      zero_blocks += 1;
      if (zero_blocks >= 2) {
        complete = true;
        offset += BLOCK;
        trailing_bytes = buffer.length - offset;
        break;
      }
      offset += BLOCK;
      continue;
    }
    if (zero_blocks > 0) invalid('ORIX_TAR_BAD_END_MARKER', 'TAR contains a non-zero header after a single end-of-archive zero block', { offset });
    if (entries.length + extension_headers >= limits.max_entries) invalid('ORIX_TAR_ENTRY_COUNT_LIMIT', 'TAR archive exceeds configured entry count', { limit: limits.max_entries });
    reader.require(offset, BLOCK, 'TAR header');
    const checksum = header_checksum(buffer, offset);
    const name_field = decode_field(buffer, offset, 100);
    const mode = parse_number(buffer, offset + 100, 8, 'mode');
    const uid = parse_number(buffer, offset + 108, 8, 'uid');
    const gid = parse_number(buffer, offset + 116, 8, 'gid');
    const header_size = parse_number(buffer, offset + 124, 12, 'size');
    const mtime = parse_number(buffer, offset + 136, 12, 'mtime');
    const typeflag = String.fromCharCode(buffer[offset + 156]);
    const link_field = decode_field(buffer, offset + 157, 100);
    const magic = buffer.toString('ascii', offset + 257, offset + 263);
    if (magic !== 'ustar\0' && magic !== 'ustar ') invalid('ORIX_TAR_UNSUPPORTED_HEADER', 'Only USTAR-compatible headers are supported', { offset, magic });
    const version = buffer.toString('ascii', offset + 263, offset + 265);
    const uname = decode_field(buffer, offset + 265, 32);
    const gname = decode_field(buffer, offset + 297, 32);
    const devmajor = parse_number(buffer, offset + 329, 8, 'devmajor');
    const devminor = parse_number(buffer, offset + 337, 8, 'devminor');
    const prefix_field = decode_field(buffer, offset + 345, 155);
    const header_path = prefix_field.value ? prefix_field.value + '/' + name_field.value : name_field.value;
    const header_path_valid = name_field.valid_utf8 && prefix_field.valid_utf8;
    const data_offset = offset + BLOCK;
    const is_extension = ['x', 'g', 'L', 'K'].includes(typeflag);
    let stored_size = header_size;
    if (is_extension) {
      if (stored_size > limits.max_metadata_bytes || stored_size > limits.max_total_metadata_bytes - total_metadata_bytes) invalid('ORIX_TAR_METADATA_LIMIT', 'TAR extension metadata exceeds configured limits', { offset, size: stored_size, total_metadata_bytes });
    } else {
      const effective_pax = { ...global_pax, ...local_pax };
      stored_size = pax_size(effective_pax.size, 'size') ?? header_size;
      if (stored_size > limits.max_entry_bytes || stored_size > limits.max_total_data_bytes - total_data_bytes) invalid('ORIX_TAR_ENTRY_LIMIT', 'TAR entry exceeds per-entry or aggregate data limits', { offset, size: stored_size, total_data_bytes });
    }
    if (!Number.isSafeInteger(stored_size) || stored_size > buffer.length - data_offset) invalid('ORIX_TAR_ENTRY_RANGE', 'TAR entry data extends beyond archive bounds', { offset, data_offset, size: stored_size, input_size: buffer.length });
    const next_offset = data_offset + Math.ceil(stored_size / BLOCK) * BLOCK;
    if (next_offset > buffer.length) invalid('ORIX_TAR_ENTRY_PADDING_TRUNCATED', 'TAR entry padding extends beyond archive bounds', { offset, next_offset, input_size: buffer.length });

    if (typeflag === 'x' || typeflag === 'g') {
      const payload = buffer.subarray(data_offset, data_offset + stored_size);
      total_metadata_bytes += stored_size;
      const parsed_pax = parse_pax_records(payload, limits, pax_records);
      pax_records += parsed_pax.count;
      if (typeflag === 'g') Object.assign(global_pax, parsed_pax.records);
      else local_pax = { ...local_pax, ...parsed_pax.records };
      extension_headers += 1;
    } else if (typeflag === 'L' || typeflag === 'K') {
      const payload = buffer.subarray(data_offset, data_offset + stored_size);
      total_metadata_bytes += stored_size;
      const end = payload.indexOf(0);
      const raw = end < 0 ? payload : payload.subarray(0, end);
      const decoded = raw.toString('utf8');
      if (!Buffer.from(decoded, 'utf8').equals(raw)) invalid('ORIX_TAR_BAD_GNU_LONGNAME', 'GNU long-name metadata is not valid UTF-8', { offset });
      if (typeflag === 'L') long_name = decoded;
      else long_link = decoded;
      extension_headers += 1;
    } else {
      const effective_pax = { ...global_pax, ...local_pax };
      const path_value = effective_pax.path ?? long_name ?? header_path;
      const link_value = effective_pax.linkpath ?? long_link ?? link_field.value;
      if (Buffer.byteLength(path_value, 'utf8') > limits.max_name_bytes || Buffer.byteLength(link_value, 'utf8') > limits.max_name_bytes) invalid('ORIX_TAR_NAME_LIMIT', 'TAR path or link name exceeds configured byte limit', { offset, path_bytes: Buffer.byteLength(path_value, 'utf8'), link_bytes: Buffer.byteLength(link_value, 'utf8'), limit: limits.max_name_bytes });
      const path_valid = effective_pax.path !== undefined || long_name !== null ? true : header_path_valid;
      const safety = path_safety(path_value, path_valid);
      if (!safety.safe) unsafe_entries.push({ name: path_value, reason: safety.reason });
      if (known.has(path_value)) duplicates.push(path_value);
      known.add(path_value);
      const type = entry_type(typeflag);
      entries.push({
        name: path_value,
        link_name: link_value || null,
        path_encoding_valid: path_valid,
        safe_path: safety.safe,
        unsafe_reason: safety.reason,
        normalized_path: path.posix.normalize(path_value.replace(/\\/g, '/')),
        type,
        typeflag: typeflag === '\0' ? '0' : typeflag,
        mode,
        permissions: (mode & 0o7777).toString(8).padStart(4, '0'),
        uid: pax_size(effective_pax.uid, 'uid') ?? uid,
        gid: pax_size(effective_pax.gid, 'gid') ?? gid,
        uname: effective_pax.uname ?? uname.value,
        gname: effective_pax.gname ?? gname.value,
        mtime: effective_pax.mtime ?? mtime,
        size_bytes: stored_size,
        device: { major: devmajor, minor: devminor },
        header_checksum: checksum,
        header_offset: offset,
        data_offset,
        data_bytes_indexed_only: true,
        sparse_metadata_present: typeflag === 'S' || Object.keys(effective_pax).some(key => key.startsWith('GNU.sparse.')),
      });
      total_data_bytes += stored_size;
      local_pax = {};
      long_name = null;
      long_link = null;
    }
    offset = next_offset;
  }

  if (!complete && offset < buffer.length) trailing_bytes = buffer.length - offset;
  return {
    format: 'TAR',
    variant: 'ustar-compatible',
    entries,
    unsafe_entries,
    duplicates,
    extension_headers,
    pax_records,
    trailer_found: complete,
    complete,
    trailing_bytes,
    summary: {
      entries: entries.length,
      regular_files: entries.filter(entry => entry.type === 'regular').length,
      directories: entries.filter(entry => entry.type === 'directory').length,
      links: entries.filter(entry => entry.type === 'symlink' || entry.type === 'hardlink').length,
      unsafe_paths: unsafe_entries.length,
      duplicate_paths: duplicates.length,
      total_data_bytes,
      total_metadata_bytes,
    },
    limits,
    limitations: [
      'Only USTAR-compatible headers with valid checksums are accepted; legacy V7-only headers are not recognized.',
      'PAX and GNU long-name/link metadata are parsed under strict size and record limits; vendor-specific extensions are retained only as metadata keys when relevant.',
      'Sparse file maps, ACLs, xattrs, device installation semantics and filesystem reconstruction are not implemented.',
      'File payloads are indexed by offset and length only; no files are extracted, decompressed or executed.',
      'A complete archive requires two consecutive zero end blocks; trailing bytes are reported.',
    ],
  };
}
