// JavaScript, src/formats/tar.mjs, Node.js 20+, bounded USTAR/PAX archive metadata parser.
import path from 'node:path';
import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const BLOCK_BYTES = 512;
const DEFAULTS = Object.freeze({
  max_input_bytes: 128 * 1024 * 1024,
  max_entries: 100000,
  max_name_bytes: 4096,
  max_link_bytes: 4096,
  max_entry_bytes: 32 * 1024 * 1024,
  max_total_data_bytes: 64 * 1024 * 1024,
  max_pax_bytes: 1024 * 1024,
  max_pax_records: 10000,
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

function align_block(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - (BLOCK_BYTES - 1)) {
    invalid('ORIX_TAR_OFFSET_OVERFLOW', 'TAR alignment offset exceeds safe integer bounds', { value });
  }
  return Math.ceil(value / BLOCK_BYTES) * BLOCK_BYTES;
}

function read_text(buffer, offset, length) {
  const raw = buffer.subarray(offset, offset + length);
  const zero = raw.indexOf(0);
  const bytes = zero < 0 ? raw : raw.subarray(0, zero);
  const text = bytes.toString('utf8');
  return { text, encoding_valid: Buffer.from(text, 'utf8').equals(bytes) };
}

function parse_octal_field(buffer, offset, length, label) {
  const raw = buffer.toString('ascii', offset, offset + length).replace(/\0.*$/s, '').trim();
  if (!raw) return 0;
  if (!/^[0-7]+$/.test(raw)) invalid('ORIX_TAR_BAD_OCTAL_FIELD', 'TAR numeric field is not valid octal', { offset, field: label, value: raw });
  const value = Number.parseInt(raw, 8);
  if (!Number.isSafeInteger(value)) invalid('ORIX_TAR_NUMERIC_OVERFLOW', 'TAR numeric field exceeds safe integer bounds', { offset, field: label });
  return value;
}

function parse_number_field(buffer, offset, length, label) {
  const first = buffer[offset];
  if (first & 0x80) {
    if (first & 0x40) invalid('ORIX_TAR_NEGATIVE_NUMBER', 'Negative base-256 TAR numeric fields are not supported', { offset, field: label });
    let value = first & 0x7f;
    for (let index = 1; index < length; index += 1) {
      value = value * 256 + buffer[offset + index];
      if (!Number.isSafeInteger(value)) invalid('ORIX_TAR_NUMERIC_OVERFLOW', 'Base-256 TAR numeric field exceeds safe integer bounds', { offset, field: label });
    }
    return value;
  }
  return parse_octal_field(buffer, offset, length, label);
}

function checksum_header(buffer, offset) {
  let unsigned = 0;
  let signed = 0;
  for (let index = 0; index < BLOCK_BYTES; index += 1) {
    const value = index >= 148 && index < 156 ? 32 : buffer[offset + index];
    unsigned += value;
    signed += value > 127 ? value - 256 : value;
  }
  return { unsigned, signed };
}

function path_safety(name, encoding_valid = true) {
  if (!encoding_valid) return { safe: false, reason: 'non-utf8-name' };
  const slash_name = name.replace(/\\/g, '/');
  const segments = slash_name.split('/');
  const normalized = path.posix.normalize(slash_name);
  if (name.startsWith('/') || name.startsWith('\\') || /^[a-zA-Z]:/.test(name) || segments.includes('..') || normalized === '..' || normalized.startsWith('../')) {
    return { safe: false, reason: 'path-traversal-or-absolute' };
  }
  if (!name || name.includes('\0')) return { safe: false, reason: 'empty-or-nul-path' };
  return { safe: true, reason: null };
}

function parse_pax(data, limits) {
  if (data.length > limits.max_pax_bytes) invalid('ORIX_TAR_PAX_LIMIT', 'TAR PAX metadata exceeds the configured byte limit', { size: data.length, limit: limits.max_pax_bytes });
  const values = {};
  let offset = 0;
  let records = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) invalid('ORIX_TAR_PAX_BAD_RECORD', 'PAX record is missing its length separator', { offset });
    const length_text = data.toString('ascii', offset, space);
    if (!/^[0-9]+$/.test(length_text)) invalid('ORIX_TAR_PAX_BAD_LENGTH', 'PAX record length is not decimal', { offset, value: length_text });
    const record_length = Number(length_text);
    if (!Number.isSafeInteger(record_length) || record_length <= space - offset + 2 || record_length > data.length - offset) invalid('ORIX_TAR_PAX_BAD_LENGTH', 'PAX record length is outside its data block', { offset, record_length, available: data.length - offset });
    const record_end = offset + record_length;
    if (data[record_end - 1] !== 10) invalid('ORIX_TAR_PAX_BAD_RECORD', 'PAX record is not newline terminated', { offset, record_length });
    const record = data.toString('utf8', space + 1, record_end - 1);
    const equals = record.indexOf('=');
    if (equals <= 0) invalid('ORIX_TAR_PAX_BAD_RECORD', 'PAX record is missing a key/value separator', { offset });
    const key = record.slice(0, equals);
    const value = record.slice(equals + 1);
    if (key.length > 256 || value.length > limits.max_name_bytes) invalid('ORIX_TAR_PAX_FIELD_LIMIT', 'PAX key or value exceeds the configured limit', { offset, key_length: key.length, value_length: value.length });
    if (['path', 'linkpath', 'uname', 'gname'].includes(key)) values[key] = value;
    else if (['size', 'uid', 'gid'].includes(key)) {
      if (!/^[0-9]+$/.test(value)) invalid('ORIX_TAR_PAX_BAD_NUMBER', 'PAX numeric field is not a non-negative integer', { key });
      const number = Number(value);
      if (!Number.isSafeInteger(number)) invalid('ORIX_TAR_PAX_BAD_NUMBER', 'PAX numeric field exceeds safe integer bounds', { key });
      values[key] = number;
    } else if (key === 'mtime') {
      const number = Number(value);
      if (!Number.isFinite(number) || number < 0) invalid('ORIX_TAR_PAX_BAD_NUMBER', 'PAX mtime is not a non-negative finite number', { key });
      values[key] = number;
    }
    records += 1;
    if (records > limits.max_pax_records) invalid('ORIX_TAR_PAX_RECORD_LIMIT', 'PAX header exceeds the configured record count', { limit: limits.max_pax_records });
    offset = record_end;
  }
  return { values, records };
}

function tar_type(flag) {
  switch (flag) {
    case '\0':
    case '0': return 'regular';
    case '1': return 'hardlink';
    case '2': return 'symlink';
    case '3': return 'character-device';
    case '4': return 'block-device';
    case '5': return 'directory';
    case '6': return 'fifo';
    case '7': return 'contiguous';
    case 'x': return 'pax-local-header';
    case 'g': return 'pax-global-header';
    case 'L': return 'gnu-long-name';
    case 'K': return 'gnu-long-link';
    case 'S': return 'gnu-sparse-unsupported';
    default: return 'unknown';
  }
}

function long_value(data, label, limit) {
  if (data.length > limit) invalid('ORIX_TAR_LONG_FIELD_LIMIT', 'GNU TAR ' + label + ' exceeds the configured limit', { size: data.length, limit });
  let end = data.indexOf(0);
  if (end < 0) end = data.indexOf(10);
  if (end < 0) end = data.length;
  const bytes = data.subarray(0, end);
  const value = bytes.toString('utf8');
  if (!Buffer.from(value, 'utf8').equals(bytes)) invalid('ORIX_TAR_BAD_LONG_FIELD_ENCODING', 'GNU TAR long field is not valid UTF-8', { label });
  return value;
}

export function parse_tar(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_tar requires a Buffer');
  const limits = limits_for(options);
  if (buffer.length > limits.max_input_bytes) invalid('ORIX_TAR_INPUT_LIMIT', 'TAR input exceeds the configured byte limit', { size: buffer.length, limit: limits.max_input_bytes });
  if (buffer.length < BLOCK_BYTES) invalid('ORIX_TAR_HEADER_TRUNCATED', 'TAR input is shorter than one header block', { size: buffer.length });
  const reader = new BinaryReader(buffer, { label: 'TAR USTAR archive' });
  const entries = [];
  const duplicates = [];
  const unsafe_entries = [];
  const known = new Set();
  let offset = 0;
  let total_data_bytes = 0;
  let metadata_headers = 0;
  let trailer_found = false;
  let trailing_bytes = 0;
  let global_pax = {};
  let pending_pax = {};
  let pending_long_name = null;
  let pending_long_link = null;
  while (offset < buffer.length) {
    if (buffer.length - offset < BLOCK_BYTES) invalid('ORIX_TAR_HEADER_TRUNCATED', 'TAR archive ends in a partial header block', { offset, available: buffer.length - offset });
    const header = reader.bytes(offset, BLOCK_BYTES, 'TAR header block');
    if (header.every(byte => byte === 0)) {
      if (buffer.length - offset < BLOCK_BYTES * 2) {
        trailing_bytes = buffer.length - offset;
        break;
      }
      const second = reader.bytes(offset + BLOCK_BYTES, BLOCK_BYTES, 'TAR end marker');
      if (!second.every(byte => byte === 0)) invalid('ORIX_TAR_BAD_END_MARKER', 'TAR zero header is not followed by a second zero end block', { offset });
      trailer_found = true;
      trailing_bytes = buffer.length - (offset + BLOCK_BYTES * 2);
      offset += BLOCK_BYTES * 2;
      break;
    }
    const magic = reader.ascii(offset + 257, 6, 'USTAR magic');
    const version = reader.ascii(offset + 263, 2, 'USTAR version');
    if (!['ustar\0', 'ustar '].includes(magic) || !['00', ' \0'].includes(version)) invalid('ORIX_TAR_UNSUPPORTED_HEADER', 'TAR header is not a supported USTAR header', { offset, magic, version });
    const expected_checksum = parse_octal_field(buffer, offset + 148, 8, 'checksum');
    const actual_checksum = checksum_header(buffer, offset);
    if (expected_checksum !== actual_checksum.unsigned && expected_checksum !== actual_checksum.signed) invalid('ORIX_TAR_CHECKSUM_MISMATCH', 'TAR header checksum does not match', { offset, expected: expected_checksum, unsigned: actual_checksum.unsigned, signed: actual_checksum.signed });
    const name_field = read_text(buffer, offset, 100);
    const prefix_field = read_text(buffer, offset + 345, 155);
    const raw_name = prefix_field.text ? prefix_field.text + '/' + name_field.text : name_field.text;
    const name_encoding_valid = name_field.encoding_valid && prefix_field.encoding_valid;
    const raw_link = read_text(buffer, offset + 157, 100);
    const raw_size = parse_number_field(buffer, offset + 124, 12, 'size');
    const mode = parse_number_field(buffer, offset + 100, 8, 'mode');
    const uid = parse_number_field(buffer, offset + 108, 8, 'uid');
    const gid = parse_number_field(buffer, offset + 116, 8, 'gid');
    const mtime = parse_number_field(buffer, offset + 136, 12, 'mtime');
    const devmajor = parse_number_field(buffer, offset + 329, 8, 'devmajor');
    const devminor = parse_number_field(buffer, offset + 337, 8, 'devminor');
    const flag_byte = reader.u8(offset + 156, 'TAR type flag');
    const flag = flag_byte === 0 ? '\0' : String.fromCharCode(flag_byte);
    const type = tar_type(flag);
    const data_offset = offset + BLOCK_BYTES;
    if (raw_size > limits.max_entry_bytes) invalid('ORIX_TAR_ENTRY_LIMIT', 'TAR header entry exceeds the configured per-entry limit', { name: raw_name, size: raw_size, limit: limits.max_entry_bytes });
    reader.require(data_offset, raw_size, 'TAR entry data');
    const raw_next = align_block(data_offset + raw_size);
    if (raw_next > buffer.length) invalid('ORIX_TAR_ENTRY_PADDING_TRUNCATED', 'TAR entry padding extends beyond the input', { name: raw_name, next_offset: raw_next, size: buffer.length });
    if (type === 'pax-local-header' || type === 'pax-global-header') {
      const pax = parse_pax(buffer.subarray(data_offset, data_offset + raw_size), limits);
      if (type === 'pax-global-header') global_pax = { ...global_pax, ...pax.values };
      else pending_pax = { ...pending_pax, ...pax.values };
      metadata_headers += 1;
      offset = raw_next;
      continue;
    }
    if (type === 'gnu-long-name' || type === 'gnu-long-link') {
      const value = long_value(buffer.subarray(data_offset, data_offset + raw_size), type === 'gnu-long-name' ? 'long name' : 'long link', type === 'gnu-long-name' ? limits.max_name_bytes : limits.max_link_bytes);
      if (type === 'gnu-long-name') pending_long_name = value;
      else pending_long_link = value;
      metadata_headers += 1;
      offset = raw_next;
      continue;
    }
    const pax = { ...global_pax, ...pending_pax };
    const name = pax.path ?? pending_long_name ?? raw_name;
    const link_target = pax.linkpath ?? pending_long_link ?? raw_link.text;
    const name_valid = name === raw_name ? name_encoding_valid : true;
    const link_valid = link_target === raw_link.text ? raw_link.encoding_valid : true;
    const size = pax.size ?? raw_size;
    const effective_uid = pax.uid ?? uid;
    const effective_gid = pax.gid ?? gid;
    const effective_mtime = pax.mtime ?? mtime;
    if (size > limits.max_entry_bytes) invalid('ORIX_TAR_ENTRY_LIMIT', 'TAR effective entry size exceeds the configured per-entry limit', { name, size, limit: limits.max_entry_bytes });
    if (size > limits.max_total_data_bytes - total_data_bytes) invalid('ORIX_TAR_TOTAL_DATA_LIMIT', 'TAR declared file data exceeds the aggregate byte limit', { name, total_data_bytes, size, limit: limits.max_total_data_bytes });
    reader.require(data_offset, size, 'TAR effective entry data');
    const next_offset = align_block(data_offset + size);
    if (next_offset > buffer.length) invalid('ORIX_TAR_ENTRY_PADDING_TRUNCATED', 'TAR effective entry padding extends beyond the input', { name, next_offset, size: buffer.length });
    if (entries.length >= limits.max_entries) invalid('ORIX_TAR_ENTRY_COUNT_LIMIT', 'TAR archive exceeds the configured entry count', { limit: limits.max_entries });
    const safety = path_safety(name, name_valid);
    if (!safety.safe) unsafe_entries.push({ name, reason: safety.reason });
    if (known.has(name)) duplicates.push(name);
    known.add(name);
    entries.push({
      name,
      normalized_path: path.posix.normalize(name.replace(/\\/g, '/')),
      name_encoding_valid: name_valid,
      safe_path: safety.safe,
      unsafe_reason: safety.reason,
      type,
      mode,
      permissions: (mode & 0x0fff).toString(8).padStart(4, '0'),
      uid: effective_uid,
      gid: effective_gid,
      mtime: effective_mtime,
      size_bytes: size,
      link_target,
      link_target_encoding_valid: link_valid,
      device: { major: devmajor, minor: devminor },
      data_offset,
      pax_overrides: Object.keys(pax).length > 0,
    });
    total_data_bytes += size;
    pending_pax = {};
    pending_long_name = null;
    pending_long_link = null;
    offset = next_offset;
  }
  return {
    format: 'TAR USTAR',
    entries,
    duplicates,
    unsafe_entries,
    metadata_headers,
    trailer_found,
    trailing_bytes,
    complete: trailer_found,
    summary: {
      entries: entries.length,
      regular_files: entries.filter(item => item.type === 'regular' || item.type === 'contiguous').length,
      directories: entries.filter(item => item.type === 'directory').length,
      symlinks: entries.filter(item => item.type === 'symlink').length,
      hardlinks: entries.filter(item => item.type === 'hardlink').length,
      total_data_bytes,
      unsafe_paths: unsafe_entries.length,
      duplicate_paths: duplicates.length,
      metadata_headers,
    },
    limits,
    limitations: [
      'The parser inventories USTAR, POSIX PAX and GNU long-name/link metadata; it does not extract, decompress or execute archive contents.',
      'Only USTAR magic/version headers are accepted; legacy V7 tar and vendor-specific headers are not supported.',
      'PAX numeric extensions are bounded and only selected keys are applied; sparse-file extensions and unknown PAX semantics are not reconstructed.',
      'Header checksum accepts unsigned or signed byte-sum variants; archive payload content has no general per-file checksum.',
      'Symlink/hardlink targets, filesystem semantics and device installation state are not resolved.',
    ],
  };
}
