// JavaScript, src/formats/gzip.mjs, Node.js 20+, bounded GZIP member parser and CPIO wrapper triage.
import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';
import { parse_cpio } from './cpio.mjs';
import { detect_format } from './registry.mjs';

const DEFAULTS = Object.freeze({
  max_input_bytes: 128 * 1024 * 1024,
  max_members: 64,
  max_header_bytes: 64 * 1024,
  max_header_field_bytes: 4096,
  max_member_output_bytes: 32 * 1024 * 1024,
  max_total_output_bytes: 64 * 1024 * 1024,
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

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function find_terminator(buffer, offset, maximum, label) {
  const end = Math.min(buffer.length, offset + maximum);
  for (let index = offset; index < end; index += 1) {
    if (buffer[index] === 0) return index + 1;
  }
  invalid('ORIX_GZIP_HEADER_FIELD_LIMIT', 'GZIP ' + label + ' field has no NUL terminator within the configured limit', { offset, maximum, available: buffer.length - offset });
}

export function parse_gzip(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_gzip requires a Buffer');
  const limits = limits_for(options);
  if (buffer.length > limits.max_input_bytes) invalid('ORIX_GZIP_INPUT_LIMIT', 'GZIP input exceeds the configured byte limit', { size: buffer.length, limit: limits.max_input_bytes });
  if (buffer.length < 18 || buffer[0] !== 0x1f || buffer[1] !== 0x8b) invalid('ORIX_GZIP_BAD_MAGIC', 'GZIP input must begin with the two-byte gzip signature', { size: buffer.length });
  const reader = new BinaryReader(buffer, { label: 'GZIP stream' });
  const members = [];
  const outputs = [];
  let offset = 0;
  let total_output_bytes = 0;
  let trailing_bytes = 0;
  while (offset < buffer.length) {
    if (offset + 2 > buffer.length || buffer[offset] !== 0x1f || buffer[offset + 1] !== 0x8b) {
      trailing_bytes = buffer.length - offset;
      break;
    }
    if (members.length >= limits.max_members) invalid('ORIX_GZIP_MEMBER_LIMIT', 'GZIP stream exceeds the configured member count', { limit: limits.max_members });
    const member_start = offset;
    reader.require(offset, 10, 'GZIP fixed header');
    const method = reader.u8(offset + 2, 'GZIP compression method');
    const flags = reader.u8(offset + 3, 'GZIP flags');
    if (method !== 8) invalid('ORIX_GZIP_UNSUPPORTED_METHOD', 'GZIP member uses an unsupported compression method', { offset, method });
    if ((flags & 0xe0) !== 0) invalid('ORIX_GZIP_RESERVED_FLAGS', 'GZIP member sets reserved flag bits', { offset, flags });
    const mtime = reader.u32(offset + 4, true, 'GZIP modification time');
    const xfl = reader.u8(offset + 8, 'GZIP extra flags');
    const os = reader.u8(offset + 9, 'GZIP operating system');
    offset += 10;
    let extra_bytes = 0;
    if (flags & 0x04) {
      reader.require(offset, 2, 'GZIP extra length');
      extra_bytes = reader.u16(offset, true, 'GZIP extra length');
      offset += 2;
      reader.require(offset, extra_bytes, 'GZIP extra data');
      offset += extra_bytes;
    }
    const filename_present = (flags & 0x08) !== 0;
    if (filename_present) offset = find_terminator(buffer, offset, limits.max_header_field_bytes, 'filename');
    const comment_present = (flags & 0x10) !== 0;
    if (comment_present) offset = find_terminator(buffer, offset, limits.max_header_field_bytes, 'comment');
    const header_crc_present = (flags & 0x02) !== 0;
    if (header_crc_present) {
      reader.require(offset, 2, 'GZIP header CRC16');
      const expected_header_crc = reader.u16(offset, true, 'GZIP header CRC16');
      const actual_header_crc = crc32(buffer.subarray(member_start, offset)) & 0xffff;
      if (actual_header_crc !== expected_header_crc) invalid('ORIX_GZIP_HEADER_CRC_MISMATCH', 'GZIP optional header CRC16 does not match', { offset, expected: expected_header_crc, actual: actual_header_crc });
      offset += 2;
    }
    const header_bytes = offset - member_start;
    if (header_bytes > limits.max_header_bytes) invalid('ORIX_GZIP_HEADER_LIMIT', 'GZIP member header exceeds the configured byte limit', { header_bytes, limit: limits.max_header_bytes });
    const remaining_output = limits.max_total_output_bytes - total_output_bytes;
    if (remaining_output < 1) invalid('ORIX_GZIP_TOTAL_OUTPUT_LIMIT', 'GZIP stream exceeds the configured aggregate decompressed byte limit', { total_output_bytes, limit: limits.max_total_output_bytes });
    const member_output_limit = Math.min(limits.max_member_output_bytes, remaining_output);
    let inflated;
    try {
      inflated = inflateRawSync(buffer.subarray(offset), { maxOutputLength: member_output_limit, info: true });
    } catch (error) {
      const code = error.code === 'ERR_BUFFER_TOO_LARGE' ? 'ORIX_GZIP_OUTPUT_LIMIT' : 'ORIX_GZIP_DEFLATE_INVALID';
      invalid(code, 'GZIP deflate payload could not be decompressed within the configured limits', { offset, cause_code: error.code ?? null });
    }
    const payload = inflated.buffer;
    const compressed_bytes = inflated.engine.bytesWritten;
    if (!Number.isSafeInteger(compressed_bytes) || compressed_bytes < 1) invalid('ORIX_GZIP_DEFLATE_EMPTY', 'GZIP deflate stream consumed no compressed bytes', { offset, compressed_bytes });
    offset += compressed_bytes;
    reader.require(offset, 8, 'GZIP trailer');
    const expected_crc = reader.u32(offset, true, 'GZIP data CRC32');
    const expected_size = reader.u32(offset + 4, true, 'GZIP uncompressed size');
    const actual_crc = crc32(payload);
    const actual_size = payload.length >>> 0;
    if (actual_crc !== expected_crc) invalid('ORIX_GZIP_DATA_CRC_MISMATCH', 'GZIP member data CRC32 does not match its trailer', { member: members.length, expected: expected_crc, actual: actual_crc });
    if (actual_size !== expected_size) invalid('ORIX_GZIP_SIZE_MISMATCH', 'GZIP member uncompressed size does not match its trailer', { member: members.length, expected: expected_size, actual: actual_size });
    offset += 8;
    total_output_bytes += payload.length;
    outputs.push(payload);
    members.push({
      index: members.length,
      mtime,
      xfl,
      os,
      flags: { text: (flags & 0x01) !== 0, header_crc: header_crc_present, extra: (flags & 0x04) !== 0, filename: filename_present, comment: comment_present },
      extra_bytes,
      header_bytes,
      compressed_bytes,
      decompressed_bytes: payload.length,
      crc32: { expected: expected_crc, actual: actual_crc, verified: true },
      isize: { expected: expected_size, actual: actual_size, verified: true },
    });
  }
  const output = Buffer.concat(outputs, total_output_bytes);
  const detection = detect_format(output);
  let nested = null;
  let nested_parser_status = 'not-supported';
  let nested_parser_error = null;
  if (detection.format === 'CPIO newc') {
    try {
      nested = parse_cpio(output, options.cpio_options ?? {});
      nested_parser_status = 'parsed';
    } catch (error) {
      nested_parser_status = 'rejected';
      nested_parser_error = { code: error.code ?? 'ORIX_CPIO_ERROR', message: error.message };
    }
  }
  return {
    format: 'GZIP',
    members,
    summary: {
      members: members.length,
      compressed_bytes: buffer.length - trailing_bytes,
      decompressed_bytes: total_output_bytes,
      trailing_bytes,
    },
    complete: members.length > 0 && trailing_bytes === 0,
    decompressed_sha256: createHash('sha256').update(output).digest('hex'),
    nested_format: detection.format,
    nested_parser_status,
    nested_parser_error,
    nested,
    limits,
    limitations: [
      'GZIP members are decompressed in memory under strict input, member, header and aggregate output ceilings; files are never extracted.',
      'Only DEFLATE method 8 is supported. Header CRC16, member CRC32 and ISIZE are validated when present or required by the format.',
      'Optional filename/comment values and extra-field contents are not retained; only presence and bounded extra-field length are reported.',
      'Only an immediately detected CPIO newc payload receives nested structural parsing; other decompressed formats are identified but not recursively analyzed.',
      'Trailing bytes after the last complete member are reported and make the stream incomplete.',
    ],
  };
}
