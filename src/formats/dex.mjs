// JavaScript, src/formats/dex.mjs, Node.js 20+, bounded DEX header parser.
// This module inspects header metadata only; it does not decode bytecode or execute code.

import { OrixError } from '../core/errors.mjs';

const DEX_VERSIONS = new Set(['035', '037', '038', '039', '040']);

function invalid(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function read_u32(buffer, offset, little, label) {
  if (offset < 0 || offset > buffer.length - 4) invalid('ORIX_DEX_TRUNCATED_HEADER', 'DEX header is truncated while reading ' + label, { offset });
  return little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
}

function validate_range(offset, size, file_size, label) {
  if (size === 0) {
    if (offset !== 0) invalid('ORIX_DEX_EMPTY_RANGE_OFFSET', label + ' has an offset but zero size', { offset, size });
    return;
  }
  if (offset < 112 || offset > file_size || size > file_size - offset) {
    invalid('ORIX_DEX_TABLE_RANGE', label + ' lies outside the declared DEX file', { offset, size, file_size });
  }
}

function table(buffer, little, count_offset, item_size, file_size, label) {
  const count = read_u32(buffer, count_offset, little, label + ' count');
  const data_offset = read_u32(buffer, count_offset + 4, little, label + ' offset');
  if (count > 10_000_000) invalid('ORIX_DEX_TABLE_LIMIT', label + ' count exceeds the parser limit', { count });
  const size = count * item_size;
  if (!Number.isSafeInteger(size)) invalid('ORIX_DEX_TABLE_SIZE', label + ' size exceeds safe integer precision', { count, item_size });
  validate_range(data_offset, size, file_size, label);
  return { count, offset: data_offset, byte_size: size, item_size };
}

/**
 * Parse the fixed DEX header and validate declared table ranges.
 * Set header_only=true only when the caller independently knows the complete
 * DEX entry size (for example, from a validated ZIP central-directory record).
 */
export function parse_dex(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_dex requires a Buffer');
  if (options === null || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('DEX options must be an object');
  if (buffer.length < 112) invalid('ORIX_DEX_TRUNCATED_HEADER', 'DEX header must contain at least 112 bytes');
  if (buffer.toString('ascii', 0, 4) !== 'dex\n' || buffer[7] !== 0) invalid('ORIX_DEX_BAD_MAGIC', 'Input does not contain a supported DEX magic value');
  const version = buffer.toString('ascii', 4, 7);
  if (!DEX_VERSIONS.has(version)) invalid('ORIX_DEX_UNSUPPORTED_VERSION', 'DEX version is not in the supported header set', { version });
  const little_tag = buffer.readUInt32LE(40);
  const little = little_tag === 0x12345678 ? true : little_tag === 0x78563412 ? false : null;
  if (little === null) invalid('ORIX_DEX_BAD_ENDIAN_TAG', 'DEX endian tag is invalid', { endian_tag: '0x' + little_tag.toString(16) });
  const checksum = read_u32(buffer, 8, little, 'checksum');
  const signature = buffer.subarray(12, 32).toString('hex');
  const file_size = read_u32(buffer, 32, little, 'file size');
  const header_size = read_u32(buffer, 36, little, 'header size');
  const endian_tag = read_u32(buffer, 40, little, 'endian tag');
  if (header_size !== 112) invalid('ORIX_DEX_BAD_HEADER_SIZE', 'Only the 112-byte DEX header layout is supported', { header_size, version });
  if (file_size < header_size) invalid('ORIX_DEX_BAD_FILE_SIZE', 'DEX declared file size is smaller than its header', { file_size, header_size });
  if (options.header_only === true && (!Number.isSafeInteger(options.declared_size) || options.declared_size < header_size)) {
    throw new TypeError('header_only requires a trusted declared_size of at least 112 bytes');
  }
  if (options.header_only !== true && file_size > buffer.length) invalid('ORIX_DEX_TRUNCATED_FILE', 'DEX declared file size exceeds available input bytes', { file_size, available: buffer.length });
  if (options.declared_size !== undefined && options.declared_size !== file_size) {
    invalid('ORIX_DEX_SIZE_MISMATCH', 'DEX header file size does not match its containing entry size', { header_file_size: file_size, declared_size: options.declared_size });
  }
  const link_size = read_u32(buffer, 44, little, 'link size');
  const link_offset = read_u32(buffer, 48, little, 'link offset');
  const map_offset = read_u32(buffer, 52, little, 'map offset');
  validate_range(link_offset, link_size, file_size, 'link data');
  if (map_offset !== 0 && (map_offset < header_size || map_offset > file_size - 4)) invalid('ORIX_DEX_MAP_RANGE', 'DEX map offset lies outside the declared file', { map_offset, file_size });
  const tables = {
    string_ids: table(buffer, little, 56, 4, file_size, 'string_ids'),
    type_ids: table(buffer, little, 64, 4, file_size, 'type_ids'),
    proto_ids: table(buffer, little, 72, 12, file_size, 'proto_ids'),
    field_ids: table(buffer, little, 80, 8, file_size, 'field_ids'),
    method_ids: table(buffer, little, 88, 8, file_size, 'method_ids'),
    class_defs: table(buffer, little, 96, 32, file_size, 'class_defs'),
  };
  const data_size = read_u32(buffer, 104, little, 'data size');
  const data_offset = read_u32(buffer, 108, little, 'data offset');
  validate_range(data_offset, data_size, file_size, 'data section');
  return {
    format: 'DEX',
    version,
    header: {
      file_size,
      header_size,
      endian_tag: '0x' + endian_tag.toString(16).padStart(8, '0'),
      byte_order: little ? 'little-endian' : 'reverse-endian',
      checksum: '0x' + checksum.toString(16).padStart(8, '0'),
      signature_sha1: signature,
      link: { size: link_size, offset: link_offset },
      map_offset,
      tables,
      data: { size: data_size, offset: data_offset },
    },
    notes: [
      'Fixed DEX header and table-range metadata only; string data, class structures, code items and instructions are not decoded.',
      'DEX checksum and SHA-1 signature fields are reported but are not cryptographically verified.',
      'No DEX bytecode is executed and no decompilation is performed.',
      'DEX 041 container layout and optimized/OAT formats are not supported.',
    ],
  };
}
