// JavaScript, src/formats/png.mjs, Node.js 20+, bounded PNG chunk indexer.
import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const COLOR_TYPES = Object.freeze({
  0: 'grayscale',
  2: 'truecolor',
  3: 'indexed-color',
  4: 'grayscale-with-alpha',
  6: 'truecolor-with-alpha',
});
const VALID_DEPTHS = Object.freeze({
  0: [1, 2, 4, 8, 16],
  2: [8, 16],
  3: [1, 2, 4, 8],
  4: [8, 16],
  6: [8, 16],
});
const KNOWN_CRITICAL = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND']);

function fail(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function bounded_limit(value, fallback, label, minimum, maximum) {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new TypeError(label + ' must be an integer between ' + minimum + ' and ' + maximum);
  }
  return resolved;
}

function create_crc_table() {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) !== 0 ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
    }
    table[index] = value >>> 0;
  }
  return table;
}

const CRC_TABLE = create_crc_table();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (let index = 0; index < buffer.length; index += 1) {
    crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buffer[index]) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function parse_ihdr(reader, offset) {
  const width = reader.u32(offset, false, 'PNG image width');
  const height = reader.u32(offset + 4, false, 'PNG image height');
  const bit_depth = reader.u8(offset + 8, 'PNG bit depth');
  const color_type = reader.u8(offset + 9, 'PNG color type');
  const compression_method = reader.u8(offset + 10, 'PNG compression method');
  const filter_method = reader.u8(offset + 11, 'PNG filter method');
  const interlace_method = reader.u8(offset + 12, 'PNG interlace method');

  if (width === 0 || height === 0) {
    fail('ORIX_PNG_INVALID_DIMENSIONS', 'PNG width and height must both be non-zero', { width, height });
  }
  if (!Object.hasOwn(VALID_DEPTHS, color_type)) {
    fail('ORIX_PNG_UNSUPPORTED_COLOR_TYPE', 'PNG uses an unsupported or reserved color type', { color_type });
  }
  if (!VALID_DEPTHS[color_type].includes(bit_depth)) {
    fail('ORIX_PNG_INVALID_BIT_DEPTH', 'PNG bit depth is invalid for its color type', { bit_depth, color_type });
  }
  if (compression_method !== 0) {
    fail('ORIX_PNG_UNSUPPORTED_COMPRESSION', 'PNG uses an unsupported compression method', { compression_method });
  }
  if (filter_method !== 0) {
    fail('ORIX_PNG_UNSUPPORTED_FILTER', 'PNG uses an unsupported filter method', { filter_method });
  }
  if (interlace_method !== 0 && interlace_method !== 1) {
    fail('ORIX_PNG_INVALID_INTERLACE', 'PNG interlace method must be 0 or 1', { interlace_method });
  }

  const pixel_count = BigInt(width) * BigInt(height);
  return {
    width,
    height,
    bit_depth,
    color_type,
    color_type_name: COLOR_TYPES[color_type],
    compression_method,
    filter_method,
    interlace_method,
    interlaced: interlace_method === 1,
    pixel_count: pixel_count <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(pixel_count) : pixel_count.toString(),
  };
}

function validate_palette(length, header) {
  if (length < 3 || length > 768 || length % 3 !== 0) {
    fail('ORIX_PNG_INVALID_PALETTE', 'PNG PLTE length must contain 1 to 256 complete RGB entries', { length });
  }
  if (header.color_type === 0 || header.color_type === 4) {
    fail('ORIX_PNG_FORBIDDEN_PALETTE', 'PNG grayscale images cannot contain a PLTE chunk', { color_type: header.color_type });
  }
  const entries = length / 3;
  if (header.color_type === 3 && entries > 2 ** header.bit_depth) {
    fail('ORIX_PNG_PALETTE_TOO_LARGE', 'PNG indexed-color palette exceeds the bit-depth entry limit', {
      entries,
      bit_depth: header.bit_depth,
    });
  }
  return entries;
}

function validate_transparency(reader, offset, length, header, palette_entries) {
  if (header.color_type === 0 && length !== 2) {
    fail('ORIX_PNG_INVALID_TRNS', 'Grayscale PNG tRNS chunks must contain exactly two bytes', { length });
  }
  if (header.color_type === 2 && length !== 6) {
    fail('ORIX_PNG_INVALID_TRNS', 'Truecolor PNG tRNS chunks must contain exactly six bytes', { length });
  }
  if (header.color_type === 0 || header.color_type === 2) {
    const sample_count = header.color_type === 0 ? 1 : 3;
    const maximum_sample = 2 ** header.bit_depth - 1;
    for (let index = 0; index < sample_count; index += 1) {
      const sample = reader.u16(offset + index * 2, false, 'PNG tRNS sample');
      if (sample > maximum_sample) {
        fail('ORIX_PNG_TRNS_SAMPLE_OUT_OF_RANGE', 'PNG tRNS sample exceeds the image bit-depth range', {
          color_type: header.color_type,
          bit_depth: header.bit_depth,
          sample_index: index,
          sample,
          maximum_sample,
        });
      }
    }
  }
  if (header.color_type === 3 && (length < 1 || length > palette_entries)) {
    fail('ORIX_PNG_INVALID_TRNS', 'Indexed-color PNG tRNS length must be within the palette entry count', {
      length,
      palette_entries,
    });
  }
  if (header.color_type === 4 || header.color_type === 6) {
    fail('ORIX_PNG_FORBIDDEN_TRNS', 'PNG images with an alpha channel cannot contain a tRNS chunk', {
      color_type: header.color_type,
    });
  }
}

function classify_chunk(type) {
  return {
    critical: type.charCodeAt(0) >= 0x41 && type.charCodeAt(0) <= 0x5a,
    ancillary: type.charCodeAt(0) >= 0x61 && type.charCodeAt(0) <= 0x7a,
    safe_to_copy: type.charCodeAt(3) >= 0x61 && type.charCodeAt(3) <= 0x7a,
  };
}

/**
 * Parse PNG container structure without inflating image data or decoding pixels.
 *
 * CRC work, chunk count and individual chunk sizes are bounded. A CRC budget
 * can be lowered by callers; skipped CRCs are reported instead of being
 * represented as successful verification.
 */
export function parse_png(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_png requires a Buffer');
  const reader = new BinaryReader(buffer, { label: 'PNG image' });
  if (buffer.length < PNG_SIGNATURE.length || !buffer.subarray(0, 8).equals(PNG_SIGNATURE)) {
    fail('ORIX_PNG_INVALID_SIGNATURE', 'Input does not begin with the PNG signature');
  }

  const max_chunks = bounded_limit(options.max_chunks, 10_000, 'max_chunks', 1, 1_000_000);
  const max_chunk_bytes = bounded_limit(options.max_chunk_bytes, 64 * 1024 * 1024, 'max_chunk_bytes', 1, 512 * 1024 * 1024);
  const max_crc_bytes = bounded_limit(options.max_crc_bytes, 64 * 1024 * 1024, 'max_crc_bytes', 0, 512 * 1024 * 1024);

  const chunks = [];
  const unsupported_critical_chunks = [];
  const notes = [];
  let header = null;
  let offset = PNG_SIGNATURE.length;
  let idat_seen = false;
  let idat_ended = false;
  let idat_chunk_count = 0;
  let idat_compressed_bytes = 0;
  let palette_entries = 0;
  let palette_seen = false;
  let transparency_seen = false;
  let iend_seen = false;
  let crc_bytes_checked = 0;
  let crc_checked_chunks = 0;
  let crc_skipped_chunks = 0;

  while (offset < buffer.length) {
    if (chunks.length >= max_chunks) {
      fail('ORIX_PNG_CHUNK_LIMIT', 'PNG exceeds the configured chunk-count limit', {
        max_chunks,
        offset,
      });
    }
    reader.require(offset, 8, 'PNG chunk header');

    const length = reader.u32(offset, false, 'PNG chunk length');
    const type = reader.ascii(offset + 4, 4, 'PNG chunk type');
    if (!/^[A-Za-z]{4}$/.test(type)) {
      fail('ORIX_PNG_INVALID_CHUNK_TYPE', 'PNG chunk type must contain four ASCII letters', { type, offset });
    }
    if (type.charCodeAt(2) >= 0x61 && type.charCodeAt(2) <= 0x7a) {
      fail('ORIX_PNG_RESERVED_CHUNK_BIT', 'PNG chunk type uses a lowercase reserved bit', { type, offset });
    }
    if (length > max_chunk_bytes) {
      fail('ORIX_PNG_CHUNK_SIZE_LIMIT', 'PNG chunk exceeds the configured per-chunk byte limit', {
        type,
        length,
        max_chunk_bytes,
      });
    }
    if (length > buffer.length - offset - 12) {
      fail('ORIX_PNG_TRUNCATED_CHUNK', 'PNG chunk data or CRC extends beyond the supplied bytes', {
        type,
        length,
        offset,
        available: buffer.length - offset,
      });
    }

    if (chunks.length === 0 && type !== 'IHDR') {
      fail('ORIX_PNG_IHDR_NOT_FIRST', 'PNG IHDR must be the first chunk', { first_chunk: type });
    }
    if (chunks.length > 0 && type === 'IHDR') {
      fail('ORIX_PNG_DUPLICATE_IHDR', 'PNG must contain exactly one IHDR chunk');
    }

    if (idat_seen && type !== 'IDAT') idat_ended = true;
    if (type === 'IDAT' && idat_ended) {
      fail('ORIX_PNG_NONCONTIGUOUS_IDAT', 'PNG IDAT chunks must form one consecutive sequence', { offset });
    }

    const data_offset = offset + 8;
    const crc_offset = data_offset + length;
    const expected_crc = reader.u32(crc_offset, false, 'PNG chunk CRC');
    const crc_work = length + 4;
    let crc_valid = null;

    if (crc_bytes_checked <= max_crc_bytes - crc_work) {
      const actual_crc = crc32(buffer.subarray(offset + 4, crc_offset));
      crc_bytes_checked += crc_work;
      crc_checked_chunks += 1;
      crc_valid = actual_crc === expected_crc;
      if (!crc_valid) {
        fail('ORIX_PNG_CRC_MISMATCH', 'PNG chunk CRC does not match its type and data bytes', {
          type,
          offset,
          expected_crc,
          actual_crc,
        });
      }
    } else {
      crc_skipped_chunks += 1;
    }

    if (type === 'IHDR') {
      if (length !== 13) {
        fail('ORIX_PNG_INVALID_IHDR_LENGTH', 'PNG IHDR data must be exactly 13 bytes', { length });
      }
      header = parse_ihdr(reader, data_offset);
    } else if (type === 'PLTE') {
      if (!header) fail('ORIX_PNG_MISSING_IHDR', 'PNG PLTE cannot appear before IHDR');
      if (palette_seen) fail('ORIX_PNG_DUPLICATE_PLTE', 'PNG may contain at most one PLTE chunk');
      if (idat_seen) fail('ORIX_PNG_PLTE_AFTER_IDAT', 'PNG PLTE must appear before the IDAT sequence');
      palette_entries = validate_palette(length, header);
      palette_seen = true;
    } else if (type === 'tRNS') {
      if (!header) fail('ORIX_PNG_MISSING_IHDR', 'PNG tRNS cannot appear before IHDR');
      if (transparency_seen) fail('ORIX_PNG_DUPLICATE_TRNS', 'PNG may contain at most one tRNS chunk');
      if (idat_seen) fail('ORIX_PNG_TRNS_AFTER_IDAT', 'PNG tRNS must appear before IDAT');
      if (header.color_type === 3 && !palette_seen) {
        fail('ORIX_PNG_TRNS_BEFORE_PLTE', 'Indexed-color PNG tRNS must follow PLTE');
      }
      validate_transparency(reader, data_offset, length, header, palette_entries);
      transparency_seen = true;
    } else if (type === 'IDAT') {
      if (!header) fail('ORIX_PNG_MISSING_IHDR', 'PNG IDAT cannot appear before IHDR');
      if (header.color_type === 3 && !palette_seen) {
        fail('ORIX_PNG_MISSING_PLTE', 'Indexed-color PNG requires PLTE before IDAT');
      }
      idat_seen = true;
      idat_chunk_count += 1;
      idat_compressed_bytes += length;
    } else if (type === 'IEND') {
      if (length !== 0) fail('ORIX_PNG_INVALID_IEND_LENGTH', 'PNG IEND chunk must have zero data bytes', { length });
      if (!idat_seen) fail('ORIX_PNG_MISSING_IDAT', 'PNG must contain image data before IEND');
      iend_seen = true;
    }

    const classification = classify_chunk(type);
    if (classification.critical && !KNOWN_CRITICAL.has(type)) unsupported_critical_chunks.push(type);
    chunks.push({
      index: chunks.length,
      type,
      length,
      offset,
      data_offset,
      crc_offset,
      expected_crc,
      crc_valid,
      ...classification,
    });

    offset += length + 12;
    if (type === 'IEND') {
      if (offset !== buffer.length) {
        fail('ORIX_PNG_TRAILING_DATA', 'PNG contains bytes after its IEND chunk', {
          trailing_bytes: buffer.length - offset,
        });
      }
      break;
    }
  }

  if (!header) fail('ORIX_PNG_MISSING_IHDR', 'PNG is missing its required IHDR chunk');
  if (!idat_seen) fail('ORIX_PNG_MISSING_IDAT', 'PNG is missing its required IDAT sequence');
  if (header.color_type === 3 && !palette_seen) {
    fail('ORIX_PNG_MISSING_PLTE', 'Indexed-color PNG requires a PLTE chunk');
  }
  if (!iend_seen) fail('ORIX_PNG_MISSING_IEND', 'PNG is missing its required IEND chunk');

  if (crc_skipped_chunks > 0) {
    notes.push('CRC verification was skipped for ' + crc_skipped_chunks + ' chunk(s) after the configured CRC byte budget was reached.');
  }
  if (unsupported_critical_chunks.length > 0) {
    notes.push('Unknown critical chunks are indexed but not semantically decoded: ' + [...new Set(unsupported_critical_chunks)].join(', ') + '.');
  }

  return {
    format: 'PNG',
    header,
    chunks,
    summary: {
      chunk_count: chunks.length,
      idat_chunk_count,
      idat_compressed_bytes,
      palette_entries,
      crc_checked_chunks,
      crc_skipped_chunks,
      crc_bytes_checked,
      crc_validation_complete: crc_skipped_chunks === 0,
      unsupported_critical_chunks: [...new Set(unsupported_critical_chunks)],
    },
    coverage: {
      chunk_boundaries_validated: true,
      required_ordering_validated: true,
      crc_validation_complete: crc_skipped_chunks === 0,
      image_data_inflated: false,
      scanlines_decoded: false,
      pixel_semantics_validated: false,
    },
    notes,
  };
}
