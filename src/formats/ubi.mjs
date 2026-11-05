// JavaScript, src/formats/ubi.mjs, Node.js 20+, bounded read-only UBI EC/VID header analysis.
import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';

const HEADER_SIZE = 64;
const EC_MAGIC = 'UBI#';
const VID_MAGIC = 'UBI!';
const UBI_VERSION = 1;
const DEFAULT_MAX_INPUT = 256 * 1024 * 1024;

function reject(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

// Linux UBI uses crc32_le(0xFFFFFFFF, bytes, length), without a final XOR.
function ubi_crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return crc >>> 0;
}

function parse_ec(reader, base, image_length) {
  const magic = reader.ascii(base, 4, 'UBI erase-counter magic');
  if (magic !== EC_MAGIC) reject('ORIX_UBI_BAD_EC_MAGIC', 'Physical eraseblock does not begin with a UBI EC header', { base, magic });
  const version = reader.u8(base + 4, 'UBI version');
  const erase_counter = reader.u64(base + 8, false, 'erase counter');
  const vid_hdr_offset = reader.u32(base + 16, false, 'VID header offset');
  const data_offset = reader.u32(base + 20, false, 'data offset');
  const image_seq = reader.u32(base + 24, false, 'image sequence');
  const stored_crc = reader.u32(base + 60, false, 'EC header CRC');
  const calculated_crc = ubi_crc32(reader.bytes(base, 60, 'EC header CRC input'));
  if (version !== UBI_VERSION) reject('ORIX_UBI_UNSUPPORTED_VERSION', 'Unsupported UBI EC header version', { version, supported: UBI_VERSION });
  if (vid_hdr_offset < HEADER_SIZE || data_offset < vid_hdr_offset + HEADER_SIZE || data_offset > image_length) {
    reject('ORIX_UBI_INVALID_OFFSETS', 'UBI EC header offsets are inconsistent or outside the physical eraseblock', { vid_hdr_offset, data_offset, image_length });
  }
  if (stored_crc !== calculated_crc) reject('ORIX_UBI_EC_CRC_MISMATCH', 'UBI EC header CRC does not match', { stored_crc, calculated_crc, base });
  return { version, erase_counter, vid_hdr_offset, data_offset, image_seq, stored_crc, calculated_crc, crc_valid: true };
}

function parse_vid(reader, base) {
  const magic = reader.ascii(base, 4, 'UBI volume-identifier magic');
  if (magic !== VID_MAGIC) return null;
  const version = reader.u8(base + 4, 'VID version');
  const volume_type_id = reader.u8(base + 5, 'volume type');
  const copy_flag = reader.u8(base + 6, 'copy flag');
  const compatibility = reader.u8(base + 7, 'compatibility');
  const volume_id = reader.u32(base + 8, false, 'volume ID');
  const logical_eraseblock = reader.u32(base + 12, false, 'logical eraseblock number');
  const data_size = reader.u32(base + 20, false, 'VID data size');
  const used_ebs = reader.u32(base + 24, false, 'used eraseblocks');
  const data_pad = reader.u32(base + 28, false, 'data padding');
  const data_crc = reader.u32(base + 32, false, 'data CRC');
  const sequence_number = reader.u64(base + 40, false, 'VID sequence number');
  const stored_crc = reader.u32(base + 60, false, 'VID header CRC');
  const calculated_crc = ubi_crc32(reader.bytes(base, 60, 'VID header CRC input'));
  if (version !== UBI_VERSION) reject('ORIX_UBI_UNSUPPORTED_VID_VERSION', 'Unsupported UBI VID header version', { version });
  if (![1, 2].includes(volume_type_id)) reject('ORIX_UBI_INVALID_VOLUME_TYPE', 'UBI volume type must be dynamic (1) or static (2)', { volume_type_id });
  if (copy_flag > 1) reject('ORIX_UBI_INVALID_COPY_FLAG', 'UBI copy flag must be zero or one', { copy_flag });
  if (stored_crc !== calculated_crc) reject('ORIX_UBI_VID_CRC_MISMATCH', 'UBI VID header CRC does not match', { stored_crc, calculated_crc, base });
  return {
    version, volume_type: volume_type_id === 1 ? 'dynamic' : 'static',
    copy_flag, compatibility, volume_id, logical_eraseblock,
    data_size, used_ebs, data_pad, data_crc, sequence_number,
    stored_crc, calculated_crc, crc_valid: true,
  };
}

/**
 * Inspect UBI EC/VID headers. Supply peb_size to scan a complete multi-PEB image.
 * This does not decode volume-table payloads, UBIFS nodes, or filesystem data.
 */
export function parse_ubi(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_ubi requires a Buffer');
  const max_input_bytes = options.max_input_bytes ?? DEFAULT_MAX_INPUT;
  const peb_size = options.peb_size ?? null;
  if (!Number.isSafeInteger(max_input_bytes) || max_input_bytes < HEADER_SIZE || max_input_bytes > DEFAULT_MAX_INPUT) {
    throw new TypeError('max_input_bytes must be an integer between 64 and ' + DEFAULT_MAX_INPUT);
  }
  if (buffer.length > max_input_bytes) reject('ORIX_UBI_INPUT_LIMIT', 'UBI input exceeds the configured byte limit', { size: buffer.length, limit: max_input_bytes });
  if (buffer.length < HEADER_SIZE) reject('ORIX_UBI_TRUNCATED_EC_HEADER', 'UBI EC header requires 64 bytes', { available: buffer.length });
  if (peb_size !== null && (!Number.isSafeInteger(peb_size) || peb_size < HEADER_SIZE * 2 || peb_size > buffer.length || buffer.length % peb_size !== 0)) {
    throw new TypeError('peb_size must be a valid physical eraseblock size that divides the input length');
  }

  const reader = new BinaryReader(buffer, { label: 'UBI image' });
  const first_ec = parse_ec(reader, 0, peb_size ?? buffer.length);
  if (peb_size !== null && first_ec.data_offset >= peb_size) {
    reject('ORIX_UBI_INVALID_DATA_OFFSET', 'UBI data offset must be inside its physical eraseblock', { data_offset: first_ec.data_offset, peb_size });
  }
  if (first_ec.vid_hdr_offset + HEADER_SIZE > (peb_size ?? buffer.length)) {
    reject('ORIX_UBI_TRUNCATED_VID_HEADER', 'UBI VID header location is outside the available physical eraseblock', { vid_hdr_offset: first_ec.vid_hdr_offset });
  }
  const first_vid = parse_vid(reader, first_ec.vid_hdr_offset);
  const peb_records = [];
  let erased_pebs = 0;
  let missing_ec_headers = 0;
  if (peb_size !== null) {
    const peb_count = buffer.length / peb_size;
    if (peb_count > 65536) reject('ORIX_UBI_PEB_LIMIT', 'UBI image exceeds the configured PEB scan ceiling', { peb_count, limit: 65536 });
    for (let index = 0; index < peb_count; index += 1) {
      const base = index * peb_size;
      const is_erased = buffer.subarray(base, base + 4).every(byte => byte === 0xff);
      if (is_erased) { erased_pebs += 1; continue; }
      const magic = reader.ascii(base, 4, 'PEB magic');
      if (magic !== EC_MAGIC) { missing_ec_headers += 1; peb_records.push({ physical_eraseblock: index, status: 'unrecognized-header', magic }); continue; }
      const ec = parse_ec(reader, base, peb_size);
      if (ec.vid_hdr_offset + HEADER_SIZE > peb_size) reject('ORIX_UBI_VID_OFFSET_RANGE', 'VID header exceeds physical eraseblock bounds', { physical_eraseblock: index, vid_hdr_offset: ec.vid_hdr_offset, peb_size });
      const vid = parse_vid(reader, base + ec.vid_hdr_offset);
      peb_records.push({ physical_eraseblock: index, status: 'valid-ec-header', erase_counter: ec.erase_counter, image_seq: ec.image_seq, vid });
    }
  }
  return {
    format: 'UBI',
    variant: 'erase-counter-and-volume-identifier-headers',
    analysis_scope: peb_size === null ? 'first-peb-headers-only' : 'bounded-peb-header-scan',
    geometry: { physical_eraseblock_size: peb_size, image_bytes: buffer.length, physical_eraseblock_count: peb_size === null ? null : buffer.length / peb_size },
    first_peb: { erase_counter_header: first_ec, volume_identifier_header: first_vid },
    scan: peb_size === null ? null : { scanned_pebs: buffer.length / peb_size, erased_pebs, missing_ec_headers, physical_eraseblocks: peb_records },
    validation: {
      first_ec_header_crc_valid: true,
      first_vid_header_crc_valid: first_vid === null ? null : first_vid.crc_valid,
      all_scanned_ec_header_crcs_valid: true,
      volume_table_decoded: false,
      ubifs_nodes_decoded: false,
      payloads_decompressed: false,
    },
    limitations: [
      'Only UBI EC and VID headers are decoded; layout-volume records and volume-table CRCs are not parsed.',
      'UBIFS superblocks, index nodes, journal, data nodes and filesystem trees are not decoded.',
      'No flash geometry is inferred; multi-PEB scanning requires an explicit peb_size.',
      'No payload is decompressed, extracted, written or executed.',
    ],
  };
}
