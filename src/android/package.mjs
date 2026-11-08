// JavaScript, src/android/package.mjs, Node.js 20+, read-only APK/AAB inventory.
// Selected stored/raw-DEFLATE entries are expanded in memory under strict budgets; nothing is extracted to disk.

import { parse_zip } from '../formats/zip.mjs';
import { parse_dex } from '../formats/dex.mjs';
import { parse_android_binary_xml } from './binary-xml.mjs';
import { parse_android_proto_xml } from './proto-xml.mjs';
import { parse_android_bundle_config } from './bundle-config.mjs';
import { parse_android_resource_table } from './resources-table.mjs';
import { constants as fs_constants, promises as fs } from 'node:fs';
import path from 'node:path';
import { hash_buffer } from '../core/hash.mjs';
import { inflateRawSync } from 'node:zlib';

const LOCAL_HEADER = 0x04034b50;
const BINARY_XML = 0x0003;

function is_resource_table_candidate(name) {
  const separator = name.indexOf('/');
  return separator > 0 && separator === name.lastIndexOf('/') &&
    name.slice(separator + 1) === 'resources.pb' &&
    name.slice(0, separator) !== 'BUNDLE-METADATA';
}

function is_aab_resource_table_entry(name) {
  if (!is_resource_table_candidate(name)) return false;
  const module = name.slice(0, name.indexOf('/'));
  return module !== '.' && module !== '..' && !module.includes('\\') && !module.includes(':');
}

function is_dex_entry(name, is_aab) {
  const parts = name.split('/');
  const base = parts.at(-1);
  const canonical_name = base === 'classes.dex' || /^classes(?:[2-9]|[1-9][0-9]+)\.dex$/.test(base);
  if (!canonical_name) return false;
  // APK multidex files live at the archive root; AAB DEX files live in
  // each module's dex/ directory. Do not parse arbitrary asset subdirectories.
  return is_aab
    ? parts.length === 3 && parts[0].length > 0 && parts[1] === 'dex'
    : parts.length === 1;
}

const CRC32_TABLE = Uint32Array.from({ length: 256 }, (_, value) => {
  let crc = value;
  for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  return crc >>> 0;
});

function crc32(buffer) {
  let crc = 0xffffffff;
  for (let index = 0; index < buffer.length; index++) {
    crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ buffer[index]) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function local_entry_data(buffer, entry, max_output_bytes, central_directory_offset) {
  // Selected metadata is never decoded from path-traversing, symlink or
  // directory members. This applies equally to APK and AAB manifests/DEX/config.
  if (entry.unsafe_path) return { status: 'unsafe-path' };
  if (entry.is_symlink) return { status: 'symlink' };
  if (entry.is_directory) return { status: 'not-regular-file' };
  if (!entry.local_header_valid || !entry.local_data_range_valid) return { status: 'invalid-local-range' };
  if (entry.encrypted || entry.strongly_encrypted) return { status: 'encrypted' };
  const method_code = entry.compression_method === 'stored'
    ? 0
    : entry.compression_method === 'deflate' ? 8 : null;
  if (method_code === null) return { status: 'unsupported-compression' };
  if (!Number.isSafeInteger(max_output_bytes) || max_output_bytes < 1 ||
      entry.uncompressed_size > max_output_bytes) return { status: 'output-size-limit' };
  if (entry.compression_method === 'stored' && entry.compressed_size !== entry.uncompressed_size) {
    return { status: 'size-mismatch' };
  }

  const offset = entry.local_header_offset;
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > buffer.length - 30 ||
      offset > central_directory_offset - 30 || buffer.readUInt32LE(offset) !== LOCAL_HEADER) {
    return { status: 'invalid-local-header' };
  }
  const flags = buffer.readUInt16LE(offset + 6);
  const method = buffer.readUInt16LE(offset + 8);
  const local_crc = buffer.readUInt32LE(offset + 14);
  const local_compressed_size = buffer.readUInt32LE(offset + 18);
  const local_uncompressed_size = buffer.readUInt32LE(offset + 22);
  const central_flags = entry.general_purpose_flags;
  const expected_flags = (entry.encrypted ? 1 : 0) |
    (entry.data_descriptor ? 8 : 0) |
    (entry.utf8_name ? 0x0800 : 0);
  const supported_flags = method_code === 8 ? 0x080f : 0x0809;
  const central_crc = Number.parseInt(entry.crc32, 16);
  const descriptor_mismatch = entry.data_descriptor
    ? (local_crc !== 0 && local_crc !== central_crc) ||
      (local_compressed_size !== 0 && local_compressed_size !== entry.compressed_size) ||
      (local_uncompressed_size !== 0 && local_uncompressed_size !== entry.uncompressed_size)
    : local_crc !== central_crc || local_compressed_size !== entry.compressed_size ||
      local_uncompressed_size !== entry.uncompressed_size;
  const name_length = buffer.readUInt16LE(offset + 26);
  const extra_length = buffer.readUInt16LE(offset + 28);
  if (method !== method_code || flags !== central_flags ||
      (flags & ~supported_flags) !== 0 || (flags & 0x0809) !== expected_flags ||
      descriptor_mismatch) return { status: 'local-header-mismatch' };

  const name_start = offset + 30;
  const data_offset = name_start + name_length + extra_length;
  if (name_start > buffer.length - name_length || data_offset > central_directory_offset ||
      entry.compressed_size > central_directory_offset - data_offset) {
    return { status: 'invalid-local-range' };
  }
  const local_name = buffer.subarray(name_start, name_start + name_length)
    .toString((flags & 0x0800) !== 0 ? 'utf8' : 'latin1');
  if (local_name !== entry.name) return { status: 'local-header-mismatch' };

  const compressed = buffer.subarray(data_offset, data_offset + entry.compressed_size);
  let bytes;
  if (method_code === 0) {
    bytes = compressed;
  } else {
    try {
      // The central-directory uncompressed size is the hard output ceiling;
      // dishonest size metadata cannot trigger an unbounded inflate.
      bytes = inflateRawSync(compressed, { maxOutputLength: Math.max(1, entry.uncompressed_size) });
    } catch {
      return { status: 'decompression-failed' };
    }
  }
  if (bytes.length !== entry.uncompressed_size) return { status: 'size-mismatch' };
  if (crc32(bytes) !== central_crc) return { status: 'crc-mismatch' };
  return { status: 'available', bytes };
}
function inspect_manifest(buffer, entry, central_directory_offset, options = {}) {
  const max_bytes = options.max_manifest_bytes ?? 16 * 1024 * 1024;
  if (!Number.isSafeInteger(max_bytes) || max_bytes < 8 || max_bytes > 64 * 1024 * 1024) {
    throw new TypeError('max_manifest_bytes must be between 8 and 67108864');
  }
  if (entry.uncompressed_size > max_bytes) {
    return { path: entry.name, status: 'manifest-size-limit', binary_xml: null, uncompressed_size: entry.uncompressed_size };
  }
  const data = local_entry_data(buffer, entry, max_bytes, central_directory_offset);
  if (data.status !== 'available') return { path: entry.name, status: data.status, binary_xml: null };
  // AAB module manifests are AAPT2 Resources.XmlNode protobuf messages, not
  // Android binary XML chunks. Never attempt to reinterpret malformed proto
  // bytes as an APK binary-XML document.
  if (entry.name.endsWith('/manifest/AndroidManifest.xml')) {
    try {
      const decoded = parse_android_proto_xml(data.bytes, options.proto_xml ?? {});
      return { path: entry.name, status: 'decoded-proto-xml', binary_xml: false, proto_xml: true, ...decoded };
    } catch (error) {
      return {
        path: entry.name,
        status: 'malformed-proto-xml',
        binary_xml: false,
        proto_xml: true,
        decoded: false,
        error: { code: error.code ?? 'ORIX_PROTO_XML_ERROR', message: error.message },
      };
    }
  }
  if (data.bytes.length < 8) return { path: entry.name, status: 'unknown-or-invalid-header', binary_xml: false };
  const type = data.bytes.readUInt16LE(0);
  const header_size = data.bytes.readUInt16LE(2);
  const declared_size = data.bytes.readUInt32LE(4);
  if (type !== BINARY_XML || header_size < 8 || declared_size !== data.bytes.length || declared_size < header_size) {
    return { path: entry.name, status: 'unknown-or-invalid-header', binary_xml: type === BINARY_XML, chunk_type: '0x' + type.toString(16).padStart(4, '0'), header_size, declared_size };
  }
  try {
    const decoded = parse_android_binary_xml(data.bytes, options.binary_xml ?? {});
    return { path: entry.name, status: 'decoded', binary_xml: true, chunk_type: '0x0003', header_size, declared_size, ...decoded };
  } catch (error) {
    return { path: entry.name, status: 'malformed-binary-xml', binary_xml: true, chunk_type: '0x0003', header_size, declared_size, error: { code: error.code ?? 'ORIX_AXML_ERROR', message: error.message } };
  }
}


function inspect_bundle_config(buffer, entries, central_directory_offset, options = {}) {
  const max_bytes = options.max_bundle_config_bytes ?? 4 * 1024 * 1024;
  if (!Number.isSafeInteger(max_bytes) || max_bytes < 1 || max_bytes > 64 * 1024 * 1024) {
    throw new TypeError('max_bundle_config_bytes must be between 1 and 67108864');
  }
  const matches = entries.filter(entry => entry.name === 'BundleConfig.pb');
  if (matches.length === 0) {
    return { status: 'absent', path: null, uncompressed_size: null, config: null };
  }
  if (matches.length > 1) {
    return { status: 'duplicate-path', path: 'BundleConfig.pb', uncompressed_size: null, config: null };
  }
  const entry = matches[0];
  const base = { path: 'BundleConfig.pb', uncompressed_size: entry.uncompressed_size };
  if (entry.uncompressed_size > max_bytes) {
    return { ...base, status: 'size-limit', config: null };
  }
  const data = local_entry_data(buffer, entry, max_bytes, central_directory_offset);
  if (data.status !== 'available') {
    return { ...base, status: data.status, config: null };
  }
  try {
    const config = parse_android_bundle_config(data.bytes, {
      max_file_bytes: max_bytes,
      ...(options.bundle_config ?? {}),
    });
    return { ...base, status: 'decoded', config };
  } catch (error) {
    return {
      ...base,
      status: 'malformed',
      config: null,
      error: { code: error.code ?? 'ORIX_BUNDLE_CONFIG_ERROR', message: error.message },
    };
  }
}


function inspect_resource_tables(buffer, entries, central_directory_offset, options = {}) {
  const max_bytes = options.max_resource_table_bytes ?? 4 * 1024 * 1024;
  const max_total_bytes = options.max_resource_table_total_bytes ?? 64 * 1024 * 1024;
  const max_tables = options.max_resource_tables ?? 256;
  if (!Number.isSafeInteger(max_bytes) || max_bytes < 1 || max_bytes > 64 * 1024 * 1024) {
    throw new TypeError('max_resource_table_bytes must be between 1 and 67108864');
  }
  if (!Number.isSafeInteger(max_total_bytes) || max_total_bytes < 1 || max_total_bytes > 256 * 1024 * 1024) {
    throw new TypeError('max_resource_table_total_bytes must be between 1 and 268435456');
  }
  if (!Number.isSafeInteger(max_tables) || max_tables < 1 || max_tables > 4096) {
    throw new TypeError('max_resource_tables must be between 1 and 4096');
  }
  const matches = entries.filter(entry => is_resource_table_candidate(entry.name));
  const counts = new Map();
  for (const entry of matches) counts.set(entry.name, (counts.get(entry.name) ?? 0) + 1);
  const tables = [];
  let total_bytes_used = 0;
  let omitted = 0;
  for (const entry of matches) {
    if (tables.length >= max_tables) {
      omitted += 1;
      continue;
    }
    const separator = entry.name.indexOf('/');
    const module = entry.name.slice(0, separator);
    const base = { module, path: entry.name, uncompressed_size: entry.uncompressed_size };
    // Module resources must be regular, safe archive members. Parsing happens
    // in memory, but an unsafe path or symlink is not a trustworthy AAB file.
    if (entry.is_symlink) {
      tables.push({ ...base, status: 'symlink', table: null });
      continue;
    }
    if (entry.unsafe_path || module === '.' || module === '..' || module.includes('\\') || module.includes(':')) {
      tables.push({ ...base, status: 'unsafe-path', table: null });
      continue;
    }
    if (entry.is_directory) {
      tables.push({ ...base, status: 'not-regular-file', table: null });
      continue;
    }
    if ((counts.get(entry.name) ?? 0) > 1) {
      tables.push({ ...base, status: 'duplicate-path', table: null });
      continue;
    }
    if (entry.uncompressed_size > max_bytes) {
      tables.push({ ...base, status: 'size-limit', table: null });
      continue;
    }
    if (total_bytes_used + entry.uncompressed_size > max_total_bytes) {
      tables.push({ ...base, status: 'aggregate-size-limit', table: null });
      continue;
    }
    // Reserve declared output before decompression; malformed entries do not
    // receive a fresh aggregate budget on a subsequent path.
    total_bytes_used += entry.uncompressed_size;
    const data = local_entry_data(buffer, entry, max_bytes, central_directory_offset);
    if (data.status !== 'available') {
      tables.push({ ...base, status: data.status, table: null });
      continue;
    }
    try {
      const table = parse_android_resource_table(data.bytes, {
        max_file_bytes: max_bytes,
        ...(options.resource_table ?? {}),
      });
      tables.push({ ...base, status: 'decoded', table });
    } catch (error) {
      tables.push({
        ...base,
        status: 'malformed',
        table: null,
        error: { code: error.code ?? 'ORIX_RESOURCE_TABLE_ERROR', message: error.message },
      });
    }
  }
  return {
    count: matches.length,
    reported: tables.length,
    omitted,
    bytes_used: total_bytes_used,
    tables,
  };
}

const APK_SIGNING_BLOCK_MAGIC = Buffer.from('APK Sig Block 42', 'ascii');
const APK_SIGNING_IDS = new Map([
  [0x7109871a, 'APK Signature Scheme v2'],
  [0xf05368c0, 'APK Signature Scheme v3'],
  [0x1b93ad61, 'APK Signature Scheme v3.1'],
  [0x42726577, 'Verity padding'],
]);

function inspect_apk_signing_block(buffer, central_directory_offset, options = {}) {
  const max_bytes = options.max_signing_block_bytes ?? 64 * 1024 * 1024;
  const max_pairs = options.max_signing_block_pairs ?? 4096;
  if (!Number.isSafeInteger(max_bytes) || max_bytes < 32 || max_bytes > 536_870_912) {
    throw new TypeError('max_signing_block_bytes must be between 32 and 536870912');
  }
  if (!Number.isSafeInteger(max_pairs) || max_pairs < 1 || max_pairs > 65_536) {
    throw new TypeError('max_signing_block_pairs must be between 1 and 65536');
  }
  const absent = { status: 'absent', offset: null, size_bytes: 0, pair_count: 0, schemes: [], unknown_ids: [], duplicate_ids: [] };
  if (!Number.isSafeInteger(central_directory_offset) || central_directory_offset < 24 ||
      central_directory_offset > buffer.length || !buffer.subarray(central_directory_offset - 16, central_directory_offset).equals(APK_SIGNING_BLOCK_MAGIC)) {
    return absent;
  }
  const malformed = (code, message, details = {}) => ({
    ...absent,
    status: 'malformed',
    error: { code, message, ...details },
  });
  try {
    const block_size_big = buffer.readBigUInt64LE(central_directory_offset - 24);
    if (block_size_big < 24n || block_size_big > BigInt(Number.MAX_SAFE_INTEGER)) {
      return malformed('ORIX_APK_SIGNING_BLOCK_SIZE', 'APK signing block declares an invalid or unsafe size');
    }
    const total_size = Number(block_size_big) + 8;
    if (total_size > max_bytes) {
      return malformed('ORIX_APK_SIGNING_BLOCK_LIMIT', 'APK signing block exceeds the configured size limit', { size_bytes: total_size, max_bytes });
    }
    if (total_size > central_directory_offset) {
      return malformed('ORIX_APK_SIGNING_BLOCK_RANGE', 'APK signing block starts before the beginning of the file', { size_bytes: total_size, central_directory_offset });
    }
    const start = central_directory_offset - total_size;
    const header_size = buffer.readBigUInt64LE(start);
    if (header_size !== block_size_big) {
      return malformed('ORIX_APK_SIGNING_BLOCK_SIZE_MISMATCH', 'APK signing block header and footer sizes do not match', {
        header_size: String(header_size), footer_size: String(block_size_big),
      });
    }
    const pairs_end = central_directory_offset - 24;
    let cursor = start + 8;
    const counts = new Map();
    const schemes = [];
    const unknown_ids = [];
    let pair_count = 0;
    while (cursor < pairs_end) {
      if (pair_count >= max_pairs) {
        return malformed('ORIX_APK_SIGNING_BLOCK_PAIR_LIMIT', 'APK signing block pair count exceeds the configured limit', { max_pairs });
      }
      if (pairs_end - cursor < 8) {
        return malformed('ORIX_APK_SIGNING_BLOCK_PAIR_TRUNCATED', 'APK signing block contains a truncated pair length field', { offset: cursor });
      }
      const pair_length_big = buffer.readBigUInt64LE(cursor);
      if (pair_length_big < 4n || pair_length_big > BigInt(Number.MAX_SAFE_INTEGER)) {
        return malformed('ORIX_APK_SIGNING_BLOCK_PAIR_LENGTH', 'APK signing block contains an invalid pair length', { offset: cursor, pair_length: String(pair_length_big) });
      }
      const pair_length = Number(pair_length_big);
      if (pair_length > pairs_end - cursor - 8) {
        return malformed('ORIX_APK_SIGNING_BLOCK_PAIR_RANGE', 'APK signing block pair extends beyond the pair section', { offset: cursor, pair_length });
      }
      const id = buffer.readUInt32LE(cursor + 8);
      const value_size = pair_length - 4;
      const seen = (counts.get(id) ?? 0) + 1;
      counts.set(id, seen);
      const known = APK_SIGNING_IDS.get(id);
      if (known) {
        if (seen === 1) schemes.push({ id: '0x' + id.toString(16).padStart(8, '0'), name: known, value_size });
      } else if (seen === 1) {
        unknown_ids.push('0x' + id.toString(16).padStart(8, '0'));
      }
      pair_count += 1;
      cursor += 8 + pair_length;
    }
    if (cursor !== pairs_end) {
      return malformed('ORIX_APK_SIGNING_BLOCK_PAIR_ALIGNMENT', 'APK signing block pair sequence does not end at its declared boundary', { cursor, pairs_end });
    }
    const duplicate_ids = [...counts].filter(([, count]) => count > 1)
      .map(([id, count]) => ({ id: '0x' + id.toString(16).padStart(8, '0'), count }));
    return {
      status: 'present',
      offset: start,
      size_bytes: total_size,
      pair_count,
      schemes,
      unknown_ids,
      duplicate_ids,
      notes: ['Signing-block container and ID-value pair boundaries were inspected; cryptographic signature, content digest, certificate chain and publisher identity were not verified.'],
    };
  } catch (error) {
    return malformed('ORIX_APK_SIGNING_BLOCK_READ', 'APK signing block could not be read safely', { cause_code: error.code ?? null });
  }
}

function is_v1_signature(name) {
  if (!name.startsWith('META-INF/')) return false;
  const base = name.slice(name.lastIndexOf('/') + 1).toUpperCase();
  return base.endsWith('.RSA') || base.endsWith('.DSA') || base.endsWith('.EC') || base.endsWith('.SF') || base === 'MANIFEST.MF';
}

/**
 * Identify APK/AAB ZIP containers and inventory their structural metadata.
 * Selected stored/raw-DEFLATE DEX and manifest entries are validated and parsed
 * in memory under per-entry and aggregate output budgets.
 */
export function analyze_android_package(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('Android package input must be a Buffer');
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Android package options must be an object');
  const max_file_bytes = options.max_file_bytes ?? 536_870_912;
  if (!Number.isSafeInteger(max_file_bytes) || max_file_bytes < 1 || max_file_bytes > 1_073_741_824) {
    throw new TypeError('max_file_bytes must be between 1 and 1073741824');
  }
  if (buffer.length > max_file_bytes) throw new RangeError('Android package exceeds the configured file-size limit');
  const max_dex_entries = options.max_dex_entries ?? 64;
  const max_dex_entry_bytes = options.max_dex_entry_bytes ?? 134_217_728;
  const max_dex_total_bytes = options.max_dex_total_bytes ?? 268_435_456;
  const max_manifest_bytes = options.max_manifest_bytes ?? 16 * 1024 * 1024;
  const max_manifest_total_bytes = options.max_manifest_total_bytes ?? 64 * 1024 * 1024;
  const max_dex_output_items = options.max_dex_output_items ?? 1000;
  const max_archive_entries = options.max_archive_entries ?? 1000;
  const max_archive_entry_path_length = options.max_archive_entry_path_length ?? 512;
  const max_signing_block_bytes = options.max_signing_block_bytes ?? 64 * 1024 * 1024;
  const max_signing_block_pairs = options.max_signing_block_pairs ?? 4096;
  const max_aab_modules = options.max_aab_modules ?? 256;
  const max_bundle_config_bytes = options.max_bundle_config_bytes ?? 4 * 1024 * 1024;
  const max_resource_table_bytes = options.max_resource_table_bytes ?? 4 * 1024 * 1024;
  const max_resource_table_total_bytes = options.max_resource_table_total_bytes ?? 64 * 1024 * 1024;
  const max_resource_tables = options.max_resource_tables ?? 256;
  if (!Number.isSafeInteger(max_dex_entries) || max_dex_entries < 1 || max_dex_entries > 256) throw new TypeError('max_dex_entries must be between 1 and 256');
  if (!Number.isSafeInteger(max_dex_entry_bytes) || max_dex_entry_bytes < 112 || max_dex_entry_bytes > 536_870_912) throw new TypeError('max_dex_entry_bytes must be between 112 and 536870912');
  if (!Number.isSafeInteger(max_dex_total_bytes) || max_dex_total_bytes < 112 || max_dex_total_bytes > 1_073_741_824) throw new TypeError('max_dex_total_bytes must be between 112 and 1073741824');
  if (!Number.isSafeInteger(max_manifest_bytes) || max_manifest_bytes < 8 || max_manifest_bytes > 67_108_864) throw new TypeError('max_manifest_bytes must be between 8 and 67108864');
  if (!Number.isSafeInteger(max_manifest_total_bytes) || max_manifest_total_bytes < 8 || max_manifest_total_bytes > 536_870_912) throw new TypeError('max_manifest_total_bytes must be between 8 and 536870912');
  if (!Number.isSafeInteger(max_dex_output_items) || max_dex_output_items < 1 || max_dex_output_items > 10_000) throw new TypeError('max_dex_output_items must be between 1 and 10000');
  if (!Number.isSafeInteger(max_archive_entries) || max_archive_entries < 1 || max_archive_entries > 50_000) throw new TypeError('max_archive_entries must be between 1 and 50000');
  if (!Number.isSafeInteger(max_archive_entry_path_length) || max_archive_entry_path_length < 16 || max_archive_entry_path_length > 4096) throw new TypeError('max_archive_entry_path_length must be between 16 and 4096');
  if (!Number.isSafeInteger(max_signing_block_bytes) || max_signing_block_bytes < 32 || max_signing_block_bytes > 536_870_912) throw new TypeError('max_signing_block_bytes must be between 32 and 536870912');
  if (!Number.isSafeInteger(max_signing_block_pairs) || max_signing_block_pairs < 1 || max_signing_block_pairs > 65_536) throw new TypeError('max_signing_block_pairs must be between 1 and 65536');
  if (!Number.isSafeInteger(max_aab_modules) || max_aab_modules < 1 || max_aab_modules > 4096) throw new TypeError('max_aab_modules must be between 1 and 4096');
  if (!Number.isSafeInteger(max_bundle_config_bytes) || max_bundle_config_bytes < 1 || max_bundle_config_bytes > 64 * 1024 * 1024) throw new TypeError('max_bundle_config_bytes must be between 1 and 67108864');
  if (!Number.isSafeInteger(max_resource_table_bytes) || max_resource_table_bytes < 1 || max_resource_table_bytes > 64 * 1024 * 1024) throw new TypeError('max_resource_table_bytes must be between 1 and 67108864');
  if (!Number.isSafeInteger(max_resource_table_total_bytes) || max_resource_table_total_bytes < 1 || max_resource_table_total_bytes > 256 * 1024 * 1024) throw new TypeError('max_resource_table_total_bytes must be between 1 and 268435456');
  if (!Number.isSafeInteger(max_resource_tables) || max_resource_tables < 1 || max_resource_tables > 4096) throw new TypeError('max_resource_tables must be between 1 and 4096');
  const archive = parse_zip(buffer, options.zip ?? {});
  const entries = archive.entries.filter(entry => !entry.unsafe_path && !entry.is_symlink);
  const entry_name_counts = new Map();
  for (const entry of entries) entry_name_counts.set(entry.name, (entry_name_counts.get(entry.name) ?? 0) + 1);
  const duplicate_path_names = [...entry_name_counts].filter(([, count]) => count > 1);
  const duplicate_path_entries = duplicate_path_names.reduce((total, [, count]) => total + count - 1, 0);
  const archive_entries = entries.slice(0, max_archive_entries).map(entry => ({
    path: entry.name.slice(0, max_archive_entry_path_length),
    path_truncated: entry.name.length > max_archive_entry_path_length,
    path_original_length: entry.name.length,
    kind: entry.is_directory ? 'directory' : 'file',
    compression_method: entry.compression_method,
    encrypted: entry.encrypted,
    compressed_size: entry.compressed_size,
    uncompressed_size: entry.uncompressed_size,
    crc32: entry.crc32,
    local_header_valid: entry.local_header_valid,
    local_data_range_valid: entry.local_data_range_valid,
    unix_mode: entry.unix_mode,
  }));
  const names = new Set(entries.map(entry => entry.name));
  const apk_manifest = names.has('AndroidManifest.xml');
  const bundle_manifest = entries.some(entry => entry.name.endsWith('/manifest/AndroidManifest.xml'));
  const is_aab = names.has('BundleConfig.pb') || bundle_manifest ||
    entries.some(entry => is_aab_resource_table_entry(entry.name));
  const is_apk = apk_manifest && !is_aab;
  const dex_entries = entries.filter(entry => is_dex_entry(entry.name, is_aab));
  const manifest_entries = entries.filter(entry => entry.name === 'AndroidManifest.xml' || entry.name.endsWith('/manifest/AndroidManifest.xml'));
  const duplicate_dex_paths = new Set(dex_entries.filter(entry => (entry_name_counts.get(entry.name) ?? 0) > 1).map(entry => entry.name));
  const duplicate_manifest_paths = new Set(manifest_entries.filter(entry => (entry_name_counts.get(entry.name) ?? 0) > 1).map(entry => entry.name));
  const reported_manifest_entries = manifest_entries.slice(0, max_archive_entries);
  const native_libraries = entries.filter(entry => (entry.name.startsWith('lib/') || entry.name.includes('/lib/')) && entry.name.endsWith('.so'));
  const reported_native_libraries = native_libraries.slice(0, max_archive_entries);
  const signatures = entries.filter(entry => is_v1_signature(entry.name));
  const signing_block = is_apk
    ? inspect_apk_signing_block(buffer, archive.archive.central_directory_offset, { max_signing_block_bytes, max_signing_block_pairs })
    : { status: 'not-applicable', offset: null, size_bytes: 0, pair_count: 0, schemes: [], unknown_ids: [], duplicate_ids: [] };
  const reported_signatures = signatures.slice(0, max_archive_entries);
  // Aggregate module path counts in one pass. Re-scanning the full entry
  // table once per module would turn hostile high-cardinality bundles into
  // quadratic CPU work.
  const module_inventory = new Map();
  if (is_aab) {
    for (const entry of entries) {
      const separator = entry.name.indexOf('/');
      if (separator <= 0) continue;
      const module_name = entry.name.slice(0, separator);
      if (module_name === 'BUNDLE-METADATA') continue;
      let item = module_inventory.get(module_name);
      if (!item) {
        item = {
          manifest_present: false,
          dex_entries: 0,
          native_libraries: 0,
          resources_pb_present: false,
          resource_paths: 0,
          asset_paths: 0,
          root_paths: 0,
        };
        module_inventory.set(module_name, item);
      }
      const relative = entry.name.slice(separator + 1);
      if (relative === 'manifest/AndroidManifest.xml') item.manifest_present = true;
      if (/^dex\/classes(?:[2-9]|[1-9][0-9]+)?\.dex$/.test(relative)) item.dex_entries += 1;
      if ((relative.startsWith('lib/') || relative.includes('/lib/')) && relative.endsWith('.so')) item.native_libraries += 1;
      if (relative === 'resources.pb') item.resources_pb_present = true;
      if (relative.startsWith('res/')) item.resource_paths += 1;
      if (relative.startsWith('assets/')) item.asset_paths += 1;
      if (relative.startsWith('root/')) item.root_paths += 1;
    }
  }
  const module_names = [...module_inventory.keys()].sort();
  const reported_modules = module_names.slice(0, max_aab_modules).map(name => ({
    name: name.slice(0, max_archive_entry_path_length),
    name_truncated: name.length > max_archive_entry_path_length,
    name_original_length: name.length,
    ...module_inventory.get(name),
  }));
  const bundle_config = is_aab
    ? inspect_bundle_config(buffer, entries, archive.archive.central_directory_offset, {
      max_bundle_config_bytes,
      bundle_config: options.bundle_config,
    })
    : { status: 'not-applicable', path: null, uncompressed_size: null, config: null };
  // Keep the raw ZIP inventory for resource-table diagnostics so unsafe
  // paths and symlink records can be reported without ever parsing them.
  const resource_tables = is_aab
    ? inspect_resource_tables(buffer, archive.entries, archive.archive.central_directory_offset, {
      max_resource_table_bytes,
      max_resource_table_total_bytes,
      max_resource_tables,
      resource_table: options.resource_table,
    })
    : { count: 0, reported: 0, omitted: 0, bytes_used: 0, tables: [] };
  const bundle = is_aab ? {
    status: 'recognized',
    bundle_config_present: names.has('BundleConfig.pb'),
    bundle_config,
    resource_tables,
    module_count: module_names.length,
    modules_reported: reported_modules.length,
    modules_omitted: Math.max(0, module_names.length - reported_modules.length),
    modules: reported_modules,
    module_semantics_decoded: false,
  } : {
    status: 'not-applicable',
    bundle_config_present: false,
    bundle_config,
    resource_tables,
    module_count: 0,
    modules_reported: 0,
    modules_omitted: 0,
    modules: [],
    module_semantics_decoded: false,
  };

  let dex_bytes_budget_used = 0;
  const reported_dex_entries = dex_entries.slice(0, max_archive_entries);
  const dex = reported_dex_entries.map((entry, index) => {
    const path = entry.name.slice(0, max_archive_entry_path_length);
    const path_truncated = entry.name.length > max_archive_entry_path_length;
    const path_original_length = entry.name.length;
    if (index >= max_dex_entries) return { path, path_truncated, path_original_length, status: 'entry-limit', uncompressed_size: entry.uncompressed_size };
    if (duplicate_dex_paths.has(entry.name)) return { path, path_truncated, path_original_length, status: 'duplicate-path', uncompressed_size: entry.uncompressed_size };
    if (entry.uncompressed_size > max_dex_entry_bytes) return { path, path_truncated, path_original_length, status: 'entry-size-limit', uncompressed_size: entry.uncompressed_size };
    if (dex_bytes_budget_used + entry.uncompressed_size > max_dex_total_bytes) return { path, path_truncated, path_original_length, status: 'aggregate-size-limit', uncompressed_size: entry.uncompressed_size };
    // Reserve declared output budget before attempting to inflate. Failed or
    // malicious entries must not get a fresh aggregate allowance on retry.
    dex_bytes_budget_used += entry.uncompressed_size;
    const data = local_entry_data(buffer, entry, max_dex_entry_bytes, archive.archive.central_directory_offset);
    if (data.status !== 'available') return { path, path_truncated, path_original_length, status: data.status, uncompressed_size: entry.uncompressed_size };
    try {
      const parsed = parse_dex(data.bytes, { max_file_bytes: max_dex_entry_bytes, max_output_items: max_dex_output_items });
      if (parsed.file_size !== entry.uncompressed_size) {
        return { path, path_truncated, path_original_length, status: 'size-mismatch', uncompressed_size: entry.uncompressed_size, dex_file_size: parsed.file_size };
      }
      return {
        path,
        path_truncated,
        path_original_length,
        status: 'metadata-parsed',
        uncompressed_size: entry.uncompressed_size,
        version: parsed.version,
        file_size: parsed.file_size,
        counts: parsed.counts,
        strings: parsed.strings,
        types: parsed.types,
        proto_ids: parsed.proto_ids,
        field_ids: parsed.field_ids,
        method_ids: parsed.method_ids,
        classes: parsed.classes,
        class_data: parsed.class_data,
        class_data_summary: parsed.class_data_summary,
        map_items: parsed.map_items,
        output_truncated: parsed.output_truncated,
        integrity: parsed.integrity,
        notes: parsed.notes,
      };
    } catch (error) {
      return { path, path_truncated, path_original_length, status: 'rejected', uncompressed_size: entry.uncompressed_size, error: { code: error.code ?? 'ORIX_DEX_ERROR', message: error.message } };
    }
  });
  return {
    schema_version: 'orix.android-package.v1',
    format: is_aab ? 'AAB' : is_apk ? 'APK' : 'Android package candidate',
    detected: is_aab || is_apk || dex_entries.length > 0 || bundle_manifest,
    archive: {
      entry_count: archive.entries.length,
      safe_entry_count: entries.length,
      unsafe_or_symlink_entries: archive.summary.unsafe_or_symlink_entries,
      duplicate_path_names: duplicate_path_names.length,
      duplicate_path_entries,
      entries_reported: archive_entries.length,
      entries_omitted: Math.max(0, entries.length - archive_entries.length),
      zip64: archive.archive.zip64,
    },
    archive_entries,
    summary: {
      dex_entries: dex_entries.length,
      dex_entries_reported: dex.length,
      dex_entries_omitted: Math.max(0, dex_entries.length - dex.length),
      dex_metadata_parsed: dex.filter(item => item.status === 'metadata-parsed').length,
      dex_entries_not_inspected: dex_entries.length - dex.filter(item => item.status === 'metadata-parsed').length,
      duplicate_dex_paths: duplicate_dex_paths.size,
      duplicate_manifest_paths: duplicate_manifest_paths.size,
      native_libraries: native_libraries.length,
      native_libraries_reported: reported_native_libraries.length,
      native_libraries_omitted: Math.max(0, native_libraries.length - reported_native_libraries.length),
      resources_table_present: names.has('resources.arsc') || entries.some(entry => is_aab_resource_table_entry(entry.name)),
      manifest_entries: manifest_entries.length,
      manifest_entries_reported: reported_manifest_entries.length,
      manifest_entries_omitted: Math.max(0, manifest_entries.length - reported_manifest_entries.length),
      v1_signature_files: signatures.length,
      v1_signature_files_reported: reported_signatures.length,
      v1_signature_files_omitted: Math.max(0, signatures.length - reported_signatures.length),
      apk_signing_block_present: signing_block.status === 'present',
      apk_signing_block_pairs: signing_block.pair_count,
      aab_modules: module_names.length,
      aab_modules_reported: reported_modules.length,
      aab_modules_omitted: Math.max(0, module_names.length - reported_modules.length),
      bundle_config_present: names.has('BundleConfig.pb'),
      resource_tables: resource_tables.count,
      resource_tables_reported: resource_tables.reported,
      resource_tables_omitted: resource_tables.omitted,
      resource_table_packages: resource_tables.tables.reduce((total, item) => total + (item.table?.summary.package_count ?? 0), 0),
      resource_table_entries: resource_tables.tables.reduce((total, item) => total + (item.table?.summary.entry_count ?? 0), 0),
    },
    manifests: (() => {
      let manifest_bytes_budget_used = 0;
      return reported_manifest_entries.map(entry => {
        const path = entry.name.slice(0, max_archive_entry_path_length);
        const path_truncated = entry.name.length > max_archive_entry_path_length;
        const path_original_length = entry.name.length;
        if (duplicate_manifest_paths.has(entry.name)) {
          return { path, path_truncated, path_original_length, status: 'duplicate-path', binary_xml: null };
        }
        if (entry.uncompressed_size <= max_manifest_bytes) {
          if (manifest_bytes_budget_used + entry.uncompressed_size > max_manifest_total_bytes) {
            return { path, path_truncated, path_original_length, status: 'aggregate-size-limit', binary_xml: null, uncompressed_size: entry.uncompressed_size };
          }
          // Charge rejected and malformed inputs too, so repeated bad modules
          // cannot each consume a fresh manifest decompression budget.
          manifest_bytes_budget_used += entry.uncompressed_size;
        }
        return {
          ...inspect_manifest(buffer, entry, archive.archive.central_directory_offset, options),
          path, path_truncated, path_original_length,
        };
      });
    })(),
    dex,
    native_libraries: reported_native_libraries.map(entry => ({
      path: entry.name.slice(0, max_archive_entry_path_length),
      path_truncated: entry.name.length > max_archive_entry_path_length,
      path_original_length: entry.name.length,
      compressed_size: entry.compressed_size,
      uncompressed_size: entry.uncompressed_size,
    })),
    signatures: reported_signatures.map(entry => entry.name.slice(0, max_archive_entry_path_length)),
    signing_block,
    bundle,
    limitations: [
      'ZIP entries are inventoried without filesystem extraction. Selected stored and raw-DEFLATE DEX/manifest entries are expanded in memory only within per-entry and aggregate output ceilings; encrypted, unsafe, malformed or unsupported entries are not parsed.',
      'APK binary XML and AAB AAPT2 protobuf XML manifests are decoded from stored or raw-DEFLATE, unencrypted entries whose local ZIP header and CRC match, within per-manifest and aggregate decompression budgets plus explicit parser limits; resource-reference resolution is not performed.',
      'AAB module names and DEX/native/resource/asset/root path counts are inventoried from ZIP entry names; bounded module manifests, BundleConfig.pb metadata and AAPT2 resources.pb package/type/entry/configuration/value-kind metadata are decoded under per-entry and aggregate byte, protobuf field, repeated-item, string and output budgets. Full resource-reference resolution, compound-value decoding, compiled resource-file decoding, dependency graph and split/install relationships remain unsupported.',
      'DEX strings (including Modified UTF-8), type/field/method/prototype identifiers, class-data indexes and bounded code-item structure are inspected; instruction opcodes, operands, control flow, annotations, debug programs and decompilation are not decoded.',
      'For APK files, the APK Signing Block container and ID-value pair boundaries are inventoried (v2/v3/v3.1 and unknown IDs); cryptographic signatures, content digests, certificate chains, v1 JAR signatures and publisher identity are not verified.',
      'This is offline file analysis. No Android device, adb command, app installation, emulator or application code is accessed or executed.',
    ],
    warnings: [
      ...dex.filter(item => item.status !== 'metadata-parsed').map(item => ({ path: item.path, reason: item.status })),
      ...(signing_block.status === 'malformed' ? [{ path: 'APK Signing Block', reason: signing_block.error.code }] : []),
      ...(is_aab && bundle_config.status !== 'decoded' ? [{ path: 'BundleConfig.pb', reason: bundle_config.status }] : []),
      ...resource_tables.tables.filter(item => item.status !== 'decoded').map(item => ({ path: item.path, reason: item.status })),
      ...reported_manifest_entries.filter(entry => duplicate_manifest_paths.has(entry.name)).map(entry => ({
        path: entry.name.slice(0, max_archive_entry_path_length), reason: 'duplicate-path',
      })),
    ],
  };
}


/**
 * Safely read a bounded regular file and analyze its APK/AAB structure.
 * Symlinks and files that change identity or metadata during acquisition are rejected.
 */
export async function analyze_android_package_file(file_path, options = {}) {
  const max_file_bytes = options.max_file_bytes ?? 536_870_912;
  if (!Number.isSafeInteger(max_file_bytes) || max_file_bytes < 1 || max_file_bytes > 1_073_741_824) {
    throw new TypeError('max_file_bytes must be between 1 and 1073741824');
  }
  const absolute = path.resolve(file_path);
  let handle;
  try {
    // Open first, then compare the path to the opened descriptor. This prevents
    // a path swap between a pre-open lstat and open from selecting another file.
    handle = await fs.open(absolute, fs_constants.O_RDONLY | (fs_constants.O_NOFOLLOW ?? 0), 0o600);
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size > max_file_bytes) {
      if (!opened.isFile()) throw new TypeError('Android package target must be a regular file');
      throw new RangeError('Android package exceeds the configured file-size limit');
    }

    const path_after_open = await fs.lstat(absolute);
    if (!path_after_open.isFile() || path_after_open.isSymbolicLink() ||
        path_after_open.dev !== opened.dev || path_after_open.ino !== opened.ino ||
        path_after_open.size !== opened.size || path_after_open.mtimeMs !== opened.mtimeMs ||
        path_after_open.ctimeMs !== opened.ctimeMs) {
      throw new Error('Android package path changed before acquisition');
    }

    const buffer = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < buffer.length) {
      const result = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (result.bytesRead === 0) break;
      offset += result.bytesRead;
    }

    const after = await handle.stat();
    const path_after_read = await fs.lstat(absolute);
    if (offset !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs ||
        after.ctimeMs !== opened.ctimeMs || after.dev !== opened.dev || after.ino !== opened.ino ||
        !path_after_read.isFile() || path_after_read.isSymbolicLink() ||
        path_after_read.dev !== opened.dev || path_after_read.ino !== opened.ino ||
        path_after_read.size !== opened.size || path_after_read.mtimeMs !== opened.mtimeMs ||
        path_after_read.ctimeMs !== opened.ctimeMs) {
      throw new Error('Android package changed during acquisition');
    }
    const report = analyze_android_package(buffer, options);
    return {
      ...report,
      source: {
        name: path.basename(absolute),
        size_bytes: buffer.length,
        sha256: hash_buffer(buffer),
        stable_during_read: true,
      },
    };
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

function markdown_cell(value) {
  const slash = String.fromCharCode(92);
  let output = '';
  for (const character of String(value ?? '')) {
    const code = character.charCodeAt(0);
    if (character === slash) output += slash + slash;
    else if (character === '|') output += slash + '|';
    else if (['[', ']', '*', '_', '`', '!', '(', ')'].includes(character)) output += slash + character;
    else if (character === '&') output += '&amp;';
    else if (character === '<') output += '&lt;';
    else if (character === '>') output += '&gt;';
    else if (code === 10 || code === 13) output += ' ';
    else output += character;
  }
  return output;
}

export function render_android_package_markdown(report) {
  const lines = [
    '# ORIX Android Package Report',
    '',
    '- **Format:** ' + markdown_cell(report.format),
    '- **Detected:** ' + String(report.detected),
    ...(report.source ? [
      '- **Source:** ' + markdown_cell(report.source.name),
      '- **Source bytes:** ' + report.source.size_bytes,
      '- **Source SHA-256:** ' + report.source.sha256,
      '- **Stable during read:** ' + String(report.source.stable_during_read),
    ] : []),
    '- **ZIP entries:** ' + report.archive.entry_count,
    '- **Safe entries reported:** ' + report.archive.entries_reported + ' / ' + report.archive.safe_entry_count,
    '- **Unsafe path/symlink entries excluded:** ' + report.archive.unsafe_or_symlink_entries,
    '- **Safe entries omitted by output limit:** ' + report.archive.entries_omitted,
    '- **DEX entries:** ' + report.summary.dex_entries + ' (' + report.summary.dex_entries_reported + ' reported; ' + report.summary.dex_entries_omitted + ' omitted by output limit)',
    '- **DEX headers parsed:** ' + report.summary.dex_metadata_parsed,
    '- **Native libraries:** ' + report.summary.native_libraries + ' (' + report.summary.native_libraries_reported + ' reported)',
    '- **Manifest entries:** ' + report.summary.manifest_entries + ' (' + report.summary.manifest_entries_reported + ' reported)',
    '- **V1 signature files:** ' + report.summary.v1_signature_files + ' (' + report.summary.v1_signature_files_reported + ' reported)',
    '- **APK Signing Block:** ' + markdown_cell(report.signing_block.status) + (report.signing_block.status === 'present' ? ' (' + report.signing_block.pair_count + ' pairs)' : ''),
    '',
    '## Archive entries',
    '',
    '| Path | Type | Compression | Encrypted | Compressed bytes | Uncompressed bytes |',
    '|---|---|---|---|---:|---:|',
  ];
  if (report.archive_entries.length === 0) lines.push('| None | — | — | — | 0 | 0 |');
  for (const item of report.archive_entries) {
    const entry_path = item.path + (item.path_truncated ? '… (' + item.path_original_length + ' chars total)' : '');
    lines.push('| ' + markdown_cell(entry_path) + ' | ' + item.kind + ' | ' + markdown_cell(item.compression_method) + ' | ' +
      String(item.encrypted) + ' | ' + item.compressed_size + ' | ' + item.uncompressed_size + ' |');
  }
  lines.push('', '## DEX inventory', '', '| Entry | Status | Version | Size |', '|---|---|---:|---:|');
  if (report.dex.length === 0) lines.push('| None | — | — | — |');
  for (const item of report.dex) {
    lines.push('| ' + markdown_cell(item.path) + ' | ' + markdown_cell(item.status) + ' | ' +
      markdown_cell(item.version ?? '—') + ' | ' + (item.uncompressed_size ?? '—') + ' |');
  }
  lines.push('', '## Manifests', '');
  if (report.manifests.length === 0) lines.push('No Android manifest entry was found.');
  for (const item of report.manifests) {
    lines.push('- ' + markdown_cell(item.path) + ': ' + markdown_cell(item.status));
    if (item.decoded) {
      lines.push('  - Package: ' + markdown_cell(item.package_name ?? '—'));
      lines.push('  - Version: ' + markdown_cell(item.version_name ?? item.version_code ?? '—'));
      if (item.sdk) lines.push('  - SDK: min=' + markdown_cell(item.sdk.min_version ?? 'unspecified') +
        ', target=' + markdown_cell(item.sdk.target_version ?? 'unspecified') +
        ', max=' + markdown_cell(item.sdk.max_version ?? 'unspecified'));
      if (item.application) lines.push('  - Application: debuggable=' + markdown_cell(item.application.debuggable ?? 'unspecified') +
        ', allowBackup=' + markdown_cell(item.application.allowBackup ?? 'unspecified') +
        ', cleartext=' + markdown_cell(item.application.usesCleartextTraffic ?? 'unspecified'));
      lines.push('  - Permissions: ' + (item.permissions?.length ? item.permissions.map(value => markdown_cell(value.name)).join(', ') : 'none reported'));
      lines.push('  - Components: ' + (item.components?.length ? item.components.map(value =>
        markdown_cell(value.type + ' ' + (value.name ?? 'unnamed') + ' exported=' + (value.exported ?? 'unspecified'))).join('; ') : 'none reported'));
      if (item.output_truncated) lines.push('  - Output was truncated by configured limits.');
    }
  }
  lines.push('', '## App Bundle modules', '');
  if (report.bundle.status === 'recognized') {
    lines.push('- BundleConfig.pb present: ' + String(report.bundle.bundle_config_present));
    lines.push('- BundleConfig status: ' + markdown_cell(report.bundle.bundle_config.status));
    if (report.bundle.bundle_config.config) {
      const config = report.bundle.bundle_config.config;
      if (config.bundletool?.version) lines.push('- Bundletool version: ' + markdown_cell(config.bundletool.version));
      lines.push('- Bundle type: ' + markdown_cell(config.type.name));
      if (config.compression?.uncompressed_globs.length) lines.push('- Uncompressed globs: ' + config.compression.uncompressed_globs.map(markdown_cell).join(', '));
      if (config.optimizations) lines.push('- Optimization metadata: decoded');
      if (config.coverage.output_truncated) lines.push('- BundleConfig metadata output was truncated by configured limits.');
      if (config.coverage.unknown_fields > 0) lines.push('- BundleConfig unknown fields preserved as skipped metadata: ' + config.coverage.unknown_fields);
    }
    lines.push('- Modules reported: ' + report.bundle.modules_reported + ' / ' + report.bundle.module_count);
    lines.push('- Resource tables decoded: ' + report.bundle.resource_tables.tables.filter(item => item.status === 'decoded').length +
      ' / ' + report.bundle.resource_tables.count + ' (' + report.bundle.resource_tables.bytes_used + ' bytes charged)');
    if (report.bundle.resource_tables.omitted > 0) lines.push('- Resource table outputs omitted by configured table limit: ' + report.bundle.resource_tables.omitted);
    if (report.bundle.resource_tables.tables.length > 0) {
      lines.push('', '| Module | resources.pb status | Packages | Types | Entries |', '|---|---|---:|---:|---:|');
      for (const item of report.bundle.resource_tables.tables) {
        const summary = item.table?.summary;
        lines.push('| ' + markdown_cell(item.module) + ' | ' + markdown_cell(item.status) + ' | ' +
          (summary?.package_count ?? '—') + ' | ' + (summary?.type_count ?? '—') + ' | ' + (summary?.entry_count ?? '—') + ' |');
      }
    }
    lines.push('', '| Module | Manifest | DEX | Native libraries | resources.pb | res/ | assets/ | root/ |', '|---|---:|---:|---:|---|---:|---:|---:|');
    for (const item of report.bundle.modules) {
      lines.push('| ' + markdown_cell(item.name) + ' | ' + String(item.manifest_present) + ' | ' + item.dex_entries + ' | ' + item.native_libraries + ' | ' + String(item.resources_pb_present) + ' | ' + item.resource_paths + ' | ' + item.asset_paths + ' | ' + item.root_paths + ' |');
    }
  } else lines.push('Not an Android App Bundle.');
  lines.push('', '## Native libraries', '');
  if (report.native_libraries.length === 0) lines.push('No native library paths were reported.');
  for (const item of report.native_libraries) {
    const entry_path = item.path + (item.path_truncated ? '… (' + item.path_original_length + ' chars total)' : '');
    lines.push('- ' + markdown_cell(entry_path) + ' (' + item.uncompressed_size + ' bytes)');
  }
  lines.push('', '## APK signing-block inventory', '');
  if (report.signing_block.status === 'present') {
    lines.push('- Offset: ' + report.signing_block.offset);
    lines.push('- Size: ' + report.signing_block.size_bytes + ' bytes');
    lines.push('- Signature-scheme IDs: ' + (report.signing_block.schemes.length ? report.signing_block.schemes.map(item => markdown_cell(item.name + ' (' + item.id + ')')).join(', ') : 'none recognized'));
    lines.push('- Unknown IDs: ' + (report.signing_block.unknown_ids.length ? report.signing_block.unknown_ids.join(', ') : 'none'));
    if (report.signing_block.duplicate_ids.length) lines.push('- Duplicate IDs: ' + report.signing_block.duplicate_ids.map(item => item.id + ' ×' + item.count).join(', '));
  } else lines.push('Signing-block status: ' + markdown_cell(report.signing_block.status));
  lines.push('', '## V1 signature filename hints', '');
  if (report.signatures.length === 0) lines.push('No v1 signature filenames were reported.');
  for (const name of report.signatures) lines.push('- ' + markdown_cell(name));
  lines.push('', '## Limitations', '');
  for (const note of report.limitations) lines.push('- ' + note);
  if (report.warnings.length > 0) {
    lines.push('', '## Warnings', '');
    for (const warning of report.warnings) lines.push('- ' + markdown_cell(warning.path) + ': ' + markdown_cell(warning.reason));
  }
  return lines.join(String.fromCharCode(10)) + String.fromCharCode(10);
}
