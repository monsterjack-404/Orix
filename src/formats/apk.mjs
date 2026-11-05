// JavaScript, src/formats/apk.mjs, Node.js 20+, bounded read-only Android APK/DEX structural analysis.
import { inflateRawSync } from 'node:zlib';
import { BinaryReader } from '../core/binary-reader.mjs';
import { OrixError } from '../core/errors.mjs';
import { parse_zip } from './zip.mjs';

const DEX_MAGIC = /^dex\n0(35|36|37|38|39|40|41)\0$/;
const DEFAULTS = Object.freeze({ max_entries: 100000, max_entry_bytes: 64 * 1024 * 1024, max_total_extract_bytes: 128 * 1024 * 1024, max_dex_files: 64, max_classes_per_dex: 100000, max_identifier_items: 400000, max_manifest_strings: 100000, max_manifest_attributes: 100000 });

function limits_for(options) {
  const out = {};
  for (const [key, fallback] of Object.entries(DEFAULTS)) {
    const value = options[key] ?? fallback;
    if (!Number.isSafeInteger(value) || value < 1 || value > fallback) throw new TypeError(key + ' must be a positive integer no greater than ' + fallback);
    out[key] = value;
  }
  return out;
}
function fail(code, message, details = {}) { throw new OrixError(code, message, { details, recoverable: true }); }
function read_uleb(reader, offset, end, label) {
  let value = 0; let shift = 0; let cursor = offset;
  for (let i = 0; i < 5; i += 1) {
    if (cursor >= end) fail('ORIX_ANDROID_TRUNCATED_ULEB128', label + ' is truncated', { offset });
    const byte = reader.u8(cursor++, label);
    if (i === 4 && (byte & 0xf0)) fail('ORIX_ANDROID_BAD_ULEB128', label + ' exceeds 32-bit range', { offset });
    value |= (byte & 0x7f) << shift;
    if (!(byte & 0x80)) return { value: value >>> 0, next: cursor };
    shift += 7;
  }
  fail('ORIX_ANDROID_BAD_ULEB128', label + ' exceeds five bytes', { offset });
}
function decode_string_pool(reader, offset, end, limits) {
  reader.require(offset, 28, 'Android string-pool header');
  const type = reader.u16(offset, true, 'string-pool type');
  const header_size = reader.u16(offset + 2, true, 'string-pool header size');
  const chunk_size = reader.u32(offset + 4, true, 'string-pool chunk size');
  if (type !== 1 || header_size < 28 || chunk_size < header_size || chunk_size > end - offset) fail('ORIX_ANDROID_BAD_STRING_POOL', 'Android XML string pool has invalid framing', { offset, type, header_size, chunk_size });
  const string_count = reader.u32(offset + 8, true, 'string count');
  const style_count = reader.u32(offset + 12, true, 'style count');
  const flags = reader.u32(offset + 16, true, 'string-pool flags');
  const strings_start = reader.u32(offset + 20, true, 'strings start');
  if (string_count > limits.max_manifest_strings || style_count > limits.max_manifest_strings) fail('ORIX_ANDROID_STRING_LIMIT', 'Android XML string pool exceeds configured limits', { string_count, style_count });
  const offsets_start = offset + header_size;
  const offsets_bytes = (string_count + style_count) * 4;
  if (offsets_bytes > chunk_size - header_size || strings_start < header_size + offsets_bytes || strings_start > chunk_size) fail('ORIX_ANDROID_BAD_STRING_POOL', 'Android XML string-pool offsets are outside the chunk', { string_count, style_count, strings_start });
  const data_start = offset + strings_start;
  const chunk_end = offset + chunk_size;
  const utf8 = Boolean(flags & 0x100);
  const strings = [];
  function length8(at) {
    if (at >= chunk_end) fail('ORIX_ANDROID_BAD_STRING', 'UTF-8 string length is outside its string-pool chunk', { at });
    const first = reader.u8(at, 'UTF-8 string length');
    if (first & 0x80) {
      if (at + 1 >= chunk_end) fail('ORIX_ANDROID_BAD_STRING', 'UTF-8 string length prefix is truncated', { at });
      return { length: ((first & 0x7f) << 8) | reader.u8(at + 1, 'UTF-8 string length'), next: at + 2 };
    }
    return { length: first, next: at + 1 };
  }
  function length16(at) {
    if (at > chunk_end - 2) fail('ORIX_ANDROID_BAD_STRING', 'UTF-16 string length is outside its string-pool chunk', { at });
    const first = reader.u16(at, true, 'UTF-16 string length');
    if (first & 0x8000) {
      if (at > chunk_end - 4) fail('ORIX_ANDROID_BAD_STRING', 'UTF-16 string length prefix is truncated', { at });
      return { length: ((first & 0x7fff) << 16) | reader.u16(at + 2, true, 'UTF-16 string length'), next: at + 4 };
    }
    return { length: first, next: at + 2 };
  }
  for (let i = 0; i < string_count; i += 1) {
    const relative = reader.u32(offsets_start + i * 4, true, 'string offset');
    if (relative >= chunk_end - data_start) fail('ORIX_ANDROID_BAD_STRING_OFFSET', 'Android XML string offset is outside the pool', { index: i, relative });
    let at = data_start + relative;
    if (utf8) {
      const chars = length8(at); const bytes = length8(chars.next); at = bytes.next;
      if (bytes.length > chunk_end - at || at + bytes.length >= chunk_end || reader.u8(at + bytes.length, 'UTF-8 string terminator') !== 0) fail('ORIX_ANDROID_BAD_STRING', 'UTF-8 string exceeds pool bounds or lacks terminator', { index: i });
      strings.push(reader.bytes(at, bytes.length, 'UTF-8 string').toString('utf8'));
    } else {
      const chars = length16(at); at = chars.next;
      const byte_length = chars.length * 2;
      if (!Number.isSafeInteger(byte_length) || byte_length > chunk_end - at || at + byte_length + 2 > chunk_end || reader.u16(at + byte_length, true, 'UTF-16 string terminator') !== 0) fail('ORIX_ANDROID_BAD_STRING', 'UTF-16 string exceeds pool bounds or lacks terminator', { index: i });
      strings.push(reader.bytes(at, byte_length, 'UTF-16 string').toString('utf16le'));
    }
  }
  return { strings, end: chunk_end };
}
function parse_binary_manifest(buffer, limits) {
  const reader = new BinaryReader(buffer, { label: 'Android binary XML manifest' });
  reader.require(0, 8, 'XML root chunk');
  if (reader.u16(0, true, 'XML root type') !== 3) fail('ORIX_ANDROID_MANIFEST_NOT_BINARY_XML', 'AndroidManifest.xml is not Android binary XML');
  const root_size = reader.u32(4, true, 'XML root size');
  if (root_size !== buffer.length || reader.u16(2, true, 'XML root header size') < 8) fail('ORIX_ANDROID_BAD_XML_ROOT', 'Android binary XML root size is inconsistent', { root_size, actual: buffer.length });
  let cursor = reader.u16(2, true, 'XML root header size');
  let strings = [];
  let string_pool_seen = false;
  const permissions = []; const components = []; const sdk = {};
  let package_name = null; let application = null; let chunk_count = 0; let attribute_total = 0;
  const max_chunks = Math.min(200000, Math.max(1000, buffer.length / 8));
  while (cursor < buffer.length) {
    if (++chunk_count > max_chunks) fail('ORIX_ANDROID_XML_CHUNK_LIMIT', 'Android XML chunk count exceeds its derived bound');
    reader.require(cursor, 8, 'XML child chunk');
    const type = reader.u16(cursor, true, 'XML chunk type');
    const header_size = reader.u16(cursor + 2, true, 'XML chunk header size');
    const size = reader.u32(cursor + 4, true, 'XML chunk size');
    if (header_size < 8 || size < header_size || size > buffer.length - cursor) fail('ORIX_ANDROID_BAD_XML_CHUNK', 'Android XML child chunk has invalid bounds', { cursor, type, header_size, size });
    const end = cursor + size;
    if (type === 1) {
      if (string_pool_seen) fail('ORIX_ANDROID_DUPLICATE_STRING_POOL', 'Android XML contains more than one string pool');
      string_pool_seen = true;
      const pool = decode_string_pool(reader, cursor, end, limits);
      strings = pool.strings;
    } else if (type === 0x0102) {
      if (!strings.length) fail('ORIX_ANDROID_XML_STRING_POOL_MISSING', 'Start-element chunk appears before its string pool', { cursor });
      reader.require(cursor, 36, 'XML start-element extension');
      const name_index = reader.u32(cursor + 20, true, 'element name index');
      const attribute_start = reader.u16(cursor + 24, true, 'attribute start');
      const attribute_size = reader.u16(cursor + 26, true, 'attribute size');
      const attribute_count = reader.u16(cursor + 28, true, 'attribute count');
      if (attribute_size < 20 || attribute_count > limits.max_manifest_attributes) fail('ORIX_ANDROID_ATTRIBUTE_LIMIT', 'Android XML attribute table exceeds supported bounds', { attribute_size, attribute_count });
      attribute_total += attribute_count;
      if (attribute_total > limits.max_manifest_attributes) fail('ORIX_ANDROID_ATTRIBUTE_LIMIT', 'Android manifest has too many attributes', { attribute_total });
      const attrs = cursor + 16 + attribute_start;
      if (attrs < cursor + header_size || attribute_count > Math.floor((end - attrs) / attribute_size)) fail('ORIX_ANDROID_BAD_ATTRIBUTES', 'Android XML attributes exceed their chunk bounds', { cursor, attrs, attribute_count, attribute_size });
      if (name_index >= strings.length) fail('ORIX_ANDROID_XML_NAME_INDEX', 'Android XML element name index is outside the string pool', { name_index, string_count: strings.length });
      const element = strings[name_index];
      const values = {};
      for (let i = 0; i < attribute_count; i += 1) {
        const at = attrs + i * attribute_size;
        const attr_name_index = reader.u32(at + 4, true, 'attribute name index');
        if (attr_name_index >= strings.length) fail('ORIX_ANDROID_XML_ATTRIBUTE_NAME_INDEX', 'Android XML attribute name index is outside the string pool', { attr_name_index, string_count: strings.length });
        const attr_name = strings[attr_name_index];
        const raw_index = reader.u32(at + 8, true, 'attribute raw value');
        if (raw_index !== 0xffffffff && raw_index >= strings.length) fail('ORIX_ANDROID_XML_ATTRIBUTE_VALUE_INDEX', 'Android XML raw attribute value index is outside the string pool', { raw_index, string_count: strings.length });
        const value_type = reader.u8(at + 15, 'attribute value type');
        const value_data = reader.u32(at + 16, true, 'attribute value data');
        let value = raw_index !== 0xffffffff ? strings[raw_index] ?? null : null;
        if (value === null) {
          if (value_type === 3) {
            if (value_data >= strings.length) fail('ORIX_ANDROID_XML_ATTRIBUTE_VALUE_INDEX', 'Android XML typed string value index is outside the string pool', { value_data, string_count: strings.length });
            value = strings[value_data];
          }
          else if (value_type === 0x10 || value_type === 0x11) value = value_data;
          else if (value_type === 0x12) value = Boolean(value_data);
        }
        if (attr_name) values[attr_name] = value;
      }
      if (element === 'manifest') package_name = values.package ?? package_name;
      if (element === 'uses-sdk') Object.assign(sdk, { min_sdk: values.minSdkVersion ?? null, target_sdk: values.targetSdkVersion ?? null, max_sdk: values.maxSdkVersion ?? null });
      if (element === 'uses-permission' || element === 'uses-permission-sdk-23' || element === 'uses-permission-sdk-m') {
        const permission = values.name;
        if (typeof permission === 'string' && permissions.length < 10000) permissions.push(permission);
      }
      if (element === 'application') application = { label: values.label ?? null, icon: values.icon ?? null, debuggable: values.debuggable ?? null, allow_backup: values.allowBackup ?? null, uses_cleartext_traffic: values.usesCleartextTraffic ?? null };
      if (['activity','activity-alias','service','receiver','provider'].includes(element)) {
        if (components.length < 20000) components.push({ type: element, name: values.name ?? null, exported: values.exported ?? null, permission: values.permission ?? null });
      }
    }
    cursor = end;
  }
  if (cursor !== buffer.length) fail('ORIX_ANDROID_XML_TRAILING_DATA', 'Android XML chunk table does not end at file boundary');
  return { encoding: 'android-binary-xml', package_name, sdk, permissions: [...new Set(permissions)].sort(), application, components, string_count: strings.length, chunks: chunk_count };
}
function decode_manifest(buffer, limits) {
  const prefix = buffer.subarray(0, Math.min(buffer.length, 64)).toString('utf8').trimStart();
  if (prefix.startsWith('<')) {
    const xml = buffer.toString('utf8');
    if (!/^\s*<\?xml|^\s*<manifest\b/.test(xml)) fail('ORIX_ANDROID_MANIFEST_INVALID_XML', 'Plain-text manifest does not begin with an XML declaration or manifest element');
    const package_name = /<manifest\b[^>]*\bpackage\s*=\s*["']([^"']+)["']/i.exec(xml)?.[1] ?? null;
    const permissions = [...xml.matchAll(/<uses-permission(?:-[\w-]+)?\b[^>]*\bandroid:name\s*=\s*["']([^"']+)["']/gi)].map(m => m[1]).slice(0, 10000);
    const sdk = {};
    const sdk_tag = /<uses-sdk\b([^>]*)>/i.exec(xml)?.[1] ?? '';
    for (const [key, name] of [['minSdkVersion','min_sdk'],['targetSdkVersion','target_sdk'],['maxSdkVersion','max_sdk']]) sdk[name] = new RegExp('android:' + key + '\\s*=\\s*"([^"]+)"', 'i').exec(sdk_tag)?.[1] ?? null;
    return { encoding: 'plain-xml', package_name, sdk, permissions: [...new Set(permissions)].sort(), application: null, components: [], string_count: null, chunks: null };
  }
  return parse_binary_manifest(buffer, limits);
}
function parse_dex(buffer, limits, name) {
  const reader = new BinaryReader(buffer, { label: 'DEX file ' + name });
  reader.require(0, 0x70, 'DEX header');
  const magic = reader.ascii(0, 8, 'DEX magic');
  if (!DEX_MAGIC.test(magic)) fail('ORIX_ANDROID_BAD_DEX_MAGIC', 'DEX magic or version is unsupported', { name, magic });
  const file_size = reader.u32(0x20, true, 'DEX file size');
  const header_size = reader.u32(0x24, true, 'DEX header size');
  const endian_tag = reader.u32(0x28, true, 'DEX endian tag');
  if (file_size !== buffer.length || header_size !== 0x70 || endian_tag !== 0x12345678) fail('ORIX_ANDROID_BAD_DEX_HEADER', 'DEX header size, file size or byte order is invalid', { name, file_size, actual_size: buffer.length, header_size, endian_tag });
  const link_size = reader.u32(0x2c, true, 'DEX link size');
  const link_offset = reader.u32(0x30, true, 'DEX link offset');
  if ((link_size === 0 && link_offset !== 0) || (link_size > 0 && (link_offset < 0x70 || link_offset > buffer.length || link_size > buffer.length - link_offset))) fail('ORIX_ANDROID_DEX_LINK_RANGE', 'DEX link section has inconsistent or out-of-file bounds', { name, link_size, link_offset });
  const data_size = reader.u32(0x68, true, 'DEX data size');
  const data_offset = reader.u32(0x6c, true, 'DEX data offset');
  if ((data_size === 0 && data_offset !== 0) || (data_size > 0 && (data_offset < 0x70 || data_offset > buffer.length || data_size > buffer.length - data_offset))) fail('ORIX_ANDROID_DEX_DATA_RANGE', 'DEX data section has inconsistent or out-of-file bounds', { name, data_size, data_offset });
  const tables = {};
  for (const [key, size_at, offset_at, width] of [['strings',0x38,0x3c,4],['types',0x40,0x44,4],['protos',0x48,0x4c,12],['fields',0x50,0x54,8],['methods',0x58,0x5c,8],['classes',0x60,0x64,32]]) {
    const count = reader.u32(size_at, true, key + ' count');
    const offset = reader.u32(offset_at, true, key + ' offset');
    if (count > 0 && (offset < 0x70 || count > Math.floor((buffer.length - offset) / width))) fail('ORIX_ANDROID_DEX_TABLE_RANGE', 'DEX ' + key + ' table exceeds file bounds', { name, count, offset, width });
    if (count === 0 && offset !== 0 && offset > buffer.length) fail('ORIX_ANDROID_DEX_TABLE_RANGE', 'Empty DEX ' + key + ' table has an invalid offset', { name, offset });
    tables[key] = { count, offset };
  }
  for (const [key, table] of Object.entries(tables)) if (table.count > limits.max_identifier_items) fail('ORIX_ANDROID_DEX_TABLE_LIMIT', 'DEX ' + key + ' table exceeds the configured item ceiling', { name, count: table.count, max_identifier_items: limits.max_identifier_items });
  const map_offset = reader.u32(0x34, true, 'DEX map offset');
  if (map_offset !== 0 && (map_offset < 0x70 || map_offset > buffer.length - 4)) fail('ORIX_ANDROID_DEX_MAP_RANGE', 'DEX map offset is outside file bounds', { name, map_offset });
  const strings = [];
  const max_strings = Math.min(tables.strings.count, limits.max_identifier_items);
  if (tables.strings.count > max_strings) fail('ORIX_ANDROID_DEX_STRING_LIMIT', 'DEX string table exceeds the configured derived limit', { name, string_count: tables.strings.count, max_strings });
  for (let i = 0; i < max_strings; i += 1) {
    const data_offset = reader.u32(tables.strings.offset + i * 4, true, 'DEX string data offset');
    if (data_offset >= buffer.length) fail('ORIX_ANDROID_DEX_STRING_RANGE', 'DEX string data offset is outside file bounds', { name, index: i, data_offset });
    const length = read_uleb(reader, data_offset, buffer.length, 'DEX string length');
    let end = length.next;
    while (end < buffer.length && buffer[end] !== 0 && end - length.next <= 65535) end += 1;
    if (end >= buffer.length || end - length.next > 65535) fail('ORIX_ANDROID_DEX_STRING_RANGE', 'DEX string is unterminated or exceeds 64 KiB', { name, index: i });
    strings.push(buffer.toString('utf8', length.next, end));
  }
  const types = [];
  for (let i = 0; i < tables.types.count; i += 1) {
    const index = reader.u32(tables.types.offset + i * 4, true, 'DEX type descriptor index');
    if (index >= strings.length) fail('ORIX_ANDROID_DEX_TYPE_INDEX', 'DEX type descriptor references an unavailable string', { name, index, string_count: strings.length });
    types.push(strings[index]);
  }
  const classes = [];
  const class_count = Math.min(tables.classes.count, limits.max_classes_per_dex);
  for (let i = 0; i < class_count; i += 1) {
    const class_index = reader.u32(tables.classes.offset + i * 32, true, 'DEX class index');
    const access_flags = reader.u32(tables.classes.offset + i * 32 + 4, true, 'DEX class access flags');
    if (class_index >= types.length) fail('ORIX_ANDROID_DEX_CLASS_INDEX', 'DEX class definition references an unavailable type', { name, class_index, type_count: types.length });
    classes.push({ descriptor: types[class_index], access_flags });
  }
  return { name, version: magic.slice(4, 7), file_size, checksum: '0x' + reader.u32(8, true, 'DEX checksum').toString(16).padStart(8, '0'), tables, classes, classes_truncated: tables.classes.count > class_count, map_offset };
}
function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function extract_entry(buffer, entry, limits, remaining_budget, central_directory_offset) {
  if (entry.unsafe_path || entry.is_symlink || entry.is_directory || !entry.local_header_valid || !entry.local_data_range_valid || entry.encrypted) fail('ORIX_ANDROID_UNSAFE_ZIP_ENTRY', 'APK entry cannot be safely inspected', { name: entry.name });
  if (entry.uncompressed_size > limits.max_entry_bytes || entry.uncompressed_size > remaining_budget) fail('ORIX_ANDROID_ENTRY_SIZE_LIMIT', 'APK entry exceeds extraction budget', { name: entry.name, size: entry.uncompressed_size, max_entry_bytes: limits.max_entry_bytes, remaining_budget });
  const local = new BinaryReader(buffer, { label: 'APK ZIP entry ' + entry.name });
  const offset = entry.local_header_offset;
  const name_length = local.u16(offset + 26, true, 'local name length');
  const local_name = local.bytes(offset + 30, name_length, 'local entry name').toString(entry.utf8_name ? 'utf8' : 'latin1');
  if (local_name !== entry.name) fail('ORIX_ANDROID_LOCAL_NAME_MISMATCH', 'APK local-header name differs from its central-directory name', { name: entry.name, local_name });
  const local_flags = local.u16(offset + 6, true, 'local general-purpose flags');
  if (Boolean(local_flags & 0x0001) !== entry.encrypted || Boolean(local_flags & 0x0008) !== entry.data_descriptor || Boolean(local_flags & 0x0800) !== entry.utf8_name) fail('ORIX_ANDROID_LOCAL_FLAGS_MISMATCH', 'APK local-header flags differ from central-directory metadata', { name: entry.name, local_flags });
  const local_method = local.u16(offset + 8, true, 'local compression method');
  if (local_method !== ({ stored: 0, deflate: 8 }[entry.compression_method] ?? -1)) fail('ORIX_ANDROID_LOCAL_METHOD_MISMATCH', 'APK local-header compression method differs from central directory', { name: entry.name, local_method, central_method: entry.compression_method });
  const extra_length = local.u16(offset + 28, true, 'local extra length');
  const data_offset = offset + 30 + name_length + extra_length;
  if (offset >= central_directory_offset || data_offset > central_directory_offset || entry.compressed_size > central_directory_offset - data_offset) fail('ORIX_ANDROID_ENTRY_OVERLAPS_DIRECTORY', 'APK entry data overlaps the ZIP central directory', { name: entry.name, offset, data_offset, compressed_size: entry.compressed_size, central_directory_offset });
  const compressed = local.bytes(data_offset, entry.compressed_size, 'compressed APK entry');
  let result;
  if (entry.compression_method === 'stored') result = compressed;
  else if (entry.compression_method === 'deflate') {
    try { result = inflateRawSync(compressed, { maxOutputLength: Math.min(limits.max_entry_bytes, remaining_budget) }); }
    catch (error) { fail('ORIX_ANDROID_DECOMPRESSION_FAILED', 'APK entry decompression failed or exceeded the output bound', { name: entry.name, reason: String(error.message).slice(0, 160) }); }
  } else fail('ORIX_ANDROID_COMPRESSION_UNSUPPORTED', 'APK entry uses an unsupported compression method', { name: entry.name, compression_method: entry.compression_method });
  if (result.length !== entry.uncompressed_size) fail('ORIX_ANDROID_ENTRY_SIZE_MISMATCH', 'APK entry decompressed size does not match central-directory metadata', { name: entry.name, expected: entry.uncompressed_size, actual: result.length });
  const expected_crc = Number.parseInt(entry.crc32.slice(2), 16) >>> 0;
  const actual_crc = crc32(result);
  if (actual_crc !== expected_crc) fail('ORIX_ANDROID_ENTRY_CRC_MISMATCH', 'APK entry CRC32 does not match its central-directory checksum', { name: entry.name, expected_crc: entry.crc32, actual_crc: '0x' + actual_crc.toString(16).padStart(8, '0') });
  if (!entry.data_descriptor) {
    const local_crc = local.u32(offset + 14, true, 'local entry CRC32');
    const local_compressed_size = local.u32(offset + 18, true, 'local compressed size');
    const local_uncompressed_size = local.u32(offset + 22, true, 'local uncompressed size');
    if (local_crc !== expected_crc || local_compressed_size !== entry.compressed_size || local_uncompressed_size !== entry.uncompressed_size) fail('ORIX_ANDROID_LOCAL_METADATA_MISMATCH', 'APK local-header CRC or sizes differ from central-directory metadata', { name: entry.name });
  }
  return result;
}
export function parse_apk(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_apk requires a Buffer');
  const limits = limits_for(options);
  const zip = parse_zip(buffer, { max_entries: limits.max_entries });
  const manifest_entries = zip.entries.filter(entry => entry.name === 'AndroidManifest.xml');
  if (manifest_entries.length === 0) fail('ORIX_ANDROID_MANIFEST_MISSING', 'APK archive does not contain AndroidManifest.xml');
  if (manifest_entries.length !== 1) fail('ORIX_ANDROID_DUPLICATE_MANIFEST', 'APK archive contains duplicate AndroidManifest.xml entries', { count: manifest_entries.length });
  const manifest_entry = manifest_entries[0];
  let budget = limits.max_total_extract_bytes;
  const manifest_bytes = extract_entry(buffer, manifest_entry, limits, budget, zip.archive.central_directory_offset);
  budget -= manifest_bytes.length;
  const manifest = decode_manifest(manifest_bytes, limits);
  const dex_entries = zip.entries.filter(entry => /^classes(?:\.dex|(?:[2-9]|[1-9][0-9]+)\.dex)$/.test(entry.name)).sort((a,b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
  if (dex_entries.length > limits.max_dex_files) fail('ORIX_ANDROID_DEX_FILE_LIMIT', 'APK contains more DEX files than the configured limit', { count: dex_entries.length, max_dex_files: limits.max_dex_files });
  for (let i = 1; i < dex_entries.length; i += 1) if (dex_entries[i - 1].name === dex_entries[i].name) fail('ORIX_ANDROID_DUPLICATE_DEX', 'APK archive contains duplicate DEX entry names', { name: dex_entries[i].name });
  const dex = [];
  for (const entry of dex_entries) {
    const bytes = extract_entry(buffer, entry, limits, budget, zip.archive.central_directory_offset);
    budget -= bytes.length;
    dex.push(parse_dex(bytes, limits, entry.name));
  }
  const native_libraries = zip.entries.filter(entry => /^lib\/[^/]+\/[^/]+\.so$/i.test(entry.name)).map(entry => ({ path: entry.name, abi: entry.name.split('/')[1], compressed_size: entry.compressed_size, uncompressed_size: entry.uncompressed_size }));
  const signing_entries = zip.entries.filter(entry => /^META-INF\/(?:[^/]+\.(?:RSA|DSA|EC)|MANIFEST\.MF|[^/]+\.SF)$/i.test(entry.name)).map(entry => entry.name);
  return {
    format: 'Android APK', container: { archive_format: 'ZIP', entries: zip.archive.total_entries, zip64: zip.archive.zip64, encrypted_entries: zip.summary.encrypted_entries },
    manifest, dex, dex_file_count: dex.length, class_count: dex.reduce((sum, item) => sum + item.classes.length, 0),
    native_libraries, signing_metadata: { entries: signing_entries, signature_verified: false },
    extraction: { decompressed_bytes: limits.max_total_extract_bytes - budget, remaining_budget: budget, content_executed: false },
    limitations: ['APK signing blocks, v1/v2/v3/v4 cryptographic verification and certificate-chain trust are not verified.', 'DEX method bodies, bytecode instructions, annotations, debug info and control flow are not decoded.', 'DEX SHA-1 signature and Adler32 checksum fields are reported or retained as metadata but are not cryptographically verified.', 'Manifest component intent filters and resource references are not resolved.', 'Only stored and raw-DEFLATE ZIP entries are decompressed; unsupported methods are rejected.', 'Plain-text XML manifest extraction is conservative pattern matching, not a complete XML parser.', 'This is bounded static metadata analysis, not Android runtime behavior or malware classification.'],
  };
}
