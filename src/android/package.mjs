// JavaScript, src/android/package.mjs, Node.js 20+, read-only APK/AAB inventory.
// ZIP contents are never extracted or decompressed; only stored DEX headers are inspected.

import { parse_zip } from '../formats/zip.mjs';
import { parse_dex } from '../formats/dex.mjs';

const LOCAL_HEADER = 0x04034b50;
const BINARY_XML = 0x0003;

function is_decimal(value) {
  if (!value) return false;
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code < 48 || code > 57) return false;
  }
  return true;
}

function is_dex_entry(name) {
  const base = name.slice(name.lastIndexOf('/') + 1);
  if (!base.startsWith('classes') || !base.endsWith('.dex')) return false;
  const ordinal = base.slice(7, -4);
  return ordinal === '' || is_decimal(ordinal);
}

function local_stored_prefix(buffer, entry, minimum) {
  if (!entry.local_header_valid || !entry.local_data_range_valid) return { status: 'invalid-local-range' };
  if (entry.encrypted) return { status: 'encrypted' };
  if (entry.compression_method !== 'stored' || entry.compressed_size !== entry.uncompressed_size) return { status: 'compressed' };
  const offset = entry.local_header_offset;
  if (offset < 0 || offset > buffer.length - 30 || buffer.readUInt32LE(offset) !== LOCAL_HEADER) return { status: 'invalid-local-header' };
  const flags = buffer.readUInt16LE(offset + 6);
  const method = buffer.readUInt16LE(offset + 8);
  const name_length = buffer.readUInt16LE(offset + 26);
  const extra_length = buffer.readUInt16LE(offset + 28);
  if ((flags & 1) !== 0 || method !== 0) return { status: 'local-header-mismatch' };
  const name_start = offset + 30;
  const data_offset = name_start + name_length + extra_length;
  if (name_start > buffer.length - name_length || data_offset > buffer.length || entry.compressed_size > buffer.length - data_offset) {
    return { status: 'invalid-local-range' };
  }
  const local_name = buffer.subarray(name_start, name_start + name_length).toString((flags & 0x0800) !== 0 ? 'utf8' : 'latin1');
  if (local_name !== entry.name || minimum > entry.uncompressed_size || minimum > entry.compressed_size) return { status: 'local-header-mismatch' };
  return { status: 'available', bytes: buffer.subarray(data_offset, data_offset + minimum) };
}

function inspect_manifest(buffer, entry) {
  const prefix = local_stored_prefix(buffer, entry, 8);
  if (prefix.status !== 'available') return { path: entry.name, status: prefix.status, binary_xml: null };
  const bytes = prefix.bytes;
  const type = bytes.readUInt16LE(0);
  const header_size = bytes.readUInt16LE(2);
  const declared_size = bytes.readUInt32LE(4);
  return {
    path: entry.name,
    status: type === BINARY_XML && header_size >= 8 && declared_size >= header_size && declared_size <= entry.uncompressed_size ? 'binary-xml-header' : 'unknown-or-invalid-header',
    binary_xml: type === BINARY_XML,
    chunk_type: '0x' + type.toString(16).padStart(4, '0'),
    header_size,
    declared_size,
  };
}

function is_v1_signature(name) {
  if (!name.startsWith('META-INF/')) return false;
  const base = name.slice(name.lastIndexOf('/') + 1).toUpperCase();
  return base.endsWith('.RSA') || base.endsWith('.DSA') || base.endsWith('.EC') || base.endsWith('.SF') || base === 'MANIFEST.MF';
}

/**
 * Identify APK/AAB ZIP containers and inventory their structural metadata.
 * DEX parsing is limited to fixed headers of stored, unencrypted entries.
 */
export function analyze_android_package(buffer, options = {}) {
  const archive = parse_zip(buffer, options.zip ?? {});
  const entries = archive.entries;
  const names = new Set(entries.map(entry => entry.name));
  const apk_manifest = names.has('AndroidManifest.xml');
  const bundle_manifest = entries.some(entry => entry.name.endsWith('/manifest/AndroidManifest.xml'));
  const is_aab = names.has('BundleConfig.pb') || bundle_manifest;
  const is_apk = apk_manifest && !is_aab;
  const dex_entries = entries.filter(entry => is_dex_entry(entry.name));
  const manifest_entries = entries.filter(entry => entry.name === 'AndroidManifest.xml' || entry.name.endsWith('/manifest/AndroidManifest.xml'));
  const native_libraries = entries.filter(entry => entry.name.startsWith('lib/') && entry.name.endsWith('.so'));
  const signatures = entries.filter(entry => is_v1_signature(entry.name));
  const dex = dex_entries.map(entry => {
    const prefix = local_stored_prefix(buffer, entry, 112);
    if (prefix.status !== 'available') return { path: entry.name, status: prefix.status, uncompressed_size: entry.uncompressed_size };
    try {
      const parsed = parse_dex(prefix.bytes, { header_only: true, declared_size: entry.uncompressed_size });
      return {
        path: entry.name,
        status: 'header-parsed',
        uncompressed_size: entry.uncompressed_size,
        version: parsed.version,
        header: parsed.header,
        notes: parsed.notes,
      };
    } catch (error) {
      return { path: entry.name, status: 'rejected', uncompressed_size: entry.uncompressed_size, error: { code: error.code ?? 'ORIX_DEX_ERROR', message: error.message } };
    }
  });
  return {
    format: is_aab ? 'AAB' : is_apk ? 'APK' : 'Android package candidate',
    detected: is_aab || is_apk || dex_entries.length > 0 || bundle_manifest,
    archive: { entry_count: entries.length, zip64: archive.archive.zip64 },
    summary: {
      dex_entries: dex_entries.length,
      dex_headers_parsed: dex.filter(item => item.status === 'header-parsed').length,
      dex_entries_not_inspected: dex.filter(item => item.status !== 'header-parsed').length,
      native_libraries: native_libraries.length,
      resources_table_present: names.has('resources.arsc') || names.has('base/resources.pb'),
      manifest_entries: manifest_entries.length,
      v1_signature_files: signatures.length,
    },
    manifests: manifest_entries.map(entry => inspect_manifest(buffer, entry)),
    dex,
    native_libraries: native_libraries.map(entry => ({ path: entry.name, compressed_size: entry.compressed_size, uncompressed_size: entry.uncompressed_size })),
    signatures: signatures.map(entry => entry.name),
    limitations: [
      'ZIP entries are inventoried without extraction or decompression; DEX headers are inspected only when the entry is stored, unencrypted and its local header matches the central directory.',
      'AndroidManifest.xml binary XML is identified by its root chunk header only; package names, permissions, components and intent filters are not decoded.',
      'DEX string pools, type/method tables, class definitions, bytecode, resources and native library contents are not decoded.',
      'APK/AAB signing blocks, certificate chains, signatures and publisher identity are not verified; v1 signature filenames are inventory hints only.',
      'This is offline file analysis. No Android device, adb command, app installation, emulator or application code is accessed or executed.',
    ],
    warnings: dex.filter(item => item.status !== 'header-parsed').map(item => ({ path: item.path, reason: item.status })),
  };
}
