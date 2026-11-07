// JavaScript, src/android/package.mjs, Node.js 20+, read-only APK/AAB inventory.
// ZIP contents are never extracted or decompressed; only stored DEX headers are inspected.

import { parse_zip } from '../formats/zip.mjs';
import { parse_dex } from '../formats/dex.mjs';
import { parse_android_binary_xml } from './binary-xml.mjs';
import { constants as fs_constants, promises as fs } from 'node:fs';
import path from 'node:path';
import { hash_buffer } from '../core/hash.mjs';

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

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function local_stored_prefix(buffer, entry, minimum, central_directory_offset) {
  if (!entry.local_header_valid || !entry.local_data_range_valid) return { status: 'invalid-local-range' };
  if (entry.encrypted || entry.strongly_encrypted) return { status: 'encrypted' };
  if (entry.compression_method !== 'stored' || entry.compressed_size !== entry.uncompressed_size) return { status: 'compressed' };
  const offset = entry.local_header_offset;
  if (offset < 0 || offset > buffer.length - 30 || offset > central_directory_offset - 30 || buffer.readUInt32LE(offset) !== LOCAL_HEADER) return { status: 'invalid-local-header' };
  const flags = buffer.readUInt16LE(offset + 6);
  const method = buffer.readUInt16LE(offset + 8);
  const local_crc = buffer.readUInt32LE(offset + 14);
  const local_compressed_size = buffer.readUInt32LE(offset + 18);
  const local_uncompressed_size = buffer.readUInt32LE(offset + 22);
  const expected_flags = (entry.encrypted ? 1 : 0) | (entry.data_descriptor ? 8 : 0) | (entry.utf8_name ? 0x0800 : 0);
  const central_crc = Number.parseInt(entry.crc32, 16);
  const descriptor_mismatch = entry.data_descriptor
    ? (local_crc !== 0 && local_crc !== central_crc) ||
      (local_compressed_size !== 0 && local_compressed_size !== entry.compressed_size) ||
      (local_uncompressed_size !== 0 && local_uncompressed_size !== entry.uncompressed_size)
    : local_crc !== central_crc || local_compressed_size !== entry.compressed_size ||
      local_uncompressed_size !== entry.uncompressed_size;
  const name_length = buffer.readUInt16LE(offset + 26);
  const extra_length = buffer.readUInt16LE(offset + 28);
  if (flags !== expected_flags || method !== 0 || descriptor_mismatch) return { status: 'local-header-mismatch' };
  const name_start = offset + 30;
  const data_offset = name_start + name_length + extra_length;
  if (name_start > buffer.length - name_length || data_offset > central_directory_offset || entry.compressed_size > central_directory_offset - data_offset) {
    return { status: 'invalid-local-range' };
  }
  const local_name = buffer.subarray(name_start, name_start + name_length).toString((flags & 0x0800) !== 0 ? 'utf8' : 'latin1');
  if (local_name !== entry.name || minimum !== entry.uncompressed_size || minimum > entry.compressed_size) return { status: 'local-header-mismatch' };
  const bytes = buffer.subarray(data_offset, data_offset + minimum);
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
  const data = local_stored_prefix(buffer, entry, entry.uncompressed_size, central_directory_offset);
  if (data.status !== 'available') return { path: entry.name, status: data.status, binary_xml: null };
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
  if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Android package options must be an object');
  const max_dex_entries = options.max_dex_entries ?? 64;
  const max_dex_entry_bytes = options.max_dex_entry_bytes ?? 134_217_728;
  const max_dex_total_bytes = options.max_dex_total_bytes ?? 268_435_456;
  const max_dex_output_items = options.max_dex_output_items ?? 1000;
  const max_archive_entries = options.max_archive_entries ?? 1000;
  const max_archive_entry_path_length = options.max_archive_entry_path_length ?? 512;
  if (!Number.isSafeInteger(max_dex_entries) || max_dex_entries < 1 || max_dex_entries > 256) throw new TypeError('max_dex_entries must be between 1 and 256');
  if (!Number.isSafeInteger(max_dex_entry_bytes) || max_dex_entry_bytes < 112 || max_dex_entry_bytes > 536_870_912) throw new TypeError('max_dex_entry_bytes must be between 112 and 536870912');
  if (!Number.isSafeInteger(max_dex_total_bytes) || max_dex_total_bytes < 112 || max_dex_total_bytes > 1_073_741_824) throw new TypeError('max_dex_total_bytes must be between 112 and 1073741824');
  if (!Number.isSafeInteger(max_dex_output_items) || max_dex_output_items < 1 || max_dex_output_items > 10_000) throw new TypeError('max_dex_output_items must be between 1 and 10000');
  if (!Number.isSafeInteger(max_archive_entries) || max_archive_entries < 1 || max_archive_entries > 50_000) throw new TypeError('max_archive_entries must be between 1 and 50000');
  if (!Number.isSafeInteger(max_archive_entry_path_length) || max_archive_entry_path_length < 16 || max_archive_entry_path_length > 4096) throw new TypeError('max_archive_entry_path_length must be between 16 and 4096');
  const archive = parse_zip(buffer, options.zip ?? {});
  const entries = archive.entries.filter(entry => !entry.unsafe_path && !entry.is_symlink);
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
  const is_aab = names.has('BundleConfig.pb') || bundle_manifest;
  const is_apk = apk_manifest && !is_aab;
  const dex_entries = entries.filter(entry => is_dex_entry(entry.name));
  const manifest_entries = entries.filter(entry => entry.name === 'AndroidManifest.xml' || entry.name.endsWith('/manifest/AndroidManifest.xml'));
  const reported_manifest_entries = manifest_entries.slice(0, max_archive_entries);
  const native_libraries = entries.filter(entry => (entry.name.startsWith('lib/') || entry.name.includes('/lib/')) && entry.name.endsWith('.so'));
  const reported_native_libraries = native_libraries.slice(0, max_archive_entries);
  const signatures = entries.filter(entry => is_v1_signature(entry.name));
  const reported_signatures = signatures.slice(0, max_archive_entries);
  let dex_bytes_parsed = 0;
  const reported_dex_entries = dex_entries.slice(0, max_archive_entries);
  const dex = reported_dex_entries.map((entry, index) => {
    const path = entry.name.slice(0, max_archive_entry_path_length);
    const path_truncated = entry.name.length > max_archive_entry_path_length;
    const path_original_length = entry.name.length;
    if (index >= max_dex_entries) return { path, path_truncated, path_original_length, status: 'entry-limit', uncompressed_size: entry.uncompressed_size };
    if (entry.uncompressed_size > max_dex_entry_bytes) return { path, path_truncated, path_original_length, status: 'entry-size-limit', uncompressed_size: entry.uncompressed_size };
    if (dex_bytes_parsed + entry.uncompressed_size > max_dex_total_bytes) return { path, path_truncated, path_original_length, status: 'aggregate-size-limit', uncompressed_size: entry.uncompressed_size };
    const data = local_stored_prefix(buffer, entry, entry.uncompressed_size, archive.archive.central_directory_offset);
    if (data.status !== 'available') return { path, path_truncated, path_original_length, status: data.status, uncompressed_size: entry.uncompressed_size };
    dex_bytes_parsed += entry.uncompressed_size;
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
        classes: parsed.classes,
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
      native_libraries: native_libraries.length,
      native_libraries_reported: reported_native_libraries.length,
      native_libraries_omitted: Math.max(0, native_libraries.length - reported_native_libraries.length),
      resources_table_present: names.has('resources.arsc') || names.has('base/resources.pb'),
      manifest_entries: manifest_entries.length,
      manifest_entries_reported: reported_manifest_entries.length,
      manifest_entries_omitted: Math.max(0, manifest_entries.length - reported_manifest_entries.length),
      v1_signature_files: signatures.length,
      v1_signature_files_reported: reported_signatures.length,
      v1_signature_files_omitted: Math.max(0, signatures.length - reported_signatures.length),
    },
    manifests: reported_manifest_entries.map(entry => ({
      ...inspect_manifest(buffer, entry, archive.archive.central_directory_offset, options),
      path: entry.name.slice(0, max_archive_entry_path_length),
      path_truncated: entry.name.length > max_archive_entry_path_length,
      path_original_length: entry.name.length,
    })),
    dex,
    native_libraries: reported_native_libraries.map(entry => ({
      path: entry.name.slice(0, max_archive_entry_path_length),
      path_truncated: entry.name.length > max_archive_entry_path_length,
      path_original_length: entry.name.length,
      compressed_size: entry.compressed_size,
      uncompressed_size: entry.uncompressed_size,
    })),
    signatures: reported_signatures.map(entry => entry.name.slice(0, max_archive_entry_path_length)),
    limitations: [
      'ZIP entries are inventoried without extraction or decompression; DEX metadata is inspected only when the entry is stored, unencrypted and its local header matches the central directory.',
      'APK binary XML manifests are decoded within explicit chunk/string/element/attribute limits; AAB protobuf manifests and resource-reference resolution are not decoded.',
      'DEX string pools, type/method tables, class definitions, bytecode, resources and native library contents are not decoded.',
      'APK/AAB signing blocks, certificate chains, signatures and publisher identity are not verified; v1 signature filenames are inventory hints only.',
      'This is offline file analysis. No Android device, adb command, app installation, emulator or application code is accessed or executed.',
    ],
    warnings: dex.filter(item => item.status !== 'metadata-parsed').map(item => ({ path: item.path, reason: item.status })),
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
      if (item.application) lines.push('  - Application: debuggable=' + markdown_cell(item.application.debuggable ?? 'unspecified') +
        ', allowBackup=' + markdown_cell(item.application.allowBackup ?? 'unspecified') +
        ', cleartext=' + markdown_cell(item.application.usesCleartextTraffic ?? 'unspecified'));
      lines.push('  - Permissions: ' + (item.permissions?.length ? item.permissions.map(value => markdown_cell(value.name)).join(', ') : 'none reported'));
      lines.push('  - Components: ' + (item.components?.length ? item.components.map(value =>
        markdown_cell(value.type + ' ' + (value.name ?? 'unnamed') + ' exported=' + (value.exported ?? 'unspecified'))).join('; ') : 'none reported'));
      if (item.output_truncated) lines.push('  - Output was truncated by configured limits.');
    }
  }
  lines.push('', '## Native libraries', '');
  if (report.native_libraries.length === 0) lines.push('No native library paths were reported.');
  for (const item of report.native_libraries) {
    const entry_path = item.path + (item.path_truncated ? '… (' + item.path_original_length + ' chars total)' : '');
    lines.push('- ' + markdown_cell(entry_path) + ' (' + item.uncompressed_size + ' bytes)');
  }
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
