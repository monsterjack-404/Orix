// JavaScript, src/core/inspect.mjs, Node.js 20+, bounded read-only artifact inspection.

import { constants as FS_CONSTANTS, promises as fs } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { DEFAULT_LIMITS, resolve_limits } from './limits.mjs';
import { calculate_entropy } from './entropy.mjs';
import { extract_strings } from './strings.mjs';
import { analyze_known_format } from '../formats/index.mjs';
import { create_evidence } from './evidence.mjs';
import { OrixError } from './errors.mjs';
import { evaluate_indicators } from '../analyzer/indicators.mjs';

async function hash_file_handle(handle, file_size) {
  const hash = createHash('sha256');
  const chunk = Buffer.allocUnsafe(1024 * 1024);
  let position = 0;
  while (position < file_size) {
    const length = Math.min(chunk.length, file_size - position);
    const { bytesRead } = await handle.read(chunk, 0, length, position);
    if (bytesRead === 0) throw new OrixError('ORIX_FILE_CHANGED', 'File ended while hashing; the artifact may have changed during inspection', { details: { position, file_size }, recoverable: true });
    hash.update(chunk.subarray(0, bytesRead));
    position += bytesRead;
  }
  return hash.digest('hex');
}

function stat_fingerprint(stats) {
  return { size: stats.size, mtime_ms: stats.mtimeMs, ctime_ms: stats.ctimeMs, ino: String(stats.ino), dev: String(stats.dev) };
}

export async function inspect_file(file_path, options = {}) {
  if (typeof file_path !== 'string' || file_path.length === 0) throw new TypeError('file_path must be a non-empty string');
  const limits = resolve_limits(options.limits);
  const absolute_path = path.resolve(file_path);
  let before;
  try {
    before = await fs.lstat(absolute_path);
  } catch (error) {
    throw new OrixError('ORIX_FILE_UNAVAILABLE', `Cannot access file: ${absolute_path}`, { cause: error, details: { path: absolute_path, system_code: error.code }, recoverable: true });
  }
  if (before.isSymbolicLink()) throw new OrixError('ORIX_SYMLINK_REJECTED', 'Symbolic links are not followed by the inspector', { details: { path: absolute_path }, recoverable: true });
  if (!before.isFile()) throw new OrixError('ORIX_NOT_REGULAR_FILE', 'Only regular files can be inspected', { details: { path: absolute_path }, recoverable: true });
  if (!Number.isSafeInteger(before.size)) throw new OrixError('ORIX_FILE_SIZE_UNSAFE', 'File size cannot be represented safely', { recoverable: true });
  if (before.size > limits.max_file_bytes) {
    throw new OrixError('ORIX_FILE_TOO_LARGE', 'File exceeds the configured inspection size limit', {
      details: { size: before.size, max_file_bytes: limits.max_file_bytes }, recoverable: true,
    });
  }

  const no_follow = FS_CONSTANTS.O_NOFOLLOW ?? 0;
  let handle;
  try {
    try {
      handle = await fs.open(absolute_path, FS_CONSTANTS.O_RDONLY | no_follow);
    } catch (error) {
      throw new OrixError('ORIX_FILE_UNAVAILABLE', `Cannot open file: ${absolute_path}`, {
        cause: error,
        details: { path: absolute_path, system_code: error.code ?? null },
        recoverable: true,
      });
    }
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== before.size || String(opened.ino) !== String(before.ino) || String(opened.dev) !== String(before.dev)) {
      throw new OrixError('ORIX_FILE_REPLACED', 'File identity changed between metadata lookup and open', { recoverable: true });
    }

    const read_length = Math.min(opened.size, limits.max_read_bytes);
    const sample = Buffer.alloc(read_length);
    let sample_read = 0;
    while (sample_read < read_length) {
      const { bytesRead } = await handle.read(sample, sample_read, read_length - sample_read, sample_read);
      if (bytesRead === 0) break;
      sample_read += bytesRead;
    }
    const bytes = sample.subarray(0, sample_read);
    const sha256 = await hash_file_handle(handle, opened.size);
    const after = await handle.stat();
    const stable_during_read = opened.size === after.size && opened.mtimeMs === after.mtimeMs && opened.ctimeMs === after.ctimeMs;
    const analyzed = analyze_known_format(bytes, { file_size: opened.size, max_sections: limits.max_sections, max_commands: limits.max_sections, max_wasm_sections: limits.max_wasm_sections });
    const strings = options.extract_strings === false ? [] : extract_strings(bytes, {
      minimum: limits.min_string_length,
      maximum: limits.max_string_length,
      limit: limits.max_strings,
    });
    const entropy = calculate_entropy(bytes);
    const preview_length = Math.min(bytes.length, limits.max_hex_preview_bytes);
    const evidence = [
      create_evidence({ kind: 'file-hash', summary: 'SHA-256 calculated from the complete file contents', source: absolute_path, confidence: 'observed', details: { algorithm: 'sha256', value: sha256, bytes_hashed: opened.size } }),
      create_evidence({ kind: 'format-detection', summary: `${analyzed.detection.format} selected by leading-byte signature`, source: absolute_path, offset: 0, length: Math.min(16, bytes.length), confidence: analyzed.detection.confidence === 'signature' ? 'observed' : 'heuristic', details: { format: analyzed.detection.format, parser_status: analyzed.parser_status } }),
    ];
    if (analyzed.parser_status === 'parsed') {
      evidence.push(create_evidence({ kind: 'format-structure', summary: `${analyzed.detection.format} header structures parsed with bounds checks`, source: absolute_path, offset: 0, length: bytes.length, confidence: 'derived', details: { top_level_keys: Object.keys(analyzed.parsed) } }));
    }
    const indicators = evaluate_indicators({
      format: analyzed.detection.format,
      parser_status: analyzed.parser_status,
      parsed: analyzed.parsed,
      parser_error: analyzed.parser_error,
      entropy,
      strings,
      stable_during_read,
    });
    return {
      schema_version: 'orix.artifact.v1',
      artifact: {
        path: absolute_path,
        name: path.basename(absolute_path),
        extension: path.extname(absolute_path).toLowerCase(),
        size_bytes: opened.size,
        modified_at: opened.mtime.toISOString(),
        readable_bytes: bytes.length,
        analysis_complete_for_file: bytes.length === opened.size,
      },
      integrity: { algorithm: 'sha256', digest: sha256, stable_during_read },
      detection: analyzed.detection,
      parser: { status: analyzed.parser_status, result: analyzed.parsed, error: analyzed.parser_error ?? null },
      metrics: {
        entropy: { ...entropy, scope: bytes.length === opened.size ? 'complete-file' : 'prefix-sample' },
        strings: { count: strings.length, at_limit: limits.max_strings > 0 && strings.length === limits.max_strings, values: strings },
        hex_preview: bytes.subarray(0, preview_length).toString('hex').match(/.{1,2}/g)?.join(' ') ?? '',
        hex_preview_bytes: preview_length,
      },
      evidence,
      indicators,
      warnings: [
        ...(bytes.length < opened.size ? [`Only the first ${bytes.length} bytes were parsed; file size is ${opened.size} bytes.`] : []),
        ...(!stable_during_read ? ['File metadata changed while it was inspected; repeat the analysis against a stable copy.'] : []),
        ...(analyzed.parser_error ? [`Parser rejected the structure: ${analyzed.parser_error.code}.`] : []),
      ],
      limits: { max_file_bytes: limits.max_file_bytes, max_read_bytes: limits.max_read_bytes },
    };
  } finally {
    await handle?.close();
  }
}

export const INSPECTOR_DEFAULTS = DEFAULT_LIMITS;
