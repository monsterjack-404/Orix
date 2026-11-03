// JavaScript, src/providers/rizin.mjs, Node.js 20+, read-only Rizin import metadata adapter.

import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, realpath, stat } from 'node:fs/promises';
import { OrixError } from '../core/errors.mjs';
import { validate_provider_manifest } from './manifest.mjs';
import { run_static_provider } from './process-runner.mjs';

export const RIZIN_ADAPTER_VERSION = '0.1.0';

export const RIZIN_PROVIDER_MANIFEST = Object.freeze({
  contract_version: 'orix.provider.v1',
  id: 'rizin.static',
  name: 'Rizin static binary imports',
  version: RIZIN_ADAPTER_VERSION,
  description: 'Read-only extraction of native binary import metadata through the Rizin CLI.',
  capabilities: Object.freeze(['binary.imports']),
  supported_platforms: Object.freeze(['linux', 'windows', 'macos']),
  input_formats: Object.freeze(['pe', 'elf', 'macho']),
  execution: Object.freeze({
    mode: 'static',
    requires_authorization: false,
    executes_target: false,
    writes_target: false,
    uses_network: false,
  }),
  limits: Object.freeze({
    timeout_ms: 60_000,
    max_input_bytes: 536_870_912,
    max_output_bytes: 8_388_608,
  }),
  license: Object.freeze({
    spdx_id: 'Apache-2.0',
    redistribution: 'external-install',
    source_url: 'https://github.com/rizinorg/rizin',
  }),
  documentation_url: 'https://book.rizin.re/',
});

function provider_error(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function validate_input_path(input_path) {
  if (typeof input_path !== 'string' || input_path.trim() === '' ||
      input_path.includes('\0') || !require_path_is_absolute(input_path)) {
    throw new TypeError('input_path must be a non-empty absolute filesystem path');
  }
}

function require_path_is_absolute(value) {
  // Kept separate so platform-specific absolute-path rules remain centralized in path.
  return import_path_is_absolute(value);
}

import path from 'node:path';

function import_path_is_absolute(value) {
  return path.isAbsolute(value);
}

async function file_snapshot(input_path, maximum_bytes) {
  let link_info;
  try { link_info = await lstat(input_path); }
  catch (error) {
    provider_error('ORIX_RIZIN_INPUT_UNAVAILABLE', 'Rizin input file cannot be inspected', {
      reason: error.code ?? 'filesystem-error',
    });
  }
  if (link_info.isSymbolicLink() || !link_info.isFile()) {
    provider_error('ORIX_RIZIN_INPUT_NOT_REGULAR', 'Rizin input must be a regular non-symlink file');
  }
  const canonical_path = await realpath(input_path);
  const info = await stat(canonical_path);
  if (!info.isFile()) provider_error('ORIX_RIZIN_INPUT_NOT_REGULAR', 'Resolved Rizin input is not a regular file');
  if (!Number.isSafeInteger(info.size) || info.size < 0 || info.size > maximum_bytes) {
    provider_error('ORIX_RIZIN_INPUT_TOO_LARGE', 'Rizin input exceeds the provider manifest byte limit', {
      size_bytes: info.size, maximum_bytes,
    });
  }
  return { canonical_path, info };
}

function same_file_identity(left, right) {
  return left.dev === right.dev && left.ino === right.ino &&
    left.size === right.size && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

async function sha256_file(file_path) {
  const hash = createHash('sha256');
  try {
    for await (const chunk of createReadStream(file_path)) hash.update(chunk);
  } catch (error) {
    provider_error('ORIX_RIZIN_INPUT_READ_FAILED', 'Rizin input could not be hashed before analysis', {
      reason: error.code ?? 'read-error',
    });
  }
  return hash.digest('hex');
}

function parse_engine_version(output) {
  const match = /(?:^|\s)v?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)(?:\s|$)/m.exec(output);
  if (!match) {
    provider_error('ORIX_RIZIN_VERSION_UNKNOWN', 'Rizin version output did not contain a semantic version');
  }
  return match[1];
}

function bounded_text(value, maximum = 512) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum || value.includes('\0')) return null;
  return value;
}

function normalize_imports(source, maximum) {
  let parsed;
  try { parsed = JSON.parse(source); }
  catch {
    provider_error('ORIX_RIZIN_IMPORT_JSON_INVALID', 'Rizin import command did not return valid JSON');
  }
  if (!Array.isArray(parsed)) {
    provider_error('ORIX_RIZIN_IMPORT_SHAPE_INVALID', 'Rizin import JSON must be an array');
  }
  if (parsed.length > maximum) {
    provider_error('ORIX_RIZIN_IMPORT_LIMIT', 'Rizin import count exceeds the configured result limit', {
      count: parsed.length, maximum,
    });
  }
  return parsed.map((entry, index) => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry) ||
        Object.getPrototypeOf(entry) !== Object.prototype) {
      provider_error('ORIX_RIZIN_IMPORT_ENTRY_INVALID', 'Rizin import entry must be an object', { index });
    }
    const ordinal = Number.isSafeInteger(entry.ordinal) && entry.ordinal >= 0 ? entry.ordinal : null;
    const plt = Number.isSafeInteger(entry.plt) && entry.plt >= 0
      ? entry.plt
      : bounded_text(entry.plt, 64);
    return {
      name: bounded_text(entry.name),
      library: bounded_text(entry.libname) ?? bounded_text(entry.library),
      ordinal,
      bind: bounded_text(entry.bind, 64),
      type: bounded_text(entry.type, 64),
      plt,
    };
  });
}

/**
 * Invoke Rizin's documented CLI import-JSON command without shell evaluation.
 * The input is hashed before analysis and checked for identity/metadata changes
 * before the result is accepted.
 */
export async function analyze_rizin_imports(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Rizin adapter options must be an object');
  }
  const allowed = new Set([
    'executable', 'input_path', 'manifest', 'cwd', 'env',
    'timeout_ms', 'max_output_bytes', 'max_imports', 'signal',
  ]);
  const descriptors = Object.getOwnPropertyDescriptors(options);
  for (const key of Reflect.ownKeys(options)) {
    if (typeof key !== 'string' || !allowed.has(key) ||
        !descriptors[key] || !Object.hasOwn(descriptors[key], 'value') || !descriptors[key].enumerable) {
      throw new TypeError('Rizin adapter options must use known enumerable data properties');
    }
  }

  const manifest = validate_provider_manifest(descriptors.manifest?.value ?? RIZIN_PROVIDER_MANIFEST);
  if (manifest.id !== 'rizin.static') {
    throw new TypeError('Rizin adapter requires the rizin.static provider manifest');
  }
  const input_path = descriptors.input_path?.value;
  validate_input_path(input_path);
  const maximum_bytes = manifest.limits.max_input_bytes;
  const before = await file_snapshot(input_path, maximum_bytes);
  const input_sha256 = await sha256_file(before.canonical_path);
  const common = {
    manifest,
    executable: descriptors.executable?.value,
    cwd: descriptors.cwd?.value,
    env: descriptors.env?.value,
    timeout_ms: descriptors.timeout_ms?.value,
    max_output_bytes: descriptors.max_output_bytes?.value,
    signal: descriptors.signal?.value,
  };

  const version_result = await run_static_provider({
    ...common,
    args: ['-v'],
    max_output_bytes: Math.min(common.max_output_bytes ?? manifest.limits.max_output_bytes, 16_384),
  });
  if (!version_result.ok) {
    provider_error('ORIX_RIZIN_VERSION_FAILED', 'Rizin version probe failed', {
      exit_code: version_result.exit_code,
      timed_out: version_result.timed_out,
      cancelled: version_result.cancelled,
      stderr: version_result.stderr.slice(0, 1024),
    });
  }
  const engine_version = parse_engine_version(version_result.stdout);

  const import_result = await run_static_provider({
    ...common,
    args: ['-N', '-q', '-c', 'iij', before.canonical_path],
  });
  if (!import_result.ok) {
    provider_error('ORIX_RIZIN_IMPORT_FAILED', 'Rizin import extraction did not complete successfully', {
      exit_code: import_result.exit_code,
      timed_out: import_result.timed_out,
      cancelled: import_result.cancelled,
      output_limited: import_result.output_limited,
      stderr: import_result.stderr.slice(0, 1024),
    });
  }

  const after_link = await lstat(input_path);
  const after = await stat(before.canonical_path);
  const after_realpath = await realpath(input_path);
  const stable = !after_link.isSymbolicLink() && after_link.isFile() &&
    after_realpath === before.canonical_path && same_file_identity(before.info, after);
  if (!stable) {
    provider_error('ORIX_RIZIN_INPUT_CHANGED', 'Rizin input identity or metadata changed during analysis', {
      input_path: before.canonical_path,
    });
  }

  const max_imports = descriptors.max_imports?.value ?? 100_000;
  if (!Number.isSafeInteger(max_imports) || max_imports < 0 || max_imports > 1_000_000) {
    throw new TypeError('max_imports must be an integer between 0 and 1000000');
  }
  const imports = normalize_imports(import_result.stdout, max_imports);
  return {
    schema_version: 'orix.rizin-imports.v1',
    provider: {
      id: manifest.id,
      adapter_version: RIZIN_ADAPTER_VERSION,
      engine_version,
      executable: version_result.executable,
    },
    artifact: {
      path: before.canonical_path,
      size_bytes: before.info.size,
      sha256: input_sha256,
      stable_during_analysis: true,
    },
    imports,
    summary: {
      imports: imports.length,
      libraries: new Set(imports.map(item => item.library).filter(Boolean)).size,
    },
    diagnostics: {
      version_probe_duration_ms: version_result.duration_ms,
      import_scan_duration_ms: import_result.duration_ms,
      stderr: import_result.stderr.slice(0, 1024),
    },
    notes: [
      'Uses Rizin -N -q -c iij for static import metadata; the target is not executed.',
      'Rizin remains an optional external installation and is not bundled by ORIX.',
      'The process runner bounds runtime and captured output but is not an OS sandbox.',
    ],
  };
}
