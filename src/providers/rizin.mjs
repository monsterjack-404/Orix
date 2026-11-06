// JavaScript, src/providers/rizin.mjs, Node.js 20+, read-only Rizin import metadata adapter.

import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import path from 'node:path';
import { chmod, lstat, realpath, rm, stat } from 'node:fs/promises';
import { OrixError } from '../core/errors.mjs';
import { validate_provider_manifest } from './manifest.mjs';
import { run_static_provider } from './process-runner.mjs';
import { create_rizin_snapshot_directory } from './rizin-snapshot.mjs';

export const RIZIN_ADAPTER_VERSION = '0.2.0';

export const RIZIN_PROVIDER_MANIFEST = Object.freeze({
  contract_version: 'orix.provider.v1',
  id: 'rizin.static',
  name: 'Rizin static binary analysis',
  version: RIZIN_ADAPTER_VERSION,
  description: 'Read-only extraction of native imports, function metadata, bounded disassembly and opt-in plugin-backed pseudocode through the Rizin CLI.',
  capabilities: Object.freeze(['binary.imports', 'binary.functions', 'binary.disassembly', 'binary.decompilation']),
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
    spdx_id: 'NOASSERTION',
    redistribution: 'external-install',
    source_url: 'https://github.com/rizinorg/rizin',
  }),
  documentation_url: 'https://book.rizin.re/',
});

function provider_error(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function assert_rizin_platform(manifest) {
  const platform = process.platform === 'win32'
    ? 'windows'
    : process.platform === 'darwin' ? 'macos' : process.platform;
  if (!manifest.supported_platforms.includes(platform)) {
    provider_error('ORIX_RIZIN_PLATFORM_UNSUPPORTED', 'Rizin provider manifest does not support this runtime platform', {
      platform,
      supported_platforms: manifest.supported_platforms,
    });
  }
}

function validate_input_path(input_path) {
  if (typeof input_path !== 'string' || input_path.trim() === '' ||
      input_path.includes('\0') || !path.isAbsolute(input_path)) {
    throw new TypeError('input_path must be a non-empty absolute filesystem path');
  }
}


async function requested_isolation(value) {
  const isolation = value ?? 'none';
  if (isolation !== 'none' && isolation !== 'required') {
    throw new TypeError('isolation must be either none or required');
  }
  if (isolation === 'required' && process.platform !== 'linux') {
    provider_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE',
      'Required provider isolation currently has no enforced backend for this operating system',
      { platform: process.platform });
  }
  return isolation;
}

function file_snapshot(input_path, maximum_bytes) {
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

async function sha256_file(file_path, maximum_bytes, signal) {
  const hash = createHash('sha256');
  let bytes_read = 0;
  try {
    for await (const chunk of createReadStream(file_path, { signal })) {
      bytes_read += chunk.length;
      if (bytes_read > maximum_bytes) {
        provider_error('ORIX_RIZIN_INPUT_TOO_LARGE', 'Rizin input grew beyond its manifest byte limit while hashing', {
          bytes_read, maximum_bytes,
        });
      }
      hash.update(chunk);
    }
  } catch (error) {
    if (error instanceof OrixError) throw error;
    if (signal?.aborted) provider_error('ORIX_RIZIN_CANCELLED', 'Rizin analysis was cancelled while hashing its input');
    provider_error('ORIX_RIZIN_INPUT_READ_FAILED', 'Rizin input could not be hashed before analysis', {
      reason: error.code ?? 'read-error',
    });
  }
  return { digest: hash.digest('hex'), bytes_read };
}

async function copy_file_bounded(source, destination, maximum_bytes, signal) {
  let bytes_copied = 0;
  const limiter = new Transform({
    transform(chunk, encoding, callback) {
      bytes_copied += chunk.length;
      if (bytes_copied > maximum_bytes) {
        callback(new OrixError('ORIX_RIZIN_INPUT_TOO_LARGE', 'Rizin input grew beyond its manifest byte limit while creating the private snapshot', {
          details: { bytes_copied, maximum_bytes },
          recoverable: true,
        }));
        return;
      }
      callback(null, chunk);
    },
  });
  try {
    await pipeline(
      createReadStream(source, { signal }),
      limiter,
      createWriteStream(destination, { flags: 'wx', mode: 0o400 }),
      { signal },
    );
  } catch (error) {
    if (error instanceof OrixError) throw error;
    if (signal?.aborted) {
      provider_error('ORIX_RIZIN_CANCELLED', 'Rizin analysis was cancelled while creating its private input snapshot');
    }
    provider_error('ORIX_RIZIN_SNAPSHOT_CREATE_FAILED', 'A bounded private Rizin input snapshot could not be created', {
      reason: error.code ?? 'snapshot-error',
    });
  }
  return bytes_copied;
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
    'executable', 'executable_args', 'input_path', 'manifest', 'cwd', 'env',
    'timeout_ms', 'max_output_bytes', 'max_imports', 'signal', 'isolation', 'sandbox_root',
  ]);
  const descriptors = Object.getOwnPropertyDescriptors(options);
  for (const key of Reflect.ownKeys(options)) {
    if (typeof key !== 'string' || !allowed.has(key) ||
        !descriptors[key] || !Object.hasOwn(descriptors[key], 'value') || !descriptors[key].enumerable) {
      throw new TypeError('Rizin adapter options must use known enumerable data properties');
    }
  }

  const isolation = requested_isolation(descriptors.isolation?.value);
  const manifest = validate_provider_manifest(descriptors.manifest?.value ?? RIZIN_PROVIDER_MANIFEST);
  if (manifest.id !== 'rizin.static') {
    throw new TypeError('Rizin adapter requires the rizin.static provider manifest');
  }
  assert_rizin_platform(manifest);
  const input_path = descriptors.input_path?.value;
  validate_input_path(input_path);
  const signal = descriptors.signal?.value;
  if (signal !== undefined && !(signal instanceof AbortSignal)) {
    throw new TypeError('signal must be an AbortSignal');
  }
  if (signal?.aborted) provider_error('ORIX_RIZIN_CANCELLED', 'Rizin analysis was cancelled before input acquisition');
  const maximum_bytes = manifest.limits.max_input_bytes;
  const timeout_ms = descriptors.timeout_ms?.value ?? manifest.limits.timeout_ms;
  const max_output_bytes = descriptors.max_output_bytes?.value ?? manifest.limits.max_output_bytes;
  if (!Number.isSafeInteger(timeout_ms) || timeout_ms < 1 || timeout_ms > manifest.limits.timeout_ms) {
    throw new TypeError('timeout_ms must be between 1 and the provider manifest timeout limit');
  }
  if (!Number.isSafeInteger(max_output_bytes) || max_output_bytes < 1 ||
      max_output_bytes > manifest.limits.max_output_bytes) {
    throw new TypeError('max_output_bytes must be between 1 and the provider manifest output limit');
  }
  const analysis_started_at = Date.now();
  const before = await file_snapshot(input_path, maximum_bytes);
  const maximum_imports = descriptors.max_imports?.value ?? 100_000;
  if (!Number.isSafeInteger(maximum_imports) || maximum_imports < 0 || maximum_imports > 1_000_000) {
    throw new TypeError('max_imports must be an integer between 0 and 1000000');
  }
  if (signal?.aborted) provider_error('ORIX_RIZIN_CANCELLED', 'Rizin analysis was cancelled before input hashing');
  const input_hash = await sha256_file(before.canonical_path, maximum_bytes, signal);
  if (input_hash.bytes_read !== before.info.size) {
    provider_error('ORIX_RIZIN_INPUT_CHANGED', 'Rizin input size changed while it was hashed', {
      expected_size_bytes: before.info.size, actual_size_bytes: input_hash.bytes_read,
    });
  }
  // Analyze a private copy so the external tool never receives the caller's original path.
  // The copy is private to this process, read-only by default, and checked before and after use.
  const snapshot_directory = await create_rizin_snapshot_directory('.orix-rizin-', {
    isolation: isolation,
    sandbox_root: descriptors.sandbox_root?.value,
  });
  const extension = path.extname(before.canonical_path).slice(0, 16);
  const snapshot_path = path.join(snapshot_directory, 'artifact' + extension);
  try {
    const snapshot_bytes = await copy_file_bounded(before.canonical_path, snapshot_path, maximum_bytes, signal);
    if (snapshot_bytes !== input_hash.bytes_read) {
      provider_error('ORIX_RIZIN_INPUT_CHANGED', 'Rizin input size changed while its private analysis snapshot was created', {
        expected_size_bytes: input_hash.bytes_read, actual_size_bytes: snapshot_bytes,
      });
    }
    await chmod(snapshot_path, 0o400);
    const snapshot_hash = await sha256_file(snapshot_path, maximum_bytes, signal);
    if (snapshot_hash.digest !== input_hash.digest || snapshot_hash.bytes_read !== input_hash.bytes_read) {
      provider_error('ORIX_RIZIN_INPUT_CHANGED', 'Rizin input changed while its private analysis snapshot was created', {
        input_path: before.canonical_path,
      });
    }

    const common = {
      manifest,
      executable: descriptors.executable?.value,
      executable_args: descriptors.executable_args?.value,
      cwd: descriptors.cwd?.value,
      env: descriptors.env?.value,
      timeout_ms,
      max_output_bytes,
      signal,
      isolation: isolation,
      sandbox_root: descriptors.sandbox_root?.value,
    };

    const remaining_before_probe = timeout_ms - (Date.now() - analysis_started_at);
    if (remaining_before_probe < 1) {
      provider_error('ORIX_RIZIN_TIMEOUT', 'Rizin analysis exceeded the total provider deadline before version probing', {
        timeout_ms,
      });
    }
    const version_result = await run_static_provider({
      ...common,
      timeout_ms: remaining_before_probe,
      args: ['-v'],
      max_output_bytes: Math.min(common.max_output_bytes ?? manifest.limits.max_output_bytes, 16_384),
    });
    if (!version_result.ok) {
      const code = version_result.cancelled
        ? 'ORIX_RIZIN_CANCELLED'
        : version_result.timed_out ? 'ORIX_RIZIN_TIMEOUT' : 'ORIX_RIZIN_VERSION_FAILED';
      provider_error(code, 'Rizin version probe did not complete successfully', {
        exit_code: version_result.exit_code,
        timed_out: version_result.timed_out,
        cancelled: version_result.cancelled,
        stderr: version_result.stderr.slice(0, 1024),
      });
    }
    const engine_version = parse_engine_version(version_result.stdout);
    const remaining_timeout_ms = timeout_ms - (Date.now() - analysis_started_at);
    if (remaining_timeout_ms < 1) {
      provider_error('ORIX_RIZIN_TIMEOUT', 'Rizin analysis exceeded the total provider deadline', {
        timeout_ms,
      });
    }

    const import_result = await run_static_provider({
      ...common,
      timeout_ms: remaining_timeout_ms,
      args: ['-N', '-q', '-c', 'iij', snapshot_path],
    });
    if (!import_result.ok) {
      const code = import_result.cancelled
        ? 'ORIX_RIZIN_CANCELLED'
        : import_result.timed_out ? 'ORIX_RIZIN_TIMEOUT' : 'ORIX_RIZIN_IMPORT_FAILED';
      provider_error(code, 'Rizin import extraction did not complete successfully', {
        exit_code: import_result.exit_code,
        timed_out: import_result.timed_out,
        cancelled: import_result.cancelled,
        output_limited: import_result.output_limited,
        stderr: import_result.stderr.slice(0, 1024),
      });
    }

    let after_link;
    let after;
    let after_realpath;
    try {
      after_link = await lstat(input_path);
      after = await stat(before.canonical_path);
      after_realpath = await realpath(input_path);
    } catch (error) {
      provider_error('ORIX_RIZIN_INPUT_CHANGED', 'Rizin input disappeared or became inaccessible during analysis', {
        input_path: before.canonical_path, reason: error.code ?? 'filesystem-error',
      });
    }
    const stable = !after_link.isSymbolicLink() && after_link.isFile() &&
      after_realpath === before.canonical_path && same_file_identity(before.info, after);
    if (!stable) {
      provider_error('ORIX_RIZIN_INPUT_CHANGED', 'Rizin input identity or metadata changed during analysis', {
        input_path: before.canonical_path,
      });
    }

    const snapshot_after = await sha256_file(snapshot_path, maximum_bytes, signal);
    if (snapshot_after.digest !== input_hash.digest || snapshot_after.bytes_read !== input_hash.bytes_read) {
      provider_error('ORIX_RIZIN_SNAPSHOT_CHANGED', 'External provider modified its private input snapshot; results were discarded', {
        input_path: before.canonical_path,
      });
    }

    const imports = normalize_imports(import_result.stdout, maximum_imports);
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
        sha256: input_hash.digest,
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
        'Rizin analyzes a private temporary copy; the original input path is never passed to the provider.',
        'Rizin remains an optional external installation and is not bundled by ORIX.',
        isolation === 'required' ? 'Rizin was launched through required Bubblewrap namespace and filesystem isolation.' : 'The process runner bounds runtime and captured output but is not an OS sandbox.',
      ],
    };
  } finally {
    await rm(snapshot_directory, { recursive: true, force: true });
  }
}


function normalize_rizin_functions(source, maximum) {
  let parsed;
  try { parsed = JSON.parse(source); }
  catch { provider_error('ORIX_RIZIN_FUNCTION_JSON_INVALID', 'Rizin function command did not return valid JSON'); }
  if (!Array.isArray(parsed)) {
    provider_error('ORIX_RIZIN_FUNCTION_SHAPE_INVALID', 'Rizin function JSON must be an array');
  }
  const functions = parsed.slice(0, maximum).map((entry, index) => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry) ||
        Object.getPrototypeOf(entry) !== Object.prototype) {
      provider_error('ORIX_RIZIN_FUNCTION_ENTRY_INVALID', 'Rizin function entry must be an object', { index });
    }
    if (!Number.isSafeInteger(entry.offset) || entry.offset < 0) {
      provider_error('ORIX_RIZIN_FUNCTION_OFFSET_INVALID', 'Rizin function entry has an invalid offset', { index });
    }
    if (entry.size !== undefined && (!Number.isSafeInteger(entry.size) || entry.size < 0)) {
      provider_error('ORIX_RIZIN_FUNCTION_SIZE_INVALID', 'Rizin function entry has an invalid size', { index });
    }
    return {
      name: bounded_text(entry.name, 512) ?? ('sub_' + entry.offset.toString(16)),
      offset: entry.offset,
      size: Number.isSafeInteger(entry.size) && entry.size >= 0 ? entry.size : null,
      real_size: Number.isSafeInteger(entry.realsz) && entry.realsz >= 0 ? entry.realsz : null,
      bits: Number.isSafeInteger(entry.bits) && entry.bits > 0 ? entry.bits : null,
      type: bounded_text(entry.type, 64),
      call_type: bounded_text(entry.calltype, 64),
      signature: bounded_text(entry.signature, 1024),
      basic_blocks: Number.isSafeInteger(entry.nbbs) && entry.nbbs >= 0 ? entry.nbbs : null,
      edges: Number.isSafeInteger(entry.edges) && entry.edges >= 0 ? entry.edges : null,
      arguments: Number.isSafeInteger(entry.nargs) && entry.nargs >= 0 ? entry.nargs : null,
      locals: Number.isSafeInteger(entry.nlocals) && entry.nlocals >= 0 ? entry.nlocals : null,
      no_return: typeof entry.noreturn === 'boolean' ? entry.noreturn : null,
    };
  });
  return { functions, total: parsed.length, truncated: parsed.length > functions.length };
}

function normalize_rizin_disassembly(source, maximum) {
  let parsed;
  try { parsed = JSON.parse(source); }
  catch { provider_error('ORIX_RIZIN_DISASSEMBLY_JSON_INVALID', 'Rizin disassembly command did not return valid JSON'); }
  if (!Array.isArray(parsed)) {
    provider_error('ORIX_RIZIN_DISASSEMBLY_SHAPE_INVALID', 'Rizin disassembly JSON must be an array');
  }
  const instructions = parsed.slice(0, maximum).map((entry, index) => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry) ||
        Object.getPrototypeOf(entry) !== Object.prototype) {
      provider_error('ORIX_RIZIN_DISASSEMBLY_ENTRY_INVALID', 'Rizin instruction entry must be an object', { index });
    }
    if (!Number.isSafeInteger(entry.offset) || entry.offset < 0) {
      provider_error('ORIX_RIZIN_DISASSEMBLY_OFFSET_INVALID', 'Rizin instruction entry has an invalid offset', { index });
    }
    const opcode = bounded_text(entry.opcode, 512);
    const disassembly = bounded_text(entry.disasm, 512);
    if (!opcode && !disassembly) {
      provider_error('ORIX_RIZIN_DISASSEMBLY_OPCODE_INVALID', 'Rizin instruction entry has no bounded opcode or disassembly text', { index });
    }
    return {
      offset: entry.offset,
      size: Number.isSafeInteger(entry.size) && entry.size > 0 ? entry.size : null,
      bytes: bounded_text(entry.bytes, 128),
      opcode,
      disassembly,
      operation_type: bounded_text(entry.type, 64),
      jump: Number.isSafeInteger(entry.jump) && entry.jump >= 0 ? entry.jump : null,
      fail: Number.isSafeInteger(entry.fail) && entry.fail >= 0 ? entry.fail : null,
    };
  });
  return {
    instructions,
    total_returned: parsed.length,
    instruction_limit_reached: parsed.length >= maximum,
  };
}

function requested_rizin_address(value) {
  if (value === undefined || value === null) return null;
  let address;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    address = value;
  } else if (typeof value === 'string' && /^(?:0x[0-9a-f]{1,14}|[0-9]{1,16})$/i.test(value)) {
    try {
      const bigint = BigInt(value);
      if (bigint > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('unsafe');
      address = Number(bigint);
    } catch {
      throw new TypeError('address must be a non-negative safe integer or hexadecimal address');
    }
  } else {
    throw new TypeError('address must be a non-negative safe integer or hexadecimal address');
  }
  if (!Number.isSafeInteger(address)) throw new TypeError('address must be a non-negative safe integer or hexadecimal address');
  return address;
}

/**
 * Analyze Rizin's function inventory and, optionally, a bounded instruction
 * window at one function entry. This is disassembly, not decompilation.
 */
export async function analyze_rizin_functions(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Rizin function-analysis options must be an object');
  }
  const allowed = new Set([
    'executable', 'executable_args', 'input_path', 'manifest', 'cwd', 'env',
    'timeout_ms', 'max_output_bytes', 'max_functions',
    'address', 'max_instructions', 'decompile', 'max_decompilation_chars', 'signal', 'isolation', 'sandbox_root',
  ]);
  const descriptors = Object.getOwnPropertyDescriptors(options);
  for (const key of Reflect.ownKeys(options)) {
    if (typeof key !== 'string' || !allowed.has(key) ||
        !descriptors[key] || !Object.hasOwn(descriptors[key], 'value') || !descriptors[key].enumerable) {
      throw new TypeError('Rizin function-analysis options must use known enumerable data properties');
    }
  }

  const isolation = requested_isolation(descriptors.isolation?.value);
  const manifest = validate_provider_manifest(descriptors.manifest?.value ?? RIZIN_PROVIDER_MANIFEST);
  if (manifest.id !== 'rizin.static') {
    throw new TypeError('Rizin function analysis requires the rizin.static provider manifest');
  }
  assert_rizin_platform(manifest);
  const input_path = descriptors.input_path?.value;
  validate_input_path(input_path);
  const signal = descriptors.signal?.value;
  if (signal !== undefined && !(signal instanceof AbortSignal)) {
    throw new TypeError('signal must be an AbortSignal');
  }
  if (signal?.aborted) provider_error('ORIX_RIZIN_CANCELLED', 'Rizin function analysis was cancelled before input acquisition');

  const timeout_ms = descriptors.timeout_ms?.value ?? manifest.limits.timeout_ms;
  const max_output_bytes = descriptors.max_output_bytes?.value ?? manifest.limits.max_output_bytes;
  const max_functions = descriptors.max_functions?.value ?? 10_000;
  const max_instructions = descriptors.max_instructions?.value ?? 100;
  const address = requested_rizin_address(descriptors.address?.value);
  const decompile = descriptors.decompile?.value ?? false;
  const max_decompilation_chars = descriptors.max_decompilation_chars?.value ?? 64_000;
  if (typeof decompile !== 'boolean') throw new TypeError('decompile must be a boolean');
  if (!Number.isSafeInteger(max_decompilation_chars) || max_decompilation_chars < 1 || max_decompilation_chars > 256_000) {
    throw new TypeError('max_decompilation_chars must be an integer between 1 and 256000');
  }
  if (decompile && address === null) throw new TypeError('decompile requires an exact function-entry address');
  if (!Number.isSafeInteger(timeout_ms) || timeout_ms < 1 || timeout_ms > manifest.limits.timeout_ms) {
    throw new TypeError('timeout_ms must be between 1 and the provider manifest timeout limit');
  }
  if (!Number.isSafeInteger(max_output_bytes) || max_output_bytes < 1 ||
      max_output_bytes > manifest.limits.max_output_bytes) {
    throw new TypeError('max_output_bytes must be between 1 and the provider manifest output limit');
  }
  if (!Number.isSafeInteger(max_functions) || max_functions < 1 || max_functions > 100_000) {
    throw new TypeError('max_functions must be an integer between 1 and 100000');
  }
  if (!Number.isSafeInteger(max_instructions) || max_instructions < 1 || max_instructions > 1_000) {
    throw new TypeError('max_instructions must be an integer between 1 and 1000');
  }

  const analysis_started_at = Date.now();
  const before = await file_snapshot(input_path, manifest.limits.max_input_bytes);
  if (signal?.aborted) provider_error('ORIX_RIZIN_CANCELLED', 'Rizin function analysis was cancelled before input hashing');
  const input_hash = await sha256_file(before.canonical_path, manifest.limits.max_input_bytes, signal);
  if (input_hash.bytes_read !== before.info.size) {
    provider_error('ORIX_RIZIN_INPUT_CHANGED', 'Rizin input size changed while it was hashed', {
      expected_size_bytes: before.info.size, actual_size_bytes: input_hash.bytes_read,
    });
  }

  const snapshot_directory = await create_rizin_snapshot_directory('.orix-rizin-functions-', {
    isolation: isolation,
    sandbox_root: descriptors.sandbox_root?.value,
  });
  const extension = path.extname(before.canonical_path).slice(0, 16);
  const snapshot_path = path.join(snapshot_directory, 'artifact' + extension);
  try {
    const snapshot_bytes = await copy_file_bounded(before.canonical_path, snapshot_path, manifest.limits.max_input_bytes, signal);
    if (snapshot_bytes !== input_hash.bytes_read) {
      provider_error('ORIX_RIZIN_INPUT_CHANGED', 'Rizin input size changed while its private function-analysis snapshot was created', {
        expected_size_bytes: input_hash.bytes_read, actual_size_bytes: snapshot_bytes,
      });
    }
    await chmod(snapshot_path, 0o400);
    const snapshot_hash = await sha256_file(snapshot_path, manifest.limits.max_input_bytes, signal);
    if (snapshot_hash.digest !== input_hash.digest || snapshot_hash.bytes_read !== input_hash.bytes_read) {
      provider_error('ORIX_RIZIN_INPUT_CHANGED', 'Rizin input changed while its private function-analysis snapshot was created');
    }

    const common = {
      manifest,
      executable: descriptors.executable?.value,
      executable_args: descriptors.executable_args?.value,
      cwd: descriptors.cwd?.value,
      env: descriptors.env?.value,
      signal,
      isolation: isolation,
      sandbox_root: descriptors.sandbox_root?.value,
    };
    let captured_output_bytes = 0;
    const invoke = async (args, label) => {
      const remaining_time = timeout_ms - (Date.now() - analysis_started_at);
      const remaining_output = max_output_bytes - captured_output_bytes;
      if (remaining_time < 1) {
        provider_error('ORIX_RIZIN_TIMEOUT', 'Rizin function analysis exceeded its total deadline', { timeout_ms, phase: label });
      }
      if (remaining_output < 1) {
        provider_error('ORIX_RIZIN_OUTPUT_LIMIT', 'Rizin function analysis exhausted its aggregate output budget', { max_output_bytes, phase: label });
      }
      const result = await run_static_provider({
        ...common,
        args,
        timeout_ms: remaining_time,
        max_output_bytes: remaining_output,
      });
      if (!result.ok) {
        let code = result.cancelled
          ? 'ORIX_RIZIN_CANCELLED'
          : result.timed_out ? 'ORIX_RIZIN_TIMEOUT'
            : result.output_limited ? 'ORIX_RIZIN_OUTPUT_LIMIT' : 'ORIX_RIZIN_' + label.toUpperCase() + '_FAILED';
        if (label === 'decompilation') code = 'ORIX_RIZIN_DECOMPILER_UNAVAILABLE';
        provider_error(code, 'Rizin ' + label + ' operation did not complete successfully', {
          exit_code: result.exit_code,
          timed_out: result.timed_out,
          cancelled: result.cancelled,
          output_limited: result.output_limited,
          stderr: result.stderr.slice(0, 1024),
        });
      }
      captured_output_bytes += Buffer.byteLength(result.stdout, 'utf8') + Buffer.byteLength(result.stderr, 'utf8');
      return result;
    };

    const version_result = await invoke(['-v'], 'version');
    const engine_version = parse_engine_version(version_result.stdout);
    const function_result = await invoke(['-N', '-q', '-A', '-c', 'aflj', snapshot_path], 'functions');
    const normalized = normalize_rizin_functions(function_result.stdout, max_functions);
    let disassembly = null;
    let disassembly_duration_ms = null;
    let disassembly_stderr = '';
    let decompilation = null;
    let decompilation_duration_ms = null;
    let decompilation_stderr = '';
    let selected_function = null;
    let address_text = null;
    if (address !== null) {
      selected_function = normalized.functions.find(item => item.offset === address);
      if (!selected_function) {
        provider_error('ORIX_RIZIN_FUNCTION_NOT_FOUND', 'Requested address is not the entry offset of a function returned by Rizin', {
          address, functions_returned: normalized.total,
        });
      }
      address_text = '0x' + address.toString(16);
      const disassembly_result = await invoke([
        '-N', '-q', '-c', 'pdj ' + max_instructions + ' @ ' + address_text, snapshot_path,
      ], 'disassembly');
      const parsed_disassembly = normalize_rizin_disassembly(disassembly_result.stdout, max_instructions);
      disassembly = {
        function_name: selected_function.name,
        address,
        instruction_limit: max_instructions,
        instructions: parsed_disassembly.instructions,
        total_returned: parsed_disassembly.total_returned,
        instruction_limit_reached: parsed_disassembly.instruction_limit_reached,
      };
      disassembly_duration_ms = disassembly_result.duration_ms;
      disassembly_stderr = disassembly_result.stderr.slice(0, 1024);
    }

    if (decompile) {
      const decompilation_result = await invoke([
        '-N', '-q', '-c', 'pdg @ ' + address_text, snapshot_path,
      ], 'decompilation');
      const raw_source = decompilation_result.stdout.replace(/\0/g, '').trim();
      const provider_message = (raw_source + '\n' + decompilation_result.stderr).slice(0, 2048);
      if (!raw_source || /(?:unknown|invalid) command|command not found|pdg.{0,80}not found/i.test(provider_message)) {
        provider_error('ORIX_RIZIN_DECOMPILER_UNAVAILABLE', 'Rizin pdg decompiler command is unavailable or returned no pseudocode; install and verify the optional rz-ghidra plugin', {
          address, stderr: decompilation_result.stderr.slice(0, 1024),
        });
      }
      decompilation = {
        function_name: selected_function.name,
        address,
        backend: 'rizin-pdg',
        source: raw_source.slice(0, max_decompilation_chars),
        characters_returned: Math.min(raw_source.length, max_decompilation_chars),
        truncated: raw_source.length > max_decompilation_chars,
      };
      decompilation_duration_ms = decompilation_result.duration_ms;
      decompilation_stderr = decompilation_result.stderr.slice(0, 1024);
    }

    let after_link;
    let after;
    let after_realpath;
    try {
      after_link = await lstat(input_path);
      after = await stat(before.canonical_path);
      after_realpath = await realpath(input_path);
    } catch (error) {
      provider_error('ORIX_RIZIN_INPUT_CHANGED', 'Rizin input disappeared or became inaccessible during function analysis', {
        input_path: before.canonical_path, reason: error.code ?? 'filesystem-error',
      });
    }
    const stable = !after_link.isSymbolicLink() && after_link.isFile() &&
      after_realpath === before.canonical_path && same_file_identity(before.info, after);
    if (!stable) provider_error('ORIX_RIZIN_INPUT_CHANGED', 'Rizin input identity or metadata changed during function analysis');
    const snapshot_after = await sha256_file(snapshot_path, manifest.limits.max_input_bytes, signal);
    if (snapshot_after.digest !== input_hash.digest || snapshot_after.bytes_read !== input_hash.bytes_read) {
      provider_error('ORIX_RIZIN_SNAPSHOT_CHANGED', 'External provider modified its private function-analysis snapshot; results were discarded');
    }

    return {
      schema_version: 'orix.rizin-functions.v1',
      provider: {
        id: manifest.id,
        adapter_version: RIZIN_ADAPTER_VERSION,
        engine_version,
        executable: version_result.executable,
      },
      artifact: {
        path: before.canonical_path,
        size_bytes: before.info.size,
        sha256: input_hash.digest,
        stable_during_analysis: true,
      },
      functions: normalized.functions,
      disassembly,
      decompilation,
      summary: {
        functions_total: normalized.total,
        functions_returned: normalized.functions.length,
        functions_truncated: normalized.truncated,
        disassembly_included: disassembly !== null,
        decompilation_included: decompilation !== null,
      },
      diagnostics: {
        version_probe_duration_ms: version_result.duration_ms,
        function_scan_duration_ms: function_result.duration_ms,
        disassembly_duration_ms,
        decompilation_duration_ms,
        captured_output_bytes,
        stderr: (function_result.stderr + (disassembly_stderr ? '\n' + disassembly_stderr : '') + (decompilation_stderr ? '\n' + decompilation_stderr : '')).slice(0, 1024),
      },
      notes: [
        'Uses Rizin -A and aflj to enumerate functions; automatic analysis may miss or misclassify code.',
        'Optional pdj output is a bounded instruction disassembly window at a returned function entry, not decompiled source.',
        'Optional pdg output requires the external rz-ghidra plugin; pseudocode is heuristic and is not a source-level proof or a compilable reconstruction.',
        'The inspected target is not executed; Rizin itself is an external optional process.',
        'Rizin analyzes a private temporary copy; the original input path is never passed to the provider.',
        isolation === 'required' ? 'Rizin was launched through required Bubblewrap namespace and filesystem isolation.' : 'The process runner bounds runtime and output but is not an OS sandbox.',
      ],
    };
  } finally {
    await rm(snapshot_directory, { recursive: true, force: true });
  }
}

/**
 * Check an explicitly selected Rizin executable without opening an artifact.
 * This is a real version probe, not a PATH search or an installation claim.
 */
export async function probe_rizin(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Rizin probe options must be an object');
  }
  const allowed = new Set(['executable', 'executable_args', 'manifest', 'cwd', 'env', 'timeout_ms', 'max_output_bytes', 'signal', 'isolation', 'sandbox_root']);
  const descriptors = Object.getOwnPropertyDescriptors(options);
  for (const key of Reflect.ownKeys(options)) {
    if (typeof key !== 'string' || !allowed.has(key) ||
        !descriptors[key] || !Object.hasOwn(descriptors[key], 'value') || !descriptors[key].enumerable) {
      throw new TypeError('Rizin probe options must use known enumerable data properties');
    }
  }
  const isolation = requested_isolation(descriptors.isolation?.value);
  const manifest = validate_provider_manifest(descriptors.manifest?.value ?? RIZIN_PROVIDER_MANIFEST);
  if (manifest.id !== 'rizin.static') {
    throw new TypeError('Rizin probe requires the rizin.static provider manifest');
  }
  assert_rizin_platform(manifest);
  const timeout_ms = descriptors.timeout_ms?.value ?? Math.min(manifest.limits.timeout_ms, 10_000);
  const max_output_bytes = descriptors.max_output_bytes?.value ?? Math.min(manifest.limits.max_output_bytes, 16_384);
  if (!Number.isSafeInteger(timeout_ms) || timeout_ms < 1 || timeout_ms > manifest.limits.timeout_ms) {
    throw new TypeError('timeout_ms must be between 1 and the provider manifest timeout limit');
  }
  if (!Number.isSafeInteger(max_output_bytes) || max_output_bytes < 1 ||
      max_output_bytes > manifest.limits.max_output_bytes) {
    throw new TypeError('max_output_bytes must be between 1 and the provider manifest output limit');
  }
  const result = await run_static_provider({
    manifest,
    executable: descriptors.executable?.value,
    executable_args: descriptors.executable_args?.value,
    cwd: descriptors.cwd?.value,
    env: descriptors.env?.value,
    args: ['-v'],
    timeout_ms,
    max_output_bytes,
    signal: descriptors.signal?.value,
    isolation: isolation,
    sandbox_root: descriptors.sandbox_root?.value,
  });
  if (!result.ok) {
    const code = result.cancelled
      ? 'ORIX_RIZIN_CANCELLED'
      : result.timed_out ? 'ORIX_RIZIN_TIMEOUT' : 'ORIX_RIZIN_VERSION_FAILED';
    provider_error(code, 'Rizin version probe did not complete successfully', {
      exit_code: result.exit_code,
      timed_out: result.timed_out,
      cancelled: result.cancelled,
      stderr: result.stderr.slice(0, 1024),
    });
  }
  return {
    schema_version: 'orix.provider-probe.v1',
    provider: {
      id: manifest.id,
      adapter_version: RIZIN_ADAPTER_VERSION,
      engine_version: parse_engine_version(result.stdout),
      executable: result.executable,
    },
    runtime: {
      platform: process.platform,
      architecture: process.arch,
      node_version: process.version,
    },
    status: 'available',
    diagnostics: {
      duration_ms: result.duration_ms,
      exit_code: result.exit_code,
      stderr: result.stderr.slice(0, 1024),
    },
    notes: [
      'The executable was invoked by its explicit absolute path; ORIX did not search PATH.',
      'This probe confirms version output only; it does not validate every Rizin command or supported binary format.',
      isolation === 'required' ? 'The version probe used required Bubblewrap namespace and filesystem isolation.' : 'The process runner is not an OS sandbox.',
    ],
  };
}
