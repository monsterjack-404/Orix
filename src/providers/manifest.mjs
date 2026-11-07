// JavaScript, src/providers/manifest.mjs, Node.js 20+, bounded declarative provider-manifest validation.

import { constants as FS_CONSTANTS, promises as fs } from 'node:fs';
import path from 'node:path';
import { TextDecoder } from 'node:util';
import { OrixError } from '../core/errors.mjs';

export const PROVIDER_CONTRACT_VERSION = 'orix.provider.v1';
export const DEFAULT_PROVIDER_MANIFEST_LIMIT = 64 * 1024;

const PROVIDER_ID = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/;
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const INPUT_FORMAT = /^[a-z][a-z0-9.+_-]{0,63}$/;
const PLATFORMS = new Set(['windows', 'linux', 'macos', 'any']);
const EXECUTION_MODES = new Set(['static', 'dynamic', 'network', 'mixed']);
const REDISTRIBUTION = new Set(['bundled', 'external-install', 'proprietary', 'unknown']);

function invalid(field, message, details = null) {
  throw new OrixError('ORIX_PROVIDER_MANIFEST_INVALID', message, {
    details: { field, ...(details ?? {}) },
    recoverable: true,
  });
}

function plain_record(value, field) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    invalid(field, field + ' must be an object');
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    invalid(field, field + ' must be a plain data object');
  }
  if (Reflect.ownKeys(value).some(key => typeof key === 'symbol')) {
    invalid(field, field + ' must not contain symbol properties');
  }
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (!Object.hasOwn(descriptor, 'value')) invalid(field + '.' + key, 'Accessor properties are not accepted');
    if (!descriptor.enumerable) invalid(field + '.' + key, 'Non-enumerable manifest properties are not accepted');
  }
  return value;
}

function exact_keys(value, field, allowed, required = allowed) {
  plain_record(value, field);
  const keys = Reflect.ownKeys(value);
  for (const key of keys) {
    if (typeof key !== 'string' || !allowed.includes(key)) invalid(field + '.' + String(key), 'Unknown property in provider manifest');
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) invalid(field + '.' + key, 'Required property is missing');
  }
}

function text_value(value, field, minimum, maximum, pattern = null) {
  if (typeof value !== 'string' || value.length < minimum || value.length > maximum || (pattern && !pattern.test(value))) {
    invalid(field, field + ' has an invalid string value');
  }
  return value;
}

function integer_value(value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(field, field + ' must be an integer between ' + minimum + ' and ' + maximum);
  }
  return value;
}

function boolean_value(value, field) {
  if (typeof value !== 'boolean') invalid(field, field + ' must be a boolean');
  return value;
}

function unique_array(value, field, maximum, validate_item) {
  if (!Array.isArray(value) || value.length > maximum) invalid(field, field + ' must be an array with at most ' + maximum + ' entries');
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key === 'symbol') invalid(field, 'Array custom properties are not accepted');
    if (key === 'length') continue;
    if (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length) {
      invalid(field, 'Array custom properties are not accepted');
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) invalid(field + '[' + key + ']', 'Accessor elements are not accepted');
    if (!descriptor.enumerable) invalid(field + '[' + key + ']', 'Non-enumerable array elements are not accepted');
  }
  const seen = new Set();
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor) invalid(field + '[' + index + ']', 'Sparse arrays are not accepted');
    const item = validate_item(descriptor.value, field + '[' + index + ']');
    if (seen.has(item)) invalid(field + '[' + index + ']', 'Duplicate values are not accepted');
    seen.add(item);
    result.push(item);
  }
  return result;
}

function validate_http_url(value, field) {
  text_value(value, field, 1, 2048);
  let parsed;
  try { parsed = new URL(value); }
  catch { invalid(field, field + ' must be an absolute HTTP(S) URL'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
    invalid(field, field + ' must be an absolute HTTP(S) URL');
  }
  return parsed.href;
}

function deep_freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deep_freeze(child);
    Object.freeze(value);
  }
  return value;
}

export function validate_provider_manifest(input) {
  exact_keys(input, 'manifest', [
    'contract_version', 'id', 'name', 'version', 'description', 'capabilities',
    'supported_platforms', 'input_formats', 'execution', 'limits', 'license', 'documentation_url',
  ], [
    'contract_version', 'id', 'name', 'version', 'description', 'capabilities',
    'supported_platforms', 'input_formats', 'execution', 'limits', 'license',
  ]);

  if (input.contract_version !== PROVIDER_CONTRACT_VERSION) {
    invalid('contract_version', 'Unsupported provider contract version', { received: input.contract_version });
  }

  const id = text_value(input.id, 'id', 3, 96, PROVIDER_ID);
  const name = text_value(input.name, 'name', 1, 120);
  const version = text_value(input.version, 'version', 5, 128, SEMVER);
  const description = text_value(input.description, 'description', 1, 1000);

  const capabilities = unique_array(input.capabilities, 'capabilities', 128,
    (item, field) => text_value(item, field, 1, 96, PROVIDER_ID));
  if (capabilities.length === 0) invalid('capabilities', 'At least one capability is required');

  const supported_platforms = unique_array(input.supported_platforms, 'supported_platforms', 4, (item, field) => {
    if (typeof item !== 'string' || !PLATFORMS.has(item)) invalid(field, 'Unsupported platform identifier');
    return item;
  });
  if (supported_platforms.length === 0) invalid('supported_platforms', 'At least one platform is required');

  const input_formats = unique_array(input.input_formats, 'input_formats', 256,
    (item, field) => text_value(item, field, 1, 64, INPUT_FORMAT));

  exact_keys(input.execution, 'execution',
    ['mode', 'requires_authorization', 'executes_target', 'writes_target', 'uses_network']);
  const mode = input.execution.mode;
  if (typeof mode !== 'string' || !EXECUTION_MODES.has(mode)) invalid('execution.mode', 'Unsupported execution mode');
  const execution = {
    mode,
    requires_authorization: boolean_value(input.execution.requires_authorization, 'execution.requires_authorization'),
    executes_target: boolean_value(input.execution.executes_target, 'execution.executes_target'),
    writes_target: boolean_value(input.execution.writes_target, 'execution.writes_target'),
    uses_network: boolean_value(input.execution.uses_network, 'execution.uses_network'),
  };
  const has_side_effects = execution.executes_target || execution.writes_target || execution.uses_network;
  if (has_side_effects && !execution.requires_authorization) {
    invalid('execution.requires_authorization', 'Target execution, target writes and network access require explicit authorization');
  }
  if (mode === 'static' && has_side_effects) {
    invalid('execution.mode', 'Static providers cannot declare target execution, target writes or network access');
  }
  if (mode === 'network' && !execution.uses_network) {
    invalid('execution.uses_network', 'Network-mode providers must declare network access');
  }
  if (mode === 'dynamic' && !execution.requires_authorization) {
    invalid('execution.requires_authorization', 'Dynamic providers require explicit authorization');
  }

  exact_keys(input.limits, 'limits', ['timeout_ms', 'max_input_bytes', 'max_output_bytes']);
  const limits = {
    timeout_ms: integer_value(input.limits.timeout_ms, 'limits.timeout_ms', 1, 600_000),
    max_input_bytes: integer_value(input.limits.max_input_bytes, 'limits.max_input_bytes', 1, 2_147_483_648),
    max_output_bytes: integer_value(input.limits.max_output_bytes, 'limits.max_output_bytes', 1024, 268_435_456),
  };

  exact_keys(input.license, 'license', ['spdx_id', 'redistribution', 'source_url'], ['spdx_id', 'redistribution']);
  const spdx_id = text_value(input.license.spdx_id, 'license.spdx_id', 1, 128);
  const redistribution = input.license.redistribution;
  if (typeof redistribution !== 'string' || !REDISTRIBUTION.has(redistribution)) {
    invalid('license.redistribution', 'Unsupported redistribution classification');
  }
  const license = { spdx_id, redistribution };
  if (Object.hasOwn(input.license, 'source_url')) license.source_url = validate_http_url(input.license.source_url, 'license.source_url');

  const manifest = {
    contract_version: PROVIDER_CONTRACT_VERSION,
    id, name, version, description, capabilities, supported_platforms, input_formats,
    execution, limits, license,
  };
  if (Object.hasOwn(input, 'documentation_url')) manifest.documentation_url = validate_http_url(input.documentation_url, 'documentation_url');
  return deep_freeze(manifest);
}

export function parse_provider_manifest_json(source, options = {}) {
  if (typeof source !== 'string') throw new TypeError('Provider manifest source must be a string');
  const maximum_bytes = options.max_bytes ?? DEFAULT_PROVIDER_MANIFEST_LIMIT;
  integer_value(maximum_bytes, 'max_bytes', 1, 1024 * 1024);
  const byte_length = Buffer.byteLength(source, 'utf8');
  if (byte_length > maximum_bytes) {
    throw new OrixError('ORIX_PROVIDER_MANIFEST_TOO_LARGE', 'Provider manifest exceeds the configured byte limit', {
      details: { byte_length, maximum_bytes }, recoverable: true,
    });
  }
  let parsed;
  try { parsed = JSON.parse(source); }
  catch (error) {
    throw new OrixError('ORIX_PROVIDER_MANIFEST_JSON', 'Provider manifest is not valid JSON', { cause: error, recoverable: true });
  }
  return validate_provider_manifest(parsed);
}

function same_file_identity(left, right) {
  return left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs &&
    String(left.dev) === String(right.dev) &&
    String(left.ino) === String(right.ino);
}

export async function read_provider_manifest(file_path, options = {}) {
  if (typeof file_path !== 'string' || file_path.trim() === '') throw new TypeError('A provider manifest path is required');
  const maximum_bytes = options.max_bytes ?? DEFAULT_PROVIDER_MANIFEST_LIMIT;
  integer_value(maximum_bytes, 'max_bytes', 1, 1024 * 1024);
  const absolute_path = path.resolve(file_path);
  let before;
  try { before = await fs.lstat(absolute_path); }
  catch (error) {
    throw new OrixError('ORIX_PROVIDER_MANIFEST_UNAVAILABLE', 'Cannot access provider manifest', {
      cause: error, details: { path: absolute_path, system_code: error.code ?? null }, recoverable: true,
    });
  }
  if (before.isSymbolicLink()) {
    throw new OrixError('ORIX_PROVIDER_MANIFEST_SYMLINK', 'Provider manifest symlinks are not followed', { details: { path: absolute_path }, recoverable: true });
  }
  if (!before.isFile()) {
    throw new OrixError('ORIX_PROVIDER_MANIFEST_NOT_FILE', 'Provider manifest must be a regular file', { details: { path: absolute_path }, recoverable: true });
  }
  if (before.size > maximum_bytes) {
    throw new OrixError('ORIX_PROVIDER_MANIFEST_TOO_LARGE', 'Provider manifest exceeds the configured byte limit', {
      details: { size: before.size, maximum_bytes }, recoverable: true,
    });
  }

  let handle;
  try {
    handle = await fs.open(absolute_path, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile() || !same_file_identity(before, opened)) {
      throw new OrixError('ORIX_PROVIDER_MANIFEST_REPLACED', 'Provider manifest identity changed before it was opened', { recoverable: true });
    }
    // O_NOFOLLOW is unavailable on some platforms. Re-check the path after
    // opening so a symlink swap between the initial lstat and open is rejected.
    const path_after_open = await fs.lstat(absolute_path);
    if (path_after_open.isSymbolicLink() || !path_after_open.isFile() ||
        !same_file_identity(path_after_open, opened)) {
      throw new OrixError('ORIX_PROVIDER_MANIFEST_REPLACED', 'Provider manifest path changed while it was being opened', { recoverable: true });
    }
    const buffer = Buffer.alloc(maximum_bytes + 1);
    let total = 0;
    while (total < buffer.length) {
      const { bytesRead } = await handle.read(buffer, total, buffer.length - total, total);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    if (total > maximum_bytes) {
      throw new OrixError('ORIX_PROVIDER_MANIFEST_TOO_LARGE', 'Provider manifest grew beyond the configured byte limit while reading', {
        details: { maximum_bytes }, recoverable: true,
      });
    }
    const after = await handle.stat();
    if (!same_file_identity(opened, after)) {
      throw new OrixError('ORIX_PROVIDER_MANIFEST_CHANGED', 'Provider manifest changed while it was being read', { recoverable: true });
    }
    let source;
    try { source = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, total)); }
    catch (error) {
      throw new OrixError('ORIX_PROVIDER_MANIFEST_ENCODING', 'Provider manifest must be valid UTF-8', { cause: error, recoverable: true });
    }
    return parse_provider_manifest_json(source, { max_bytes: maximum_bytes });
  } catch (error) {
    if (error instanceof OrixError) throw error;
    throw new OrixError('ORIX_PROVIDER_MANIFEST_READ', 'Cannot read provider manifest', {
      cause: error, details: { path: absolute_path, system_code: error.code ?? null }, recoverable: true,
    });
  } finally {
    await handle?.close().catch(() => {});
  }
}
