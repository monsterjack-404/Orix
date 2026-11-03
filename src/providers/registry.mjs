// JavaScript, src/providers/registry.mjs, Node.js 20+, metadata-only provider capability registry.

import { OrixError } from '../core/errors.mjs';
import { validate_provider_manifest } from './manifest.mjs';

const SUPPORTED_PLATFORMS = new Set(['windows', 'linux', 'macos', 'any']);
const CAPABILITY_ID = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/;
const FORMAT_ID = /^[a-z][a-z0-9.+_-]{0,63}$/;

function runtime_platform() {
  if (process.platform === 'win32') return 'windows';
  if (process.platform === 'darwin') return 'macos';
  if (process.platform === 'linux') return 'linux';
  return 'any';
}

function validate_filter(value, field, pattern = null) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || (pattern && !pattern.test(value))) {
    throw new TypeError(field + ' is not a valid provider registry filter');
  }
  return value;
}

export class ProviderRegistry {
  #providers = new Map();

  constructor(options = {}) {
    const platform = options.platform ?? runtime_platform();
    if (typeof platform !== 'string' || !SUPPORTED_PLATFORMS.has(platform)) {
      throw new TypeError('platform must be windows, linux, macos or any');
    }
    this.platform = platform;
  }

  register(input) {
    const manifest = validate_provider_manifest(input);
    if (this.#providers.has(manifest.id)) {
      throw new OrixError('ORIX_PROVIDER_DUPLICATE', 'A provider with this identifier is already registered', {
        details: { provider_id: manifest.id }, recoverable: true,
      });
    }
    this.#providers.set(manifest.id, manifest);
    return manifest;
  }

  unregister(provider_id) {
    if (typeof provider_id !== 'string' || !CAPABILITY_ID.test(provider_id)) {
      throw new TypeError('provider_id must be a valid provider identifier');
    }
    return this.#providers.delete(provider_id);
  }

  get(provider_id) {
    if (typeof provider_id !== 'string' || !CAPABILITY_ID.test(provider_id)) return null;
    return this.#providers.get(provider_id) ?? null;
  }

  list(filters = {}) {
    if (filters === null || typeof filters !== 'object' || Array.isArray(filters)) {
      throw new TypeError('Provider registry filters must be an object');
    }
    const capability = validate_filter(filters.capability, 'capability', CAPABILITY_ID);
    const input_format = validate_filter(filters.input_format, 'input_format', FORMAT_ID);
    const platform = validate_filter(filters.platform ?? this.platform, 'platform');
    if (platform !== null && !SUPPORTED_PLATFORMS.has(platform)) {
      throw new TypeError('platform must be windows, linux, macos or any');
    }

    return [...this.#providers.values()]
      .filter(manifest => capability === null || manifest.capabilities.includes(capability))
      .filter(manifest => input_format === null || manifest.input_formats.includes(input_format))
      .filter(manifest => platform === null || platform === 'any' ||
        manifest.supported_platforms.includes('any') || manifest.supported_platforms.includes(platform))
      .sort((left, right) => left.id.localeCompare(right.id, 'en'));
  }

  get size() {
    return this.#providers.size;
  }

  snapshot() {
    return Object.freeze({
      schema_version: 'orix.provider-registry.v1',
      platform: this.platform,
      provider_count: this.#providers.size,
      providers: Object.freeze(this.list()),
    });
  }
}
