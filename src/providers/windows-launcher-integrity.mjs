// Source-pinned Windows AppContainer launcher payload integrity.
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';

export const WINDOWS_PROVIDER_LAUNCHER_SHA256 = 'cc8ec9a48fbf9753af55c225576383f0306f645a3cda92dc3b1402c1cae8d27f';
export const WINDOWS_PROVIDER_LAUNCHER_GZIP_SHA256 = 'e31f89cc4557498daf274da97488dd724b93dfa138e627e2ec9b6de2602d1819';
export const WINDOWS_PROVIDER_LAUNCHER_MAX_COMPRESSED_BYTES = 256 * 1024;
export const WINDOWS_PROVIDER_LAUNCHER_MAX_BYTES = 1024 * 1024;

export function decodeWindowsProviderLauncherBase64(encoded) {
  const maximumEncodedBytes = Math.ceil(WINDOWS_PROVIDER_LAUNCHER_MAX_COMPRESSED_BYTES / 3) * 4;
  if (typeof encoded !== 'string' || encoded.length === 0 ||
      encoded.length > maximumEncodedBytes || encoded.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    throw new Error('Windows launcher base64 payload has an invalid size or alphabet');
  }
  const compressed = Buffer.from(encoded, 'base64');
  if (compressed.length === 0 || compressed.length > WINDOWS_PROVIDER_LAUNCHER_MAX_COMPRESSED_BYTES ||
      compressed.toString('base64') !== encoded) {
    throw new Error('Windows launcher base64 payload is malformed or non-canonical');
  }
  return compressed;
}

export function decodeWindowsProviderLauncher(compressed) {
  if (!Buffer.isBuffer(compressed) || compressed.length === 0 ||
      compressed.length > WINDOWS_PROVIDER_LAUNCHER_MAX_COMPRESSED_BYTES) {
    throw new Error('Windows launcher compressed payload has an invalid size');
  }
  if (createHash('sha256').update(compressed).digest('hex') !== WINDOWS_PROVIDER_LAUNCHER_GZIP_SHA256) {
    throw new Error('Windows launcher compressed payload SHA-256 mismatch');
  }
  let executable;
  try {
    executable = gunzipSync(compressed, { maxOutputLength: WINDOWS_PROVIDER_LAUNCHER_MAX_BYTES });
  } catch {
    throw new Error('Windows launcher compressed payload is malformed or exceeds its output limit');
  }
  if (executable.length === 0 || executable.length > WINDOWS_PROVIDER_LAUNCHER_MAX_BYTES ||
      createHash('sha256').update(executable).digest('hex') !== WINDOWS_PROVIDER_LAUNCHER_SHA256) {
    throw new Error('Windows launcher executable SHA-256 mismatch');
  }
  return executable;
}
