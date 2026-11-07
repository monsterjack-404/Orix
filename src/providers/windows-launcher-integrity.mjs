// Source-pinned Windows AppContainer launcher payload integrity.
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';

export const WINDOWS_PROVIDER_LAUNCHER_SHA256 = '9dfbf55f31e9ff2e215da31153afc74a4117ec96af47ab5de56fc0daaeae5ec31';
export const WINDOWS_PROVIDER_LAUNCHER_GZIP_SHA256 = 'd1e783190ba3f69a867a6a2d622c44ca616e18cd091205c6964b2820fe5fdc61';
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
