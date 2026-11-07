// Source-pinned Windows AppContainer launcher payload integrity.
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';

export const WINDOWS_PROVIDER_LAUNCHER_SHA256 = '975dbe8dd65ec19b7a28c67eb77f8946fb8245bf5a5229a8b5467d381688e3d0';
export const WINDOWS_PROVIDER_LAUNCHER_GZIP_SHA256 = 'caf5a2d9125fbf70f3f39f45dfb991465ac6e3048ece68a418c707d30569a541';
export const WINDOWS_PROVIDER_LAUNCHER_MAX_COMPRESSED_BYTES = 256 * 1024;
export const WINDOWS_PROVIDER_LAUNCHER_MAX_BYTES = 1024 * 1024;

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
