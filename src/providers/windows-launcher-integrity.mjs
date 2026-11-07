// Source-pinned Windows AppContainer launcher payload integrity.
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';

export const WINDOWS_PROVIDER_LAUNCHER_SHA256 = '14c4902a89e369cde661fae61a1779b0f1b0a8cb01e41c69c9210feeab674a34';
export const WINDOWS_PROVIDER_LAUNCHER_GZIP_SHA256 = 'd0667d4c4f5702e2aab6f02d11094f955f8b6de7a379d4ce089065c5600d28db';
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
