// Source-pinned Windows AppContainer launcher payload integrity.
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';

export const WINDOWS_PROVIDER_LAUNCHER_SHA256 = 'dc8cb95df3734b64f6b1af854d44864038a7da02a02c7bb2fd4f0d0185b32b47';
export const WINDOWS_PROVIDER_LAUNCHER_GZIP_SHA256 = '992f2b67a940d083b82cc628b9d66f7e1a94e938e9c66c1383a5e556f3e7def9';
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
