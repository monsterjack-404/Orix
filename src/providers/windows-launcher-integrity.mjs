// Source-pinned Windows AppContainer launcher payload integrity.
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';

export const WINDOWS_PROVIDER_LAUNCHER_SHA256 = '4c7cf078de466c1c583c0047d6456434bed3d041469f9192a1cab7adc4766092';
export const WINDOWS_PROVIDER_LAUNCHER_GZIP_SHA256 = '8d69c8a54af3cd4ad5dcbd0207a6b6c609de3356982b858e7d82a27d5f85c184';
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
