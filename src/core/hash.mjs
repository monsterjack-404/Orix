// JavaScript, src/core/hash.mjs, Node.js 20+, stable cryptographic file hashing.

import { createHash } from 'node:crypto';

export function hash_buffer(buffer, algorithm = 'sha256') {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('hash_buffer requires a Buffer');
  return createHash(algorithm).update(buffer).digest('hex');
}

export function hash_stream(stream, algorithm = 'sha256') {
  return new Promise((resolve, reject) => {
    const hash = createHash(algorithm);
    stream.on('data', chunk => hash.update(chunk));
    stream.once('error', reject);
    stream.once('end', () => resolve(hash.digest('hex')));
  });
}
