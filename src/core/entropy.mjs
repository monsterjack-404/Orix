// JavaScript, src/core/entropy.mjs, Node.js 20+, byte-distribution analysis.

export function calculate_entropy(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('calculate_entropy requires a Buffer');
  if (buffer.length === 0) return { bits_per_byte: 0, normalized: 0, sample_size: 0 };
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte] += 1;
  let entropy = 0;
  for (const count of counts) {
    if (!count) continue;
    const probability = count / buffer.length;
    entropy -= probability * Math.log2(probability);
  }
  return {
    bits_per_byte: Number(entropy.toFixed(6)),
    normalized: Number((entropy / 8).toFixed(6)),
    sample_size: buffer.length,
  };
}
