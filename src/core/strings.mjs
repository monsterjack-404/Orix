// JavaScript, src/core/strings.mjs, Node.js 20+, bounded ASCII and UTF-16LE extraction.

const PRINTABLE = value => value >= 0x20 && value <= 0x7e;

function extract_ascii(buffer, minimum, maximum, remaining) {
  const found = [];
  let start = -1;
  for (let index = 0; index <= buffer.length && found.length < remaining; index += 1) {
    const valid = index < buffer.length && PRINTABLE(buffer[index]);
    if (valid && start < 0) start = index;
    if (!valid && start >= 0) {
      const length = index - start;
      if (length >= minimum) found.push({ value: buffer.toString('ascii', start, Math.min(index, start + maximum)), encoding: 'ascii', offset: start, length });
      start = -1;
    }
  }
  return found;
}

function extract_utf16le(buffer, minimum, maximum, remaining, ascii_ranges) {
  const found = [];
  for (let parity = 0; parity < 2 && found.length < remaining; parity += 1) {
    let start = -1;
    let index = parity;
    for (; index + 1 < buffer.length && found.length < remaining; index += 2) {
      const valid = PRINTABLE(buffer[index]) && buffer[index + 1] === 0;
      if (valid && start < 0) {
        const overlaps_ascii = ascii_ranges.some(item => index < item.offset + item.length && index + 2 > item.offset);
        if (!overlaps_ascii) start = index;
      }
      if (!valid && start >= 0) {
        const length = (index - start) / 2;
        if (length >= minimum && !ascii_ranges.some(item => start < item.offset + item.length && start + 2 > item.offset)) found.push({ value: buffer.toString('utf16le', start, Math.min(index, start + maximum * 2)), encoding: 'utf16le', offset: start, length: length * 2 });
        start = -1;
      }
    }
    if (start >= 0 && found.length < remaining) {
      const end = index + 1 < buffer.length ? index : buffer.length;
      const length = Math.floor((end - start) / 2);
      if (length >= minimum && !ascii_ranges.some(item => start < item.offset + item.length && start + 2 > item.offset)) found.push({ value: buffer.toString('utf16le', start, Math.min(end, start + maximum * 2)), encoding: 'utf16le', offset: start, length: length * 2 });
    }
  }
  return found;
}

export function extract_strings(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('extract_strings requires a Buffer');
  const minimum = options.minimum ?? 5;
  const maximum = options.maximum ?? 512;
  const limit = options.limit ?? 2_000;
  if (minimum > maximum) throw new TypeError('minimum cannot exceed maximum');
  for (const [name, value] of Object.entries({ minimum, maximum, limit })) {
    if (!Number.isSafeInteger(value) || value < (name === 'limit' ? 0 : 1)) throw new TypeError(`${name} must be a valid positive integer`);
  }
  const ascii = extract_ascii(buffer, minimum, maximum, limit);
  const wide = extract_utf16le(buffer, minimum, maximum, Math.max(0, limit - ascii.length), ascii);
  return [...ascii, ...wide].sort((left, right) => left.offset - right.offset).slice(0, limit);
}
