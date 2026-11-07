// JavaScript, src/core/binary-reader.mjs, Node.js 20+, bounds-checked binary reads.

import { OrixError } from './errors.mjs';

export class BinaryReader {
  constructor(buffer, { base_offset = 0, label = 'buffer' } = {}) {
    if (!Buffer.isBuffer(buffer)) throw new TypeError('BinaryReader requires a Buffer');
    if (!Number.isSafeInteger(base_offset) || base_offset < 0) throw new TypeError('base_offset must be non-negative');
    this.buffer = buffer;
    this.base_offset = base_offset;
    this.label = label;
    this.view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  }

  has(offset, length) {
    return Number.isSafeInteger(offset) && Number.isSafeInteger(length) && offset >= 0 && length >= 0 && offset <= this.buffer.length && length <= this.buffer.length - offset;
  }

  require(offset, length, field = 'field') {
    if (!this.has(offset, length)) {
      throw new OrixError('ORIX_TRUNCATED_INPUT', `Truncated ${this.label} while reading ${field}`, {
        details: { offset, length, available: this.buffer.length, absolute_offset: this.base_offset + offset },
        recoverable: true,
      });
    }
  }

  u8(offset, field) { this.require(offset, 1, field); return this.view.getUint8(offset); }
  u16(offset, little = true, field) { this.require(offset, 2, field); return this.view.getUint16(offset, little); }
  u32(offset, little = true, field) { this.require(offset, 4, field); return this.view.getUint32(offset, little); }
  i32(offset, little = true, field) { this.require(offset, 4, field); return this.view.getInt32(offset, little); }
  u64(offset, little = true, field) {
    this.require(offset, 8, field);
    const value = this.view.getBigUint64(offset, little);
    return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString();
  }
  bytes(offset, length, field) { this.require(offset, length, field); return this.buffer.subarray(offset, offset + length); }
  ascii(offset, length, field) { return this.bytes(offset, length, field).toString('ascii'); }
  c_string(offset, max_length, field = 'string') {
    this.require(offset, Math.min(max_length, this.buffer.length - offset), field);
    const end_limit = Math.min(this.buffer.length, offset + max_length);
    let end = offset;
    while (end < end_limit && this.buffer[end] !== 0) end += 1;
    return this.buffer.toString('utf8', offset, end);
  }
}

export function safe_range(offset, length, total, label = 'range') {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset > total || length > total - offset) {
    throw new OrixError('ORIX_INVALID_RANGE', `${label} is outside the available data`, {
      details: { offset, length, total }, recoverable: true,
    });
  }
  return { offset, length };
}
