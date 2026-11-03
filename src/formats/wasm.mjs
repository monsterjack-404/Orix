// JavaScript, src/formats/wasm.mjs, Node.js 20+, bounded WebAssembly section indexer.

import { OrixError } from '../core/errors.mjs';
import { BinaryReader } from '../core/binary-reader.mjs';

const SECTION_NAMES = new Map([[0,'custom'],[1,'type'],[2,'import'],[3,'function'],[4,'table'],[5,'memory'],[6,'global'],[7,'export'],[8,'start'],[9,'element'],[10,'code'],[11,'data'],[12,'data-count'],[13,'tag']]);

function read_varuint(reader, offset, max_bytes = 5, end_limit = reader.buffer.length) {
  let value = 0;
  let multiplier = 1;
  let cursor = offset;
  for (let count = 0; count < max_bytes; count += 1) {
    if (cursor >= end_limit) throw new OrixError('ORIX_WASM_TRUNCATED_LEB128', 'WebAssembly integer crosses its containing boundary', { details: { offset, end_limit }, recoverable: true });
    const byte = reader.u8(cursor, 'WebAssembly varuint');
    value += (byte & 0x7f) * multiplier;
    cursor += 1;
    if ((byte & 0x80) === 0) return { value, next: cursor };
    multiplier *= 128;
  }
  throw new OrixError('ORIX_WASM_BAD_LEB128', 'WebAssembly integer uses too many LEB128 bytes', { details: { offset, max_bytes }, recoverable: true });
}

export function parse_wasm(buffer, options = {}) {
  const reader = new BinaryReader(buffer, { label: 'WebAssembly module' });
  if (reader.ascii(0, 4, 'WebAssembly magic') !== '\0asm') throw new OrixError('ORIX_WASM_BAD_MAGIC', 'Input does not contain the WebAssembly magic', { recoverable: true });
  const version = reader.u32(4, true, 'WebAssembly version');
  const maximum_sections = options.max_sections ?? 4_096;
  if (!Number.isSafeInteger(maximum_sections) || maximum_sections < 1 || maximum_sections > 65_535) {
    throw new TypeError('max_sections must be an integer between 1 and 65535');
  }
  const sections = [];
  let cursor = 8;
  while (cursor < buffer.length) {
    if (sections.length >= maximum_sections) throw new OrixError('ORIX_WASM_SECTION_LIMIT', 'WebAssembly section count exceeds configured limit', { details: { maximum_sections }, recoverable: true });
    const id = reader.u8(cursor, 'section ID');
    const size_info = read_varuint(reader, cursor + 1);
    const payload_offset = size_info.next;
    if (size_info.value > buffer.length - payload_offset) {
      throw new OrixError('ORIX_WASM_SECTION_OUT_OF_RANGE', 'WebAssembly section extends beyond end of file', { details: { id, payload_offset, payload_size: size_info.value, file_size: buffer.length }, recoverable: true });
    }
    let custom_name = null;
    if (id === 0 && size_info.value > 0) {
      const name_length = read_varuint(reader, payload_offset, 5, payload_offset + size_info.value);
      if (name_length.value > payload_offset + size_info.value - name_length.next) throw new OrixError('ORIX_WASM_BAD_CUSTOM_NAME', 'Custom section name extends beyond its payload', { recoverable: true });
      custom_name = reader.bytes(name_length.next, name_length.value, 'custom section name').toString('utf8');
    }
    sections.push({ id, name: id === 0 ? 'custom' : (SECTION_NAMES.get(id) ?? `unknown-${id}`), custom_name, offset: cursor, payload_offset, payload_size: size_info.value });
    cursor = payload_offset + size_info.value;
  }
  return { format: 'WebAssembly', version, sections, notes: ['Section framing and custom-section names are validated; instruction bodies and type semantics are not decompiled.'] };
}
