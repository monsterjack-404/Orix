// JavaScript, src/formats/index.mjs, Node.js 20+, parser dispatch and support metadata.

import { detect_format } from './registry.mjs';
import { parse_pe } from './pe.mjs';
import { parse_elf } from './elf.mjs';
import { parse_macho } from './macho.mjs';
import { parse_wasm } from './wasm.mjs';
import { parse_zip } from './zip.mjs';

const PARSERS = new Map([
  ['PE', parse_pe], ['ELF', parse_elf], ['Mach-O', parse_macho], ['WebAssembly', parse_wasm], ['ZIP', parse_zip],
]);

export function analyze_known_format(buffer, options = {}) {
  const detection = detect_format(buffer);
  const parser = PARSERS.get(detection.format);
  if (!parser) return { detection, parsed: null, parser_status: 'not-supported' };
  try {
    return { detection, parsed: parser(buffer, options), parser_status: 'parsed' };
  } catch (error) {
    return { detection, parsed: null, parser_status: 'rejected', parser_error: { code: error.code ?? 'ORIX_PARSER_ERROR', message: error.message, details: error.details ?? null } };
  }
}

export { detect_format, list_supported_formats } from './registry.mjs';
export { parse_pe } from './pe.mjs';
export { parse_elf } from './elf.mjs';
export { parse_macho } from './macho.mjs';
export { parse_wasm } from './wasm.mjs';
export { parse_zip } from './zip.mjs';
