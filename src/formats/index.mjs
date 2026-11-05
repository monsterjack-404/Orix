// JavaScript, src/formats/index.mjs, Node.js 20+, parser dispatch and support metadata.

import { detect_format } from './registry.mjs';
import { parse_pe } from './pe.mjs';
import { parse_elf } from './elf.mjs';
import { parse_macho, parse_macho_fat } from './macho.mjs';
import { parse_wasm } from './wasm.mjs';
import { parse_zip } from './zip.mjs';
import { parse_pdf } from './pdf.mjs';
import { parse_png } from './png.mjs';
import { parse_apk } from './apk.mjs';
import { parse_cpio } from './cpio.mjs';
import { parse_gzip } from './gzip.mjs';
import { parse_tar } from './tar.mjs';
import { parse_pcap } from './pcap.mjs';
import { parse_pcapng } from './pcapng.mjs';
import { parse_squashfs } from './squashfs.mjs';
import { parse_cramfs } from './cramfs.mjs';
import { parse_ubi } from './ubi.mjs';

const PARSERS = new Map([
  ['PE', parse_pe], ['ELF', parse_elf], ['Mach-O', parse_macho], ['Mach-O Universal', parse_macho_fat], ['WebAssembly', parse_wasm], ['ZIP', parse_zip], ['PDF', parse_pdf], ['PNG', parse_png], ['CPIO newc', parse_cpio], ['GZIP', parse_gzip], ['PCAP', parse_pcap], ['PCAPNG', parse_pcapng], ['TAR', parse_tar], ['SquashFS', parse_squashfs], ['cramfs', parse_cramfs], ['UBI', parse_ubi],
]);

export function analyze_known_format(buffer, options = {}) {
  const detection = detect_format(buffer);
  let result_detection = detection;
  const parser = PARSERS.get(detection.format);
  if (!parser) return { detection, parsed: null, parser_status: 'not-supported' };
  try {
    if (detection.format === 'ZIP') {
      const archive = parser(buffer, options);
      if (archive.entries.some(entry => entry.name === 'AndroidManifest.xml')) {
        result_detection = { ...detection, format: 'Android APK', description: 'Android application package', confidence: 'structural' };
        return { detection: result_detection, parsed: parse_apk(buffer, options), parser_status: 'parsed' };
      }
      return { detection, parsed: archive, parser_status: 'parsed' };
    }
    return { detection, parsed: parser(buffer, options), parser_status: 'parsed' };
  } catch (error) {
    return { detection: result_detection, parsed: null, parser_status: 'rejected', parser_error: { code: error.code ?? 'ORIX_PARSER_ERROR', message: error.message, details: error.details ?? null } };
  }
}

export { detect_format, list_supported_formats } from './registry.mjs';

import { list_supported_formats } from './registry.mjs';

export function list_format_capabilities() {
  return list_supported_formats().map(item => ({
    ...item,
    parser_status: PARSERS.has(item.format) ? 'available' : 'signature-only',
  }));
}
export { parse_pe } from './pe.mjs';
export { parse_elf } from './elf.mjs';
export { parse_macho, parse_macho_fat } from './macho.mjs';
export { parse_wasm } from './wasm.mjs';
export { parse_zip } from './zip.mjs';
export { parse_pdf } from './pdf.mjs';
export { parse_png } from './png.mjs';
export { parse_apk } from './apk.mjs';
export { parse_cpio } from './cpio.mjs';
export { parse_gzip } from './gzip.mjs';
export { parse_tar } from './tar.mjs';
export { parse_pcap } from './pcap.mjs';
export { parse_pcapng } from './pcapng.mjs';
export { parse_squashfs } from './squashfs.mjs';
export { parse_cramfs } from './cramfs.mjs';
export { parse_ubi } from './ubi.mjs';
