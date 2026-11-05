// JavaScript, src/formats/registry.mjs, Node.js 20+, signature-based format registry.

const SIGNATURES = [
  { format: 'ELF', description: 'Executable and Linkable Format', matches: b => b.length >= 4 && b.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) },
  { format: 'PE', description: 'Portable Executable / COFF', matches: b => b.length >= 2 && b[0] === 0x4d && b[1] === 0x5a },
  { format: 'Mach-O', description: 'Mach object or executable', matches: b => b.length >= 4 && ['feedface','cefaedfe','feedfacf','cffaedfe'].includes(b.subarray(0, 4).toString('hex')) },
  { format: 'Mach-O Universal', description: 'Universal Mach-O container', matches: b => b.length >= 4 && ['cafebabe','bebafeca','cafebabf','bfbafeca'].includes(b.subarray(0, 4).toString('hex')) },
  { format: 'WebAssembly', description: 'WebAssembly module', matches: b => b.length >= 8 && b.subarray(0, 4).toString('hex') === '0061736d' },
  { format: 'ZIP', description: 'ZIP archive', matches: b => b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && [0x03,0x05,0x07].includes(b[2]) && [0x04,0x06,0x08].includes(b[3]) },
  { format: 'PDF', description: 'Portable Document Format', matches: b => b.length >= 5 && b.subarray(0, 5).toString('ascii') === '%PDF-' },
  { format: 'PNG', description: 'Portable Network Graphics', matches: b => b.length >= 8 && b.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])) },
  { format: 'JPEG', description: 'JPEG image', matches: b => b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { format: 'SQLite', description: 'SQLite database', matches: b => b.length >= 16 && b.subarray(0, 16).toString('ascii') === 'SQLite format 3\0' },
  { format: 'GZIP', description: 'GZIP compressed stream', matches: b => b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b },
  { format: 'CPIO newc', description: 'CPIO newc or CRC-newc archive', matches: b => b.length >= 6 && ['070701', '070702'].includes(b.subarray(0, 6).toString('ascii')) },
];

export function detect_format(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('detect_format requires a Buffer');
  const match = SIGNATURES.find(candidate => candidate.matches(buffer));
  return match ? { ...match, confidence: 'signature' } : { format: 'Unknown', description: 'No recognized leading signature', confidence: 'none' };
}

export function list_supported_formats() {
  return SIGNATURES.map(({ format, description }) => ({ format, description }));
}
