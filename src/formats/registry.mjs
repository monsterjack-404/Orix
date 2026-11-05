// JavaScript, src/formats/registry.mjs, Node.js 20+, signature-based format registry.

function matches_ustar(buffer) {
  if (buffer.length < 512) return false;
  const magic = buffer.toString('ascii', 257, 263);
  if (magic !== 'ustar\0' && magic !== 'ustar ') return false;
  const raw = buffer.toString('ascii', 148, 156).replace(/\0.*$/s, '').trim();
  if (!/^[0-7]+$/.test(raw)) return false;
  const expected = Number.parseInt(raw, 8);
  let unsigned = 0;
  let signed = 0;
  for (let i = 0; i < 512; i += 1) {
    const value = i >= 148 && i < 156 ? 0x20 : buffer[i];
    unsigned += value;
    signed += value > 127 ? value - 256 : value;
  }
  return expected === unsigned || expected === signed;
}

const SIGNATURES = [
  { format: 'ELF', description: 'Executable and Linkable Format', matches: b => b.length >= 4 && b.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) },
  { format: 'PE', description: 'Portable Executable / COFF', matches: b => b.length >= 2 && b[0] === 0x4d && b[1] === 0x5a },
  { format: 'Mach-O', description: 'Mach object or executable', matches: b => b.length >= 4 && ['feedface','cefaedfe','feedfacf','cffaedfe'].includes(b.subarray(0, 4).toString('hex')) },
  { format: 'Mach-O Universal', description: 'Universal Mach-O container', matches: b => b.length >= 4 && ['cafebabe','bebafeca','cafebabf','bfbafeca'].includes(b.subarray(0, 4).toString('hex')) },
  { format: 'WebAssembly', description: 'WebAssembly module', matches: b => b.length >= 8 && b.subarray(0, 4).toString('hex') === '0061736d' },
  { format: 'PCAP', description: 'Classic PCAP capture', matches: b => b.length >= 4 && ['d4c3b2a1','a1b2c3d4','4d3cb2a1','a1b23c4d'].includes(b.subarray(0, 4).toString('hex')) },
  { format: 'ZIP', description: 'ZIP archive', matches: b => b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && [0x03,0x05,0x07].includes(b[2]) && [0x04,0x06,0x08].includes(b[3]) },
  { format: 'PDF', description: 'Portable Document Format', matches: b => b.length >= 5 && b.subarray(0, 5).toString('ascii') === '%PDF-' },
  { format: 'PNG', description: 'Portable Network Graphics', matches: b => b.length >= 8 && b.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])) },
  { format: 'JPEG', description: 'JPEG image', matches: b => b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { format: 'SQLite', description: 'SQLite database', matches: b => b.length >= 16 && b.subarray(0, 16).toString('ascii') === 'SQLite format 3\0' },
  { format: 'GZIP', description: 'GZIP compressed stream', matches: b => b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b },
  { format: 'CPIO newc', description: 'CPIO newc or CRC-newc archive', matches: b => b.length >= 6 && ['070701', '070702'].includes(b.subarray(0, 6).toString('ascii')) },
  { format: 'TAR', description: 'USTAR-compatible archive', matches: matches_ustar },
];

export function detect_format(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('detect_format requires a Buffer');
  const match = SIGNATURES.find(candidate => candidate.matches(buffer));
  return match ? { ...match, confidence: 'signature' } : { format: 'Unknown', description: 'No recognized leading signature', confidence: 'none' };
}

export function list_supported_formats() {
  return SIGNATURES.map(({ format, description }) => ({ format, description }));
}
