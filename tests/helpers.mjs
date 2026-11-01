// JavaScript, tests/helpers.mjs, Node.js 20+, deterministic binary fixture builders.

export function create_pe_fixture({ is_64 = false } = {}) {
  const optional_size = is_64 ? 240 : 224;
  const pe_offset = 0x80;
  const section_table = pe_offset + 4 + 20 + optional_size;
  const raw_offset = section_table + 40;
  const buffer = Buffer.alloc(raw_offset + 16);
  buffer.write('MZ', 0, 'ascii');
  buffer.writeUInt32LE(pe_offset, 0x3c);
  buffer.write('PE\0\0', pe_offset, 'binary');
  const coff = pe_offset + 4;
  buffer.writeUInt16LE(is_64 ? 0x8664 : 0x014c, coff);
  buffer.writeUInt16LE(1, coff + 2);
  buffer.writeUInt32LE(0x65a1b2c3, coff + 4);
  buffer.writeUInt16LE(optional_size, coff + 16);
  buffer.writeUInt16LE(0x0022, coff + 18);
  const opt = coff + 20;
  buffer.writeUInt16LE(is_64 ? 0x20b : 0x10b, opt);
  buffer.writeUInt32LE(0x1000, opt + 16);
  if (is_64) buffer.writeBigUInt64LE(0x140000000n, opt + 24);
  else buffer.writeUInt32LE(0x400000, opt + 28);
  buffer.writeUInt32LE(0x1000, opt + 32);
  buffer.writeUInt32LE(0x200, opt + 36);
  buffer.writeUInt32LE(0x3000, opt + 56);
  buffer.writeUInt32LE(0x400, opt + 60);
  buffer.writeUInt16LE(3, opt + 68);
  buffer.writeUInt16LE(0x0140, opt + 70);
  buffer.writeUInt32LE(16, opt + (is_64 ? 108 : 92));
  const section = section_table;
  buffer.write('.text', section, 'ascii');
  buffer.writeUInt32LE(0x20, section + 8);
  buffer.writeUInt32LE(0x1000, section + 12);
  buffer.writeUInt32LE(16, section + 16);
  buffer.writeUInt32LE(raw_offset, section + 20);
  buffer.writeUInt32LE(0x60000020, section + 36);
  buffer.fill(0x90, raw_offset, raw_offset + 16);
  return buffer;
}

export function create_elf_fixture() {
  const buffer = Buffer.alloc(64);
  buffer.set([0x7f,0x45,0x4c,0x46,2,1,1,0], 0);
  buffer.writeUInt16LE(2, 16);
  buffer.writeUInt16LE(62, 18);
  buffer.writeUInt32LE(1, 20);
  buffer.writeBigUInt64LE(0x401000n, 24);
  buffer.writeBigUInt64LE(0n, 32);
  buffer.writeBigUInt64LE(0n, 40);
  buffer.writeUInt32LE(0, 48);
  buffer.writeUInt16LE(64, 52);
  buffer.writeUInt16LE(56, 54);
  buffer.writeUInt16LE(0, 56);
  buffer.writeUInt16LE(64, 58);
  buffer.writeUInt16LE(0, 60);
  buffer.writeUInt16LE(0, 62);
  return buffer;
}

export function create_wasm_fixture() {
  return Buffer.from([0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,0x01,0x01,0x00]);
}

export function create_zip_fixture(entry_name = 'sample.txt', contents = 'hello') {
  const name = Buffer.from(entry_name, 'utf8');
  const payload = Buffer.from(contents, 'utf8');
  const local_size = 30 + name.length + payload.length;
  const central_size = 46 + name.length;
  const eocd_size = 22;
  const buffer = Buffer.alloc(local_size + central_size + eocd_size);
  buffer.writeUInt32LE(0x04034b50, 0);
  buffer.writeUInt16LE(20, 4);
  buffer.writeUInt32LE(0, 6);
  buffer.writeUInt16LE(0, 8);
  buffer.writeUInt32LE(0, 14);
  buffer.writeUInt32LE(payload.length, 18);
  buffer.writeUInt32LE(payload.length, 22);
  buffer.writeUInt16LE(name.length, 26);
  buffer.writeUInt16LE(0, 28);
  name.copy(buffer, 30);
  payload.copy(buffer, 30 + name.length);
  const central = local_size;
  buffer.writeUInt32LE(0x02014b50, central);
  buffer.writeUInt16LE(0x0314, central + 4);
  buffer.writeUInt16LE(20, central + 6);
  buffer.writeUInt16LE(0, central + 8);
  buffer.writeUInt16LE(0, central + 10);
  buffer.writeUInt32LE(0, central + 16);
  buffer.writeUInt32LE(payload.length, central + 20);
  buffer.writeUInt32LE(payload.length, central + 24);
  buffer.writeUInt16LE(name.length, central + 28);
  buffer.writeUInt16LE(0, central + 30);
  buffer.writeUInt16LE(0, central + 32);
  buffer.writeUInt16LE(0, central + 34);
  buffer.writeUInt32LE(0, central + 38);
  buffer.writeUInt32LE(0, central + 42);
  name.copy(buffer, central + 46);
  const eocd = central + central_size;
  buffer.writeUInt32LE(0x06054b50, eocd);
  buffer.writeUInt16LE(0, eocd + 4);
  buffer.writeUInt16LE(0, eocd + 6);
  buffer.writeUInt16LE(1, eocd + 8);
  buffer.writeUInt16LE(1, eocd + 10);
  buffer.writeUInt32LE(central_size, eocd + 12);
  buffer.writeUInt32LE(central, eocd + 16);
  buffer.writeUInt16LE(0, eocd + 20);
  return buffer;
}
