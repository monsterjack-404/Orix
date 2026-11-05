// JavaScript, tests/helpers.mjs, Node.js 20+, deterministic binary fixture builders.
import { createHash } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';

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

export function create_pdf_fixture() {
  const parts = ['%PDF-1.7\n', '1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n', '2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n', '3 0 obj\n<< /S /JavaScript /JS (app.alert) >>\nendobj\n'];
  let offset = 0;
  const offsets = [0];
  for (let index = 1; index < parts.length; index += 1) {
    offsets[index] = offset + Buffer.byteLength(parts.slice(0, index).join(''), 'latin1');
  }
  const body = parts.join('');
  const xref_offset = Buffer.byteLength(body, 'latin1');
  const xref = ['xref\n0 4\n', '0000000000 65535 f \n'];
  for (let index = 1; index < offsets.length; index += 1) xref.push(String(offsets[index]).padStart(10, '0') + ' 00000 n \n');
  xref.push('trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n' + xref_offset + '\n%%EOF\n');
  return Buffer.from(body + xref.join(''), 'latin1');
}

function fixture_crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function create_zip_entries(entries) {
  const records = entries.map(entry => { const raw = Buffer.from(entry.contents); const method = entry.method ?? 0; return { name: Buffer.from(entry.name, 'utf8'), raw, payload: method === 8 ? deflateRawSync(raw) : raw, method, crc: fixture_crc32(raw) }; });
  const local_parts = [];
  const central_parts = [];
  let offset = 0;
  for (const record of records) {
    const local = Buffer.alloc(30 + record.name.length + record.payload.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(record.method, 8);
    local.writeUInt32LE(record.crc, 14);
    local.writeUInt32LE(record.payload.length, 18);
    local.writeUInt32LE(record.raw.length, 22);
    local.writeUInt16LE(record.name.length, 26);
    local.writeUInt16LE(0, 28);
    record.name.copy(local, 30);
    record.payload.copy(local, 30 + record.name.length);
    local_parts.push(local);
    const central = Buffer.alloc(46 + record.name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x0314, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(record.method, 10);
    central.writeUInt32LE(record.crc, 16);
    central.writeUInt32LE(record.payload.length, 20);
    central.writeUInt32LE(record.raw.length, 24);
    central.writeUInt16LE(record.name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    record.name.copy(central, 46);
    central_parts.push(central);
    offset += local.length;
  }
  const central_bytes = Buffer.concat(central_parts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(records.length, 8);
  eocd.writeUInt16LE(records.length, 10);
  eocd.writeUInt32LE(central_bytes.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...local_parts, central_bytes, eocd]);
}

function finalize_dex_integrity(buffer) {
  createHash('sha1').update(buffer.subarray(32)).digest().copy(buffer, 12);
  let a = 1;
  let b = 0;
  for (let i = 12; i < buffer.length; i += 1) {
    a = (a + buffer[i]) % 65521;
    b = (b + a) % 65521;
  }
  buffer.writeUInt32LE(((b << 16) | a) >>> 0, 8);
  return buffer;
}

export function create_minimal_dex_fixture() {
  const buffer = Buffer.alloc(0x70);
  buffer.write('dex\n039\0', 0, 'binary');
  buffer.writeUInt32LE(buffer.length, 0x20);
  buffer.writeUInt32LE(0x70, 0x24);
  buffer.writeUInt32LE(0x12345678, 0x28);
  return finalize_dex_integrity(buffer);
}


export function create_dex_class_fixture(descriptor = 'Lcom/example/App;') {
  const text = Buffer.from(descriptor, 'utf8');
  const string_data_offset = 0x98;
  const buffer = Buffer.alloc(string_data_offset + 1 + text.length + 1);
  buffer.write('dex\n039\0', 0, 'binary');
  buffer.writeUInt32LE(buffer.length, 0x20);
  buffer.writeUInt32LE(0x70, 0x24);
  buffer.writeUInt32LE(0x12345678, 0x28);
  buffer.writeUInt32LE(buffer.length - string_data_offset, 0x68);
  buffer.writeUInt32LE(string_data_offset, 0x6c);
  buffer.writeUInt32LE(1, 0x38);
  buffer.writeUInt32LE(0x70, 0x3c);
  buffer.writeUInt32LE(1, 0x40);
  buffer.writeUInt32LE(0x74, 0x44);
  buffer.writeUInt32LE(1, 0x60);
  buffer.writeUInt32LE(0x78, 0x64);
  buffer.writeUInt32LE(string_data_offset, 0x70);
  buffer.writeUInt32LE(0, 0x74);
  buffer.writeUInt32LE(0, 0x78);
  buffer.writeUInt32LE(1, 0x7c);
  buffer.writeUInt32LE(0xffffffff, 0x80);
  buffer.writeUInt32LE(0, 0x84);
  buffer.writeUInt32LE(0xffffffff, 0x88);
  buffer.writeUInt32LE(0, 0x8c);
  buffer.writeUInt32LE(0, 0x90);
  buffer.writeUInt32LE(0, 0x94);
  buffer.writeUInt8(text.length, string_data_offset);
  text.copy(buffer, string_data_offset + 1);
  buffer.writeUInt8(0, string_data_offset + 1 + text.length);
  return finalize_dex_integrity(buffer);
}

function write_tar_octal(buffer, offset, length, value) {
  const text = value.toString(8).padStart(length - 1, '0') + '\0';
  buffer.write(text, offset, length, 'ascii');
}

export function create_tar_fixture(entries = []) {
  const blocks = [];
  for (const entry of entries) {
    const payload = Buffer.from(entry.contents ?? '');
    const header = Buffer.alloc(512);
    header.write(entry.name ?? 'file', 0, 100, 'utf8');
    write_tar_octal(header, 100, 8, entry.mode ?? 0o100644);
    write_tar_octal(header, 108, 8, entry.uid ?? 1000);
    write_tar_octal(header, 116, 8, entry.gid ?? 1000);
    write_tar_octal(header, 124, 12, entry.size_override ?? payload.length);
    write_tar_octal(header, 136, 12, entry.mtime ?? 1);
    header.fill(0x20, 148, 156);
    header.write(entry.typeflag ?? '0', 156, 1, 'ascii');
    if (entry.linkname) header.write(entry.linkname, 157, 100, 'utf8');
    header.write('ustar\0', 257, 6, 'binary');
    header.write('00', 263, 2, 'ascii');
    header.write('root', 265, 32, 'ascii');
    header.write('root', 297, 32, 'ascii');
    write_tar_octal(header, 329, 8, entry.devmajor ?? 0);
    write_tar_octal(header, 337, 8, entry.devminor ?? 0);
    if (entry.prefix) header.write(entry.prefix, 345, 155, 'utf8');
    let checksum = 0;
    for (const byte of header) checksum += byte;
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
    blocks.push(header);
    blocks.push(payload);
    const padding = (512 - (payload.length % 512)) % 512;
    if (padding) blocks.push(Buffer.alloc(padding));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

export function create_pax_record(key, value) {
  const body = Buffer.from(key + '=' + value + '\n', 'utf8');
  let length = body.length + 2;
  while (true) {
    const next = body.length + String(length).length + 1;
    if (next === length) return Buffer.concat([Buffer.from(String(length) + ' ', 'ascii'), body]);
    length = next;
  }
}
