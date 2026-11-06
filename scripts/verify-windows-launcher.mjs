#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function fail(message) {
  throw new Error('Windows launcher artifact validation failed: ' + message);
}

function u16(bytes, offset, label) {
  if (offset < 0 || offset + 2 > bytes.length) fail('truncated ' + label);
  return bytes.readUInt16LE(offset);
}
function u32(bytes, offset, label) {
  if (offset < 0 || offset + 4 > bytes.length) fail('truncated ' + label);
  return bytes.readUInt32LE(offset);
}
function rvaToOffset(bytes, sections, rva, size, label) {
  for (const section of sections) {
    const virtualAddress = section.virtualAddress;
    const span = Math.max(section.virtualSize, section.rawSize);
    if (rva < virtualAddress || rva - virtualAddress >= span) continue;
    const delta = rva - virtualAddress;
    if (delta + size > section.rawSize) fail(label + ' extends beyond section raw data');
    const offset = section.rawPointer + delta;
    if (offset + size > bytes.length) fail(label + ' extends beyond file');
    return offset;
  }
  fail(label + ' RVA is not mapped by a PE section');
}

export function inspectWindowsLauncher(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 0x40) fail('file is too small');
  if (bytes.toString('ascii', 0, 2) !== 'MZ') fail('missing DOS MZ signature');
  const peOffset = u32(bytes, 0x3c, 'PE header offset');
  if (bytes.toString('ascii', peOffset, peOffset + 4) !== 'PE\0\0') fail('missing PE signature');

  const machine = u16(bytes, peOffset + 4, 'COFF machine');
  const sectionCount = u16(bytes, peOffset + 6, 'section count');
  const optionalSize = u16(bytes, peOffset + 20, 'optional header size');
  const optionalOffset = peOffset + 24;
  const magic = u16(bytes, optionalOffset, 'optional header magic');
  if (machine !== 0x014c || magic !== 0x010b) {
    fail('expected an architecture-neutral .NET AnyCPU PE32 image (I386/PE32)');
  }
  if (sectionCount < 1 || sectionCount > 96) fail('invalid PE section count');
  const directoryOffset = optionalOffset + 96;
  if (optionalSize < 96 + (15 * 8)) fail('optional header has no CLR data-directory entry');
  const clrRva = u32(bytes, directoryOffset + (14 * 8), 'CLR directory RVA');
  const clrSize = u32(bytes, directoryOffset + (14 * 8) + 4, 'CLR directory size');
  if (!clrRva || clrSize < 0x48) fail('missing or truncated CLR header');

  const sectionOffset = optionalOffset + optionalSize;
  const sections = [];
  for (let index = 0; index < sectionCount; index++) {
    const offset = sectionOffset + index * 40;
    if (offset + 40 > bytes.length) fail('truncated section table');
    sections.push({
      virtualSize: u32(bytes, offset + 8, 'section virtual size'),
      virtualAddress: u32(bytes, offset + 12, 'section virtual address'),
      rawSize: u32(bytes, offset + 16, 'section raw size'),
      rawPointer: u32(bytes, offset + 20, 'section raw pointer'),
    });
  }

  const clrOffset = rvaToOffset(bytes, sections, clrRva, 0x48, 'CLR header');
  const clrHeaderSize = u32(bytes, clrOffset, 'CLR header size');
  if (clrHeaderSize < 0x48 || clrHeaderSize > clrSize) fail('invalid CLR header size');
  const metadataRva = u32(bytes, clrOffset + 8, 'CLR metadata RVA');
  const metadataSize = u32(bytes, clrOffset + 12, 'CLR metadata size');
  if (!metadataRva || metadataSize < 4) fail('missing CLR metadata');
  rvaToOffset(bytes, sections, metadataRva, 4, 'CLR metadata');
  const flags = u32(bytes, clrOffset + 16, 'CLR flags');
  const ilOnly = (flags & 0x00000001) !== 0;
  const requires32Bit = (flags & 0x00000002) !== 0;
  const prefers32Bit = (flags & 0x00020000) !== 0;
  if (!ilOnly || requires32Bit || prefers32Bit) {
    fail('launcher must be IL-only AnyCPU without 32-bit-required/preferred flags');
  }
  return { machine, sections: sectionCount, clrRva, clrSize, flags };
}

async function main() {
  const input = process.argv[2];
  if (!input) fail('usage: node scripts/verify-windows-launcher.mjs <launcher.exe>');
  const bytes = await readFile(path.resolve(input));
  const metadata = inspectWindowsLauncher(bytes);
  const sha256 = createHash('sha256').update(bytes).digest('hex').toUpperCase();
  process.stdout.write(JSON.stringify({ file: path.basename(input), size: bytes.length, sha256, ...metadata }, null, 2) + '\n');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
}
