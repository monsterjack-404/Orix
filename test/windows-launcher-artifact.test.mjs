import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectWindowsLauncher } from '../scripts/verify-windows-launcher.mjs';

function validLauncher() {
  const bytes = Buffer.alloc(0x500);
  const pe = 0x80;
  const optional = pe + 24;
  const section = optional + 224;
  bytes.write('MZ', 0, 'ascii');
  bytes.writeUInt32LE(pe, 0x3c);
  bytes.write('PE\0\0', pe, 'binary');
  bytes.writeUInt16LE(0x014c, pe + 4);
  bytes.writeUInt16LE(1, pe + 6);
  bytes.writeUInt16LE(224, pe + 20);
  bytes.writeUInt16LE(0x010b, optional);
  bytes.writeUInt32LE(0x2000, optional + 96 + (14 * 8));
  bytes.writeUInt32LE(0x48, optional + 96 + (14 * 8) + 4);
  bytes.writeUInt32LE(0x300, section + 8);
  bytes.writeUInt32LE(0x2000, section + 12);
  bytes.writeUInt32LE(0x300, section + 16);
  bytes.writeUInt32LE(0x200, section + 20);
  bytes.writeUInt32LE(0x48, 0x200);
  bytes.writeUInt32LE(0x2080, 0x208);
  bytes.writeUInt32LE(0x40, 0x20c);
  bytes.writeUInt32LE(1, 0x210);
  bytes.write('BSJB', 0x280, 'ascii');
  return bytes;
}

test('Windows launcher artifact verifier accepts a valid IL-only AnyCPU CLR image', () => {
  const metadata = inspectWindowsLauncher(validLauncher());
  assert.equal(metadata.machine, 0x014c);
  assert.equal(metadata.flags & 1, 1);
});

test('Windows launcher artifact verifier rejects non-PE and truncated inputs', () => {
  assert.throws(() => inspectWindowsLauncher(Buffer.from('not a PE image')), /too small|MZ signature/);
  const mzOnly = Buffer.alloc(128);
  mzOnly.write('MZ', 0, 'ascii');
  mzOnly.writeUInt32LE(64, 0x3c);
  assert.throws(() => inspectWindowsLauncher(mzOnly), /PE signature/);
});

test('Windows launcher artifact verifier rejects a non-AnyCPU architecture', () => {
  const bytes = validLauncher();
  bytes.writeUInt16LE(0x8664, 0x84);
  assert.throws(() => inspectWindowsLauncher(bytes), /architecture-neutral/);
});

test('Windows launcher artifact verifier rejects CLR metadata with a bad BSJB signature', () => {
  const bytes = validLauncher();
  bytes.write('NOPE', 0x280, 'ascii');
  assert.throws(() => inspectWindowsLauncher(bytes), /metadata signature/);
});

test('Windows launcher artifact verifier rejects CLR metadata extending beyond section data', () => {
  const bytes = validLauncher();
  bytes.writeUInt32LE(0x22f0, 0x208);
  bytes.writeUInt32LE(0x40, 0x20c);
  assert.throws(() => inspectWindowsLauncher(bytes), /extends beyond section raw data/);
});

test('Windows launcher artifact verifier rejects 32-bit-required CLR images', () => {
  const bytes = validLauncher();
  bytes.writeUInt32LE(3, 0x210);
  assert.throws(() => inspectWindowsLauncher(bytes), /IL-only AnyCPU/);
});
