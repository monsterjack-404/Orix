import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { inspectWindowsLauncher, verifyWindowsLauncher } from '../scripts/verify-windows-launcher.mjs';
import { decodeWindowsProviderLauncher, decodeWindowsProviderLauncherBase64, WINDOWS_PROVIDER_LAUNCHER_SHA256 } from '../src/providers/windows-launcher-integrity.mjs';

function makeAnyCpuPe() {
  const bytes = Buffer.alloc(0x400);
  bytes.write('MZ', 0, 'ascii');
  bytes.writeUInt32LE(0x80, 0x3c);
  bytes.write('PE\0\0', 0x80, 'binary');
  const coff = 0x84;
  bytes.writeUInt16LE(0x014c, coff);
  bytes.writeUInt16LE(1, coff + 2);
  bytes.writeUInt16LE(224, coff + 16);
  const optional = coff + 20;
  bytes.writeUInt16LE(0x010b, optional);
  bytes.writeUInt32LE(16, optional + 92);
  bytes.writeUInt32LE(0x2000, optional + 96 + (14 * 8));
  bytes.writeUInt32LE(0x48, optional + 96 + (14 * 8) + 4);
  const section = optional + 224;
  bytes.writeUInt32LE(0x200, section + 8);
  bytes.writeUInt32LE(0x2000, section + 12);
  bytes.writeUInt32LE(0x200, section + 16);
  bytes.writeUInt32LE(0x200, section + 20);
  const clr = 0x200;
  bytes.writeUInt32LE(0x48, clr);
  bytes.writeUInt32LE(0x2080, clr + 8);
  bytes.writeUInt32LE(4, clr + 12);
  bytes.writeUInt32LE(1, clr + 16);
  bytes.writeUInt32LE(0x424a5342, 0x280);
  return bytes;
}
async function readPackagedLauncherPayload() {
  const parts = [
    new URL('../native/bin/win32-anycpu/launcher-payload-01.b64', import.meta.url),
    new URL('../native/bin/win32-anycpu/launcher-payload-02.b64', import.meta.url),
    new URL('../native/bin/win32-anycpu/launcher-payload-03.b64', import.meta.url),
    new URL('../native/bin/win32-anycpu/launcher-payload-04.b64', import.meta.url),
  ];
  const encoded = (await Promise.all(parts.map(url => readFile(url, 'utf8')))).join('');
  return decodeWindowsProviderLauncherBase64(encoded);
}

test('Windows launcher artifact verifier accepts IL-only architecture-neutral AnyCPU PE images', () => {
  const result = inspectWindowsLauncher(makeAnyCpuPe());
  assert.equal(result.machine, 0x014c);
  assert.equal(result.flags, 1);
});

test('Windows launcher artifact verifier rejects non-PE and truncated inputs', () => {
  assert.throws(() => inspectWindowsLauncher(Buffer.from('not a PE image')), /too small|MZ signature/);
  const mzOnly = Buffer.alloc(128);
  mzOnly.write('MZ', 0, 'ascii');
  mzOnly.writeUInt32LE(64, 0x3c);
  assert.throws(() => inspectWindowsLauncher(mzOnly), /PE signature/);
});

test('Windows launcher artifact verifier rejects 32-bit-required and malformed CLR metadata', () => {
  const requires32Bit = makeAnyCpuPe();
  requires32Bit.writeUInt32LE(3, 0x200 + 16);
  assert.throws(() => inspectWindowsLauncher(requires32Bit), /IL-only AnyCPU/);
  const badMetadata = makeAnyCpuPe();
  badMetadata.writeUInt32LE(0, 0x280);
  assert.throws(() => inspectWindowsLauncher(badMetadata), /metadata signature/);
});

test('Windows launcher artifact verifier rejects a CLR directory extending past section raw data', () => {
  const truncatedDirectory = makeAnyCpuPe();
  truncatedDirectory.writeUInt32LE(0x201, 0x84 + 20 + 96 + (14 * 8) + 4);
  assert.throws(() => inspectWindowsLauncher(truncatedDirectory), /CLR directory extends beyond section raw data/);
});

test('source-pinned launcher payload segments decode to the exact reviewed AnyCPU executable', async () => {
  const payload = await readPackagedLauncherPayload();
  const bytes = decodeWindowsProviderLauncher(payload);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), WINDOWS_PROVIDER_LAUNCHER_SHA256);
  assert.equal(bytes.toString('ascii', 0, 2), 'MZ');
  assert.equal(inspectWindowsLauncher(bytes).machine, 0x014c);
});

test('launcher payload base64 rejects malformed and non-canonical input', () => {
  assert.throws(() => decodeWindowsProviderLauncherBase64('%%%='), /invalid size or alphabet/);
  assert.throws(() => decodeWindowsProviderLauncherBase64('AB=='), /non-canonical/);
});

test('source-pinned launcher payload rejects modified compressed bytes', async () => {
  const payload = await readPackagedLauncherPayload();
  const changed = Buffer.from(payload);
  changed[changed.length - 1] ^= 0x01;
  assert.throws(() => decodeWindowsProviderLauncher(changed), /SHA-256 mismatch/);
});

test('Windows launcher build verifier requires the reviewed binary digest', () => {
  const synthetic = makeAnyCpuPe();
  const digest = createHash('sha256').update(synthetic).digest('hex');
  assert.equal(verifyWindowsLauncher(synthetic, digest).sha256.toLowerCase(), digest);
  assert.throws(() => verifyWindowsLauncher(synthetic), /source-pinned Windows launcher digest/);
});
