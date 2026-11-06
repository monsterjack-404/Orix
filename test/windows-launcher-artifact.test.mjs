import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectWindowsLauncher } from '../scripts/verify-windows-launcher.mjs';

test('Windows launcher artifact verifier rejects non-PE and truncated inputs', () => {
  assert.throws(() => inspectWindowsLauncher(Buffer.from('not a PE image')), /too small|MZ signature/);
  const mzOnly = Buffer.alloc(128);
  mzOnly.write('MZ', 0, 'ascii');
  mzOnly.writeUInt32LE(64, 0x3c);
  assert.throws(() => inspectWindowsLauncher(mzOnly), /PE signature/);
});
