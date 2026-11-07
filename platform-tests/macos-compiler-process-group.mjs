// POSIX-only macOS compiler process-group teardown regression.
// Executed explicitly on macOS; Windows has its own Job Object hostile-process gate.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cleanup_macos_compiler_process_group } from '../src/providers/macos-isolation.mjs';

test('macOS compiler cleanup waits for TERM/KILL and verifies the whole process group is empty', {
  timeout: 10_000,
}, async () => {
  const source = String.raw`
const { spawn } = require('node:child_process');
spawn(process.execPath, ['-e', 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000);'], { stdio: 'ignore' });
process.on('SIGTERM', () => {});
setTimeout(() => process.stdout.write('ready'), 150);
setInterval(() => {}, 1000);
`;
  const child = spawn(process.execPath, ['-e', source], {
    detached: true,
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  let output = '';
  let readyResolve;
  let readyReject;
  const ready = new Promise((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  const closed = new Promise(resolve => {
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', chunk => {
    output += chunk;
    if (output.includes('ready')) readyResolve();
  });
  child.once('error', readyReject);

  let cleanupResult = null;
  try {
    await ready;
    cleanupResult = await cleanup_macos_compiler_process_group(child.pid, {
      term_grace_ms: 100,
      verify_timeout_ms: 5000,
    });
    assert.equal(cleanupResult.term_signal_sent, true);
    assert.equal(cleanupResult.force_kill_sent, true,
      'SIGKILL escalation should be required because both controlled processes ignore SIGTERM');
    assert.equal(cleanupResult.verified_empty, true);
    await closed;
  } finally {
    if (cleanupResult?.verified_empty !== true) {
      await cleanup_macos_compiler_process_group(child.pid, {
        term_grace_ms: 100,
        verify_timeout_ms: 5000,
      }).catch(() => {});
    }
  }
});
