// JavaScript, tests/linux-cgroup-v2-bootstrap.test.mjs, Linux descriptor-handoff regression tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { closeSync, fstatSync, openSync, readFileSync, readSync, writeFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const project_root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bootstrap_path = path.join(project_root, 'src/providers/linux-cgroup-v2-bootstrap.mjs');

async function with_directory(callback) {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-cgroup-bootstrap-'));
  try {
    await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function run_bootstrap_with_fd(fd, args, { close_parent_fd = true } = {}) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(process.execPath, [bootstrap_path, ...args], {
        cwd: project_root,
        env: {},
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe', fd],
      });
    } catch (error) {
      if (close_parent_fd) closeSync(fd);
      reject(error);
      return;
    }

    // The default mirrors the host contract: drop its copy after inheritance.
    // One regression test retains the test harness copy for positional readback.
    if (close_parent_fd) closeSync(fd);
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

if (process.platform === 'linux') {
  test('bootstrap attaches before provider launch and does not leak fd 3', { timeout: 10_000 }, async () => {
    await with_directory(async directory => {
      const attach_file = path.join(directory, 'attach-capability');
      // Create the fixture and obtain its read/write capability in one
      // exclusive open, avoiding a create-then-reopen pathname sequence.
      const fd = openSync(attach_file, 'wx+');
      try {
        const attach_info = fstatSync(fd);
        const provider_code = [
          "const { fstatSync } = require('node:fs');",
          "const expectedDev = process.argv[1];",
          "const expectedIno = process.argv[2];",
          "let leaked = false;",
          "try { const actual = fstatSync(3); leaked = String(actual.dev) === expectedDev && String(actual.ino) === expectedIno; }",
          "catch (error) { if (error.code !== 'EBADF') throw error; }",
          "process.stdout.write(!leaked ? 'attached-and-closed' : 'failed');"
        ].join(' ');
        const result = await run_bootstrap_with_fd(fd, [
          '--attach-fd=3', '--', process.execPath, '-e', provider_code, String(attach_info.dev), String(attach_info.ino),
        ], { close_parent_fd: false });

        assert.equal(result.code, 0, result.stderr);
        assert.equal(result.signal, null);
        assert.equal(result.stdout, 'attached-and-closed');
        const membership_buffer = Buffer.alloc(64);
        const bytes_read = readSync(fd, membership_buffer, 0, membership_buffer.length, 0);
        assert.match(membership_buffer.subarray(0, bytes_read).toString('utf8'), /^\d+\n$/);
      } finally {
        closeSync(fd);
      }
    });
  });

  test('bootstrap fails closed and never launches provider when attach write fails', { timeout: 10_000 }, async () => {
    await with_directory(async directory => {
      const attach_file = path.join(directory, 'read-only-capability');
      const launch_marker = path.join(directory, 'provider-started');
      writeFileSync(attach_file, 'read-only');
      const fd = openSync(attach_file, 'r');
      const provider_code = "const { writeFileSync } = require('node:fs'); writeFileSync(process.argv[1], 'started');";
      const result = await run_bootstrap_with_fd(fd, [
        '--attach-fd=3', '--', process.execPath, '-e', provider_code, launch_marker,
      ]);

      assert.equal(result.code, 125);
      assert.match(result.stderr, /ORIX_CGROUP_BOOTSTRAP_ATTACH_FAILED/);
      assert.throws(() => readFileSync(launch_marker), error => error.code === 'ENOENT');
    });
  });

  test('bootstrap rejects an unexpected descriptor contract before provider launch', { timeout: 10_000 }, async () => {
    await with_directory(async directory => {
      const launch_marker = path.join(directory, 'provider-started');
      const provider_code = "const { writeFileSync } = require('node:fs'); writeFileSync(process.argv[1], 'started');";
      const result = await new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [
          bootstrap_path, '--attach-fd=4', '--', process.execPath, '-e', provider_code, launch_marker,
        ], { cwd: project_root, env: {}, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
        let stderr = '';
        child.stderr.setEncoding('utf8');
        child.stderr.on('data', chunk => { stderr += chunk; });
        child.once('error', reject);
        child.once('close', code => resolve({ code, stderr }));
      });

      assert.equal(result.code, 125);
      assert.match(result.stderr, /ORIX_CGROUP_BOOTSTRAP_ARGUMENTS_INVALID/);
      assert.throws(() => readFileSync(launch_marker), error => error.code === 'ENOENT');
    });
  });
}
