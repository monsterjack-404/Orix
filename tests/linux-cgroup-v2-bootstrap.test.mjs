// JavaScript, tests/linux-cgroup-v2-bootstrap.test.mjs, Linux descriptor-handoff regression tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { closeSync, openSync, readFileSync, readlinkSync, writeFileSync } from 'node:fs';
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

function run_bootstrap_with_fd(fd, args) {
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
      closeSync(fd);
      reject(error);
      return;
    }

    // The child has received its dedicated fd 3; the host must drop its copy.
    closeSync(fd);
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
      writeFileSync(attach_file, '');
      const fd = openSync(attach_file, 'w');
      const provider_code = [
        "const { readFileSync, readlinkSync } = require('node:fs');",
        "const marker = process.argv[1];",
        "const membership = readFileSync(marker, 'utf8');",
        "let leaked = false;",
        "try { leaked = readlinkSync('/proc/self/fd/3').includes(marker); }",
        "catch (error) { if (error.code !== 'ENOENT') throw error; }",
        "process.stdout.write(/^\\d+\\n$/.test(membership) && !leaked ? 'attached-and-closed' : 'failed');",
      ].join(' ');
      const result = await run_bootstrap_with_fd(fd, [
        '--attach-fd=3', '--', process.execPath, '-e', provider_code, attach_file,
      ]);

      assert.equal(result.code, 0, result.stderr);
      assert.equal(result.signal, null);
      assert.equal(result.stdout, 'attached-and-closed');
      assert.match(readFileSync(attach_file, 'utf8'), /^\\d+\\n$/);
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
