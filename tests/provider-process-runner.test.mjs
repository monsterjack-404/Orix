// JavaScript, tests/provider-process-runner.test.mjs, Node.js 20+, bounded process runner regressions.

import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { run_static_provider } from '../src/providers/process-runner.mjs';

function manifest(overrides = {}) {
  return {
    contract_version: 'orix.provider.v1',
    id: 'test.static',
    name: 'Static test provider',
    version: '1.0.0',
    description: 'A test-only static provider.',
    capabilities: ['test.process'],
    supported_platforms: ['linux', 'windows', 'macos'],
    input_formats: ['test'],
    execution: {
      mode: 'static',
      requires_authorization: false,
      executes_target: false,
      writes_target: false,
      uses_network: false,
    },
    limits: {
      timeout_ms: 5000,
      max_input_bytes: 1024 * 1024,
      max_output_bytes: 64 * 1024,
    },
    license: { spdx_id: 'MIT', redistribution: 'external-install' },
    ...overrides,
  };
}

async function with_directory(callback) {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-process-test-'));
  try { await callback(directory); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

async function node_executable() {
  return realpath(process.execPath);
}

test('static provider runner uses argv without shell interpolation and returns bounded diagnostics', async () => {
  const result = await run_static_provider({
    manifest: manifest(),
    executable: await node_executable(),
    args: ['-e', 'process.stdout.write(process.argv[1]); process.stderr.write("diagnostic");', 'literal $(not-a-shell) value'],
    env: { ORIX_CHILD_TEST: 'present' },
    timeout_ms: 1000,
  });
  assert.equal(result.ok, true);
  assert.equal(result.schema_version, 'orix.provider-execution.v1');
  assert.equal(result.success, true);
  assert.equal(result.termination_reason, null);
  assert.equal(result.args_count, 3);
  assert.equal(result.output.bytes_captured, result.captured_bytes);
  assert.ok(result.completed_at);
  assert.equal(result.stdout, 'literal $(not-a-shell) value');
  assert.equal(result.stderr, 'diagnostic');
  assert.equal(result.provider.id, 'test.static');
  assert.equal(result.schema_version, 'orix.provider-execution.v1');
  assert.ok(Number.isFinite(Date.parse(result.started_at)));
  assert.ok(Number.isFinite(Date.parse(result.completed_at)));
  assert.equal(result.termination_reason, null);
  assert.equal(result.success, true);
  assert.equal(result.output.stdout, result.stdout);
  assert.equal(result.output.bytes_captured, result.captured_bytes);
  assert.equal(result.limits.timeout_ms, 1000);
  assert.equal(result.stdout_bytes, Buffer.byteLength(result.stdout));
  assert.equal(result.stderr_bytes, Buffer.byteLength(result.stderr));
});

test('static provider runner prepends bounded executable arguments without shell evaluation', async () => {
  const result = await run_static_provider({
    manifest: manifest(),
    executable: await node_executable(),
    executable_args: ['-e', 'process.stdout.write(process.argv.slice(1).join("|"))'],
    args: ['first literal', 'second $(not-a-shell) literal'],
  });
  assert.equal(result.ok, true);
  assert.equal(result.stdout, 'first literal|second $(not-a-shell) literal');
  assert.equal(result.args_count, 4);
});

test('static provider runner does not inherit the parent environment by default', async () => {
  const key = 'ORIX_PROCESS_RUNNER_PARENT_SECRET';
  const previous = process.env[key];
  process.env[key] = 'must-not-leak';
  try {
    const result = await run_static_provider({
      manifest: manifest(),
      executable: await node_executable(),
      args: ['-e', 'process.stdout.write(process.env.ORIX_PROCESS_RUNNER_PARENT_SECRET || "absent")'],
    });
    assert.equal(result.ok, true);
    assert.equal(result.stdout, 'absent');
  } finally {
    if (previous === undefined) delete process.env[key];
    else process.env[key] = previous;
  }
});

test('static provider runner reports non-zero exit status instead of hiding it', async () => {
  const result = await run_static_provider({
    manifest: manifest(),
    executable: await node_executable(),
    args: ['-e', 'process.stderr.write("failure"); process.exitCode = 7;'],
  });
  assert.equal(result.ok, false);
  assert.equal(result.exit_code, 7);
  assert.equal(result.stderr, 'failure');
});

test('static provider runner enforces the per-run output ceiling', async () => {
  const result = await run_static_provider({
    manifest: manifest(),
    executable: await node_executable(),
    args: ['-e', 'process.stdout.write("x".repeat(8192))'],
    max_output_bytes: 1024,
    kill_grace_ms: 20,
  });
  assert.equal(result.output_limited, true);
  assert.equal(result.termination_reason, 'output-limit');
  assert.equal(result.output_truncated, true);
  assert.ok(result.captured_bytes <= 1024);
  assert.equal(result.ok, false);
});

test('static provider runner terminates providers at the configured deadline', async () => {
  const result = await run_static_provider({
    manifest: manifest(),
    executable: await node_executable(),
    args: ['-e', 'setTimeout(() => {}, 5000)'],
    timeout_ms: 40,
    kill_grace_ms: 20,
  });
  assert.equal(result.timed_out, true);
  assert.equal(result.termination_reason, 'timeout');
  assert.equal(result.ok, false);
});

test('Windows static provider timeout terminates the spawned process tree', {
  skip: process.platform !== 'win32',
}, async () => {
  const child_source = 'setInterval(() => {}, 1000)';
  const parent_source = [
    "const { spawn } = require('node:child_process');",
    "const descendant = spawn(process.execPath, ['-e', " + JSON.stringify(child_source) + "], { stdio: 'ignore', windowsHide: true });",
    'process.stdout.write(String(descendant.pid));',
    'setInterval(() => {}, 1000);',
  ].join('\n');

  const result = await run_static_provider({
    manifest: manifest(),
    executable: await node_executable(),
    args: ['-e', parent_source],
    timeout_ms: 1500,
    kill_grace_ms: 20,
  });

  assert.equal(result.timed_out, true);
  assert.equal(result.termination_reason, 'timeout');
  const descendant_pid = Number(result.stdout.trim());
  assert.ok(Number.isSafeInteger(descendant_pid) && descendant_pid > 0,
    'the test provider must report its spawned descendant PID');

  let descendant_exited = false;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      process.kill(descendant_pid, 0);
    } catch (error) {
      if (error.code === 'ESRCH') {
        descendant_exited = true;
        break;
      }
      throw error;
    }
    await new Promise(resolve => setTimeout(resolve, 50));
  }

  if (!descendant_exited) {
    try { process.kill(descendant_pid); } catch {
      // Best-effort cleanup so a failed regression test does not leak a process.
    }
  }
  assert.equal(descendant_exited, true,
    'Windows timeout must terminate provider descendants, not only the direct child');
});

test('static provider runner supports AbortSignal cancellation', async () => {
  const controller = new AbortController();
  // Executable/cwd validation can be substantially slower on Windows CI;
  // wait long enough that this exercises cancellation after child launch rather
  // than the documented pre-launch cancellation path.
  const abort_timer = setTimeout(() => controller.abort(), 1_500);
  try {
    const result = await run_static_provider({
      manifest: manifest(),
      executable: await node_executable(),
      args: ['-e', 'setTimeout(() => {}, 5000)'],
      signal: controller.signal,
      timeout_ms: 2000,
      kill_grace_ms: 20,
    });
    assert.equal(result.cancelled, true);
    assert.equal(result.termination_reason, 'cancelled');
    assert.equal(result.timed_out, false);
    assert.equal(result.ok, false);
  } finally {
    clearTimeout(abort_timer);
  }
});

test('static provider runner rejects dynamic, write-capable, network and authorization-required manifests', async () => {
  const dynamic = manifest({
    execution: {
      mode: 'dynamic',
      requires_authorization: true,
      executes_target: true,
      writes_target: false,
      uses_network: false,
    },
  });
  await assert.rejects(
    run_static_provider({ manifest: dynamic, executable: await node_executable(), args: [] }),
    error => error.code === 'ORIX_PROVIDER_EXECUTION_NOT_STATIC',
  );
});

test('static provider runner rejects NUL, sparse, accessor-backed and custom-property argv arrays', async () => {
  const executable = await node_executable();
  await assert.rejects(
    run_static_provider({ manifest: manifest(), executable, args: ['bad\0arg'] }),
    /without NUL bytes/,
  );
  const sparse = new Array(1);
  await assert.rejects(
    run_static_provider({ manifest: manifest(), executable, args: sparse }),
    /must not be sparse/,
  );
  const accessor = [];
  Object.defineProperty(accessor, '0', {
    enumerable: true,
    get() { throw new Error('getter must not run'); },
  });
  accessor.length = 1;
  await assert.rejects(
    run_static_provider({ manifest: manifest(), executable, args: accessor }),
    /data elements only/,
  );
  const custom = [];
  custom.extra = 'hidden';
  await assert.rejects(
    run_static_provider({ manifest: manifest(), executable, args: custom }),
    /custom array properties/,
  );
});

test('static provider runner rejects symlink executables and working directories', async () => {
  await with_directory(async directory => {
    const executable = await node_executable();
    const executable_link = path.join(directory, 'node-link');
    const cwd_link = path.join(directory, 'cwd-link');
    const cwd_target = path.join(directory, 'cwd-target');
    await symlink(executable, executable_link, process.platform === 'win32' ? 'file' : undefined);
    await import('node:fs/promises').then(fs => fs.mkdir(cwd_target));
    await symlink(cwd_target, cwd_link, process.platform === 'win32' ? 'junction' : undefined);
    await assert.rejects(
      run_static_provider({ manifest: manifest(), executable: executable_link, args: [] }),
      error => error.code === 'ORIX_PROVIDER_EXECUTABLE_NOT_REGULAR',
    );
    await assert.rejects(
      run_static_provider({ manifest: manifest(), executable, args: [], cwd: cwd_link }),
      error => error.code === 'ORIX_PROVIDER_CWD_INVALID',
    );
  });
});

test('static provider runner rejects invalid environment accessors without invoking them', async () => {
  let getter_called = false;
  const env = {};
  Object.defineProperty(env, 'ORIX_BAD', {
    enumerable: true,
    get() { getter_called = true; throw new Error('must not run'); },
  });
  await assert.rejects(
    run_static_provider({
      manifest: manifest(),
      executable: await node_executable(),
      args: [],
      env,
    }),
    /enumerable string data properties/,
  );
  assert.equal(getter_called, false);
});

test('static provider runner rejects non-absolute executable paths before spawning', async () => {
  await assert.rejects(
    run_static_provider({ manifest: manifest(), executable: 'node', args: [] }),
    /absolute filesystem path/,
  );
});


test('static provider runner restricts executable launch to the exact canonical allowlist', async () => {
  const executable = await node_executable();
  await assert.rejects(
    run_static_provider({
      manifest: manifest(),
      executable,
      allowed_executables: [],
      args: [],
    }),
    /allowed_executables must contain/,
  );
  await assert.rejects(
    run_static_provider({
      manifest: manifest(),
      executable,
      allowed_executables: ['/definitely/not/the/node/executable'],
      args: [],
    }),
    error => error.code === 'ORIX_PROVIDER_ALLOWLIST_UNAVAILABLE',
  );
});

test('static provider runner confines its working directory to an explicit allowed root', async () => {
  await with_directory(async allowed_root => {
    const outside = await mkdtemp(path.join(tmpdir(), 'orix-cwd-outside-'));
    try {
      await assert.rejects(
        run_static_provider({
          manifest: manifest(),
          executable: await node_executable(),
          args: [],
          cwd: outside,
          allowed_working_directories: [allowed_root],
        }),
        error => error.code === 'ORIX_PROVIDER_CWD_DENIED',
      );
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });
});

test('static provider runner rejects symlinks inside executable and working-directory allowlists', async () => {
  await with_directory(async directory => {
    const executable = await node_executable();
    const executable_link = path.join(directory, 'node-allowlist-link');
    const root_link = path.join(directory, 'cwd-allowlist-link');
    const root_target = path.join(directory, 'cwd-allowlist-target');
    await symlink(executable, executable_link, process.platform === 'win32' ? 'file' : undefined);
    await import('node:fs/promises').then(fs => fs.mkdir(root_target));
    await symlink(root_target, root_link, process.platform === 'win32' ? 'junction' : undefined);
    await assert.rejects(
      run_static_provider({
        manifest: manifest(),
        executable,
        allowed_executables: [executable_link],
        args: [],
      }),
      error => error.code === 'ORIX_PROVIDER_ALLOWLIST_UNSAFE',
    );
    await assert.rejects(
      run_static_provider({
        manifest: manifest(),
        executable,
        args: [],
        cwd: root_target,
        allowed_working_directories: [root_link],
      }),
      error => error.code === 'ORIX_PROVIDER_CWD_ALLOWLIST_UNSAFE',
    );
  });
});

test('static provider runner rejects PATH and executable-loader environment overrides', async () => {
  const executable = await node_executable();
  for (const key of ['PATH', 'NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES']) {
    await assert.rejects(
      run_static_provider({
        manifest: manifest(),
        executable,
        args: [],
        env: { [key]: 'attacker-controlled-value' },
      }),
      /enumerable string data properties with valid names/,
    );
  }
});


test('static provider runner rejects NUL bytes in executable and working-directory allowlists', async () => {
  const executable = await node_executable();
  await assert.rejects(
    run_static_provider({
      manifest: manifest(),
      executable,
      allowed_executables: [executable + '\0suffix'],
      args: [],
    }),
    /absolute paths without NUL bytes/,
  );
  await assert.rejects(
    run_static_provider({
      manifest: manifest(),
      executable,
      cwd: process.cwd() + '\0suffix',
      args: [],
    }),
    /cwd must be an absolute filesystem path/,
  );
});
