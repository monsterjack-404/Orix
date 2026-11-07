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
  assert.equal(result.isolation_cleanup.error, null);
  assert.deepEqual(result.isolation_cleanup, {
    attempted: false,
    complete: true,
    failed: false,
    reason: null,
    error: null,
    report: null,
  });
  assert.equal(typeof result.process_group_cleanup.attempted, 'boolean');
  assert.equal(typeof result.process_group_cleanup.force_kill_sent, 'boolean');
  assert.equal(typeof result.process_group_cleanup.failed, 'boolean');
  assert.ok(result.process_group_cleanup.verified_empty === null ||
    typeof result.process_group_cleanup.verified_empty === 'boolean');
  assert.equal(result.launch_setup_failed, false);
  assert.equal(result.args_count, 3);
  assert.equal(result.output.bytes_captured, result.captured_bytes);
  assert.ok(result.completed_at);
  assert.ok(Number.isSafeInteger(result.duration_ms));
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
  for (const key of [
    'PATH', 'NODE_OPTIONS', 'NODE_PATH', 'NODE_V8_COVERAGE', 'NODE_COMPILE_CACHE',
    'LD_PRELOAD', 'LD_AUDIT', 'LD_DEBUG_OUTPUT', 'GCONV_PATH',
    'DYLD_INSERT_LIBRARIES', 'DYLD_FALLBACK_LIBRARY_PATH', 'DYLD_ROOT_PATH',
    'ld_audit',
  ]) {
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


test('required provider isolation fails closed when no sandbox root is supplied', async () => {
  await assert.rejects(
    run_static_provider({
      manifest: manifest(),
      executable: await node_executable(),
      args: [],
      isolation: 'required',
    }),
    error => process.platform === 'linux'
      ? /sandbox_root must be an absolute filesystem path/.test(error.message)
      : error.code === 'ORIX_PROVIDER_ISOLATION_UNAVAILABLE',
  );
});

test('provider isolation rejects unknown isolation modes before launch', async () => {
  await assert.rejects(
    run_static_provider({
      manifest: manifest(),
      executable: await node_executable(),
      args: [],
      isolation: 'best-effort',
    }),
    /isolation must be either none or required/,
  );
});

test('required provider isolation refuses executable and cwd paths outside its rootfs', async () => {
  await with_directory(async root => {
    const fs = await import('node:fs/promises');
    for (const name of ['proc', 'dev', 'tmp']) await fs.mkdir(path.join(root, name));
    const executable = await node_executable();
    await assert.rejects(
      run_static_provider({
        manifest: manifest(),
        executable,
        args: [],
        isolation: 'required',
        sandbox_root: root,
      }),
      error => process.platform === 'linux'
        ? error.code === 'ORIX_PROVIDER_SANDBOX_PATH_DENIED'
        : error.code === 'ORIX_PROVIDER_ISOLATION_UNAVAILABLE',
    );
  });
});


if (process.platform !== 'win32') {
  test('static provider runner terminates same-process-group descendants after the provider exits', { timeout: 10_000 }, async () => {
    await with_directory(async directory => {
      const counter_path = path.join(directory, 'grandchild-counter');
      const grandchild_script = [
        "const fs = require('node:fs');",
        "const counter = process.argv[1];",
        "let count = 0;",
        "process.on('SIGTERM', () => {});",
        "fs.writeFileSync(counter, '0');",
        "setInterval(() => fs.writeFileSync(counter, String(++count)), 10);",
      ].join(' ');
      const parent_script = [
        "const { spawn } = require('node:child_process');",
        "const fs = require('node:fs');",
        "const counter = process.argv[1];",
        "spawn(process.execPath, ['-e', " + JSON.stringify(grandchild_script) + ", counter], { stdio: 'ignore' });",
        "const deadline = Date.now() + 3000;",
        "function waitForReady() {",
        "  if (fs.existsSync(counter)) { setTimeout(() => process.exit(0), 80); return; }",
        "  if (Date.now() >= deadline) { process.stderr.write('grandchild readiness timeout'); process.exit(2); return; }",
        "  setTimeout(waitForReady, 5);",
        "}",
        "waitForReady();",
      ].join(' ');

      const result = await run_static_provider({
        manifest: manifest(),
        executable: await node_executable(),
        args: ['-e', parent_script, counter_path],
        timeout_ms: 3_000,
        kill_grace_ms: 120,
      });

      assert.equal(result.ok, true);
      assert.deepEqual(result.process_group_cleanup, {
        attempted: true,
        force_kill_sent: true,
        verified_empty: true,
        failed: false,
      });

      const fs = await import('node:fs/promises');
      const counter_after_cleanup = await fs.readFile(counter_path, 'utf8');
      await new Promise(resolve => setTimeout(resolve, 100));
      const counter_later = await fs.readFile(counter_path, 'utf8');
      assert.equal(counter_later, counter_after_cleanup, 'Same-process-group descendant continued running after provider completion');
    });
  });
}


if (process.platform !== 'win32') {
  test('static provider runner kills ignored-SIGTERM descendants when cancellation interrupts the provider', { timeout: 10_000 }, async () => {
    await with_directory(async directory => {
      const counter_path = path.join(directory, 'cancelled-grandchild-counter');
      const grandchild_script = [
        "const fs = require('node:fs');",
        "const counter = process.argv[1];",
        "let count = 0;",
        "fs.writeFileSync(counter, '0');",
        "process.on('SIGTERM', () => {});",
        "setInterval(() => fs.writeFileSync(counter, String(++count)), 10);",
      ].join(' ');
      const parent_script = [
        "const { spawn } = require('node:child_process');",
        "const child = spawn(process.execPath, ['-e', " + JSON.stringify(grandchild_script) + ", " + JSON.stringify(counter_path) + "], { stdio: 'ignore' });",
        "child.once('spawn', () => { process.stdout.write('grandchild-started'); setInterval(() => {}, 1000); });",
      ].join(' ');
      const controller = new AbortController();
      const abort_timer = setTimeout(() => controller.abort(), 1_500);
      try {
        const result = await run_static_provider({
          manifest: manifest(),
          executable: await node_executable(),
          args: ['-e', parent_script],
          signal: controller.signal,
          timeout_ms: 5_000,
          kill_grace_ms: 120,
        });
        assert.equal(result.cancelled, true);
        assert.equal(result.termination_reason, 'cancelled');
        assert.equal(result.ok, false);
        assert.equal(result.stdout, 'grandchild-started');
        assert.deepEqual(result.process_group_cleanup, {
          attempted: true,
          force_kill_sent: true,
          verified_empty: true,
          failed: false,
        });
        const fs = await import('node:fs/promises');
        const counter_after_cleanup = await fs.readFile(counter_path, 'utf8');
        await new Promise(resolve => setTimeout(resolve, 100));
        const counter_later = await fs.readFile(counter_path, 'utf8');
        assert.equal(counter_later, counter_after_cleanup, 'Cancelled process-group descendant continued running');
      } finally {
        clearTimeout(abort_timer);
      }
    });
  });
}
