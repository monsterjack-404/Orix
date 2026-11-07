// Linux cgroup v2 manager contract tests. These tests do not claim kernel enforcement.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { prepare_linux_provider_cgroup, LINUX_PROVIDER_CGROUP_LIMITS, parse_cgroup_process_ids } from '../src/providers/linux-cgroup-v2-manager.mjs';

test('supervisor cgroup process-list parsing handles multiple newline-separated PIDs', () => {
  assert.deepEqual(parse_cgroup_process_ids('123\n456\n789\n'), ['123', '456', '789']);
  assert.deepEqual(parse_cgroup_process_ids('  123\t456  \n'), ['123', '456']);
  assert.deepEqual(parse_cgroup_process_ids(''), []);
});

test('supervisor cgroup process-list parsing rejects malformed and duplicate PID records', () => {
  assert.throws(() => parse_cgroup_process_ids('123\nnot-a-pid\n'), /invalid process ID/);
  for (const invalid of ['0', '01', '+123', '-123', '1.5', '123\n123', '9'.repeat(32)]) {
    assert.throws(() => parse_cgroup_process_ids(invalid), /invalid process ID|duplicate process ID/);
  }
  assert.throws(() => parse_cgroup_process_ids(null), /must be a string/);
});

test('provider cgroup policy uses finite aggregate CPU, memory, swap and task ceilings', () => {
  assert.deepEqual(LINUX_PROVIDER_CGROUP_LIMITS, {
    'cpu.max': '50000 100000',
    'memory.max': '536870912',
    'memory.swap.max': '0',
    'memory.oom.group': '1',
    'pids.max': '64',
  });
});

if (process.platform === 'linux') {
  test('required cgroup manager fails closed when the administrator parent is absent', async () => {
    await assert.rejects(
      prepare_linux_provider_cgroup(''),
      error => error.code === 'ORIX_CGROUP_PARENT_REQUIRED',
    );
  });

  test('required cgroup manager rejects non-absolute parent configuration', async () => {
    await assert.rejects(
      prepare_linux_provider_cgroup('relative/cgroup'),
      error => error.code === 'ORIX_CGROUP_PARENT_REQUIRED',
    );
  });

  test('required cgroup manager rejects an ordinary filesystem directory without mutating it', async () => {
    const directory = await mkdtemp(path.join(tmpdir(), 'orix-cgroup-manager-untrusted-'));
    try {
      const before = await readdir(directory);
      await assert.rejects(
        prepare_linux_provider_cgroup(directory),
        error => error.code === 'ORIX_CGROUP_PREFLIGHT_FAILED',
      );
      assert.deepEqual(await readdir(directory), before,
        'A non-cgroup filesystem path must be rejected before any child cgroup is created');
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}
