// Linux cgroup v2 manager contract tests. These tests do not claim kernel enforcement.
import test from 'node:test';
import assert from 'node:assert/strict';
import { prepare_linux_provider_cgroup, LINUX_PROVIDER_CGROUP_LIMITS } from '../src/providers/linux-cgroup-v2-manager.mjs';

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
}
