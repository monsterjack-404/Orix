// JavaScript, tests/linux-cgroup-v2-manager.test.mjs, Linux cgroup v2 lease-manager tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { closeSync, readFileSync, writeSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, unlink, writeFile, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  create_linux_provider_cgroup,
  parse_linux_cgroup_v2_populated,
  serialize_linux_cgroup_v2_limits,
  validate_linux_cgroup_v2_limits,
} from '../src/providers/linux-cgroup-v2-manager.mjs';

const valid_limits = Object.freeze({
  cpu_quota_us: 50_000,
  cpu_period_us: 100_000,
  memory_max_bytes: 256 * 1024 * 1024,
  pids_max: 32,
});

test('cgroup v2 limits require an exact plain data record and safe positive ceilings', () => {
  assert.deepEqual(validate_linux_cgroup_v2_limits(valid_limits), valid_limits);
  assert.deepEqual(serialize_linux_cgroup_v2_limits(valid_limits), {
    'cpu.max': '50000 100000',
    'memory.max': String(256 * 1024 * 1024),
    'pids.max': '32',
  });
  for (const invalid of [
    null,
    [],
    { ...valid_limits, extra: 1 },
    { ...valid_limits, pids_max: 1 },
    { ...valid_limits, cpu_period_us: 999 },
    { ...valid_limits, cpu_quota_us: 0 },
    { ...valid_limits, memory_max_bytes: Number.MAX_SAFE_INTEGER + 1 },
  ]) {
    assert.throws(
      () => validate_linux_cgroup_v2_limits(invalid),
      error => error.code === 'ORIX_CGROUP_LIMITS_INVALID',
    );
  }
  const accessor = { ...valid_limits };
  Object.defineProperty(accessor, 'pids_max', {
    enumerable: true,
    get() { throw new Error('untrusted getter must not execute'); },
  });
  assert.throws(
    () => validate_linux_cgroup_v2_limits(accessor),
    error => error.code === 'ORIX_CGROUP_LIMITS_INVALID',
  );
});

test('cgroup.events populated parser requires exactly one valid state', () => {
  assert.equal(parse_linux_cgroup_v2_populated('populated 0\nfrozen 0\n'), 0);
  assert.equal(parse_linux_cgroup_v2_populated('populated 1\nfrozen 0\n'), 1);
  for (const invalid of ['', 'populated 2\n', 'populated 0\npopulated 1\n', 'populated yes\n']) {
    assert.throws(
      () => parse_linux_cgroup_v2_populated(invalid),
      error => error.code === 'ORIX_CGROUP_EVENTS_INVALID',
    );
  }
});

async function make_fake_delegated_parent() {
  const root = await mkdtemp(path.join(tmpdir(), 'orix-cgroup-manager-'));
  const parent = path.join(root, 'delegated');
  await mkdir(parent, { mode: 0o700 });
  await chmod(parent, 0o700);
  await writeFile(path.join(parent, 'cgroup.procs'), '');
  return { root, parent };
}

function fake_adapter({ populated_after_kill = 0, mismatch_file = null } = {}) {
  return {
    preflight: async () => ({ ready: true, reason: null }),
    after_create_leaf: async leaf_path => {
      const controls = {
        'cgroup.controllers': 'cpu memory pids\n',
        'cgroup.type': 'domain\n',
        'cgroup.procs': '',
        'cgroup.events': 'populated 0\nfrozen 0\n',
        'cgroup.kill': '',
        'cpu.max': 'max 100000\n',
        'memory.max': 'max\n',
        'pids.max': 'max\n',
      };
      await Promise.all(Object.entries(controls).map(([name, contents]) =>
        writeFile(path.join(leaf_path, name), contents, { mode: 0o600 })));
    },
    after_control_write: async ({ leaf_fd_path, name }) => {
      if (mismatch_file === name) {
        await writeFile(path.join(leaf_fd_path, name), 'mismatch\n');
      }
      if (name === 'cgroup.kill' && populated_after_kill === 0) {
        await writeFile(path.join(leaf_fd_path, 'cgroup.events'), 'populated 0\nfrozen 0\n');
      }
    },
    remove_leaf: async leaf_path => {
      for (const name of await readdir(leaf_path)) {
        await unlink(path.join(leaf_path, name));
      }
      await rmdir(leaf_path);
    },
  };
}

if (process.platform === 'linux') {
  test('manager configures exact limits, returns a one-shot attach fd, and tears down idempotently', { timeout: 10_000 }, async () => {
    const fixture = await make_fake_delegated_parent();
    try {
      const lease = await create_linux_provider_cgroup({
        parent_path: fixture.parent,
        limits: valid_limits,
        cleanup_timeout_ms: 500,
      }, fake_adapter());

      assert.match(lease.leaf_name, /^provider-\d+-[0-9a-f-]+$/);
      const leaf_path = path.join(fixture.parent, lease.leaf_name);
      assert.equal(await readFile(path.join(leaf_path, 'cpu.max'), 'utf8'), '50000 100000');
      assert.equal(await readFile(path.join(leaf_path, 'memory.max'), 'utf8'), String(valid_limits.memory_max_bytes));
      assert.equal(await readFile(path.join(leaf_path, 'pids.max'), 'utf8'), '32');

      writeSync(lease.attach_fd, Buffer.from(String(process.pid) + '\n', 'ascii'));
      assert.equal(readFileSync(path.join(leaf_path, 'cgroup.procs'), 'utf8'), String(process.pid) + '\n');
      lease.close_attach_fd();
      assert.throws(
        () => lease.attach_fd,
        error => error.code === 'ORIX_CGROUP_ATTACH_DESCRIPTOR_CLOSED',
      );

      const first = await lease.teardown();
      const second = await lease.teardown();
      assert.equal(first.removed, true);
      assert.deepEqual(second, first);
      await assert.rejects(readFile(leaf_path), error => error.code === 'ENOENT');
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test('manager fails closed and removes an empty leaf when kernel limit read-back differs', { timeout: 10_000 }, async () => {
    const fixture = await make_fake_delegated_parent();
    try {
      await assert.rejects(
        create_linux_provider_cgroup({
          parent_path: fixture.parent,
          limits: valid_limits,
        }, fake_adapter({ mismatch_file: 'cpu.max' })),
        error => error.code === 'ORIX_CGROUP_LIMIT_READBACK_MISMATCH',
      );
      assert.deepEqual(await readdir(fixture.parent), ['cgroup.procs']);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test('manager never removes a populated leaf after cleanup timeout and permits safe retry', { timeout: 10_000 }, async () => {
    const fixture = await make_fake_delegated_parent();
    try {
      const adapter = fake_adapter({ populated_after_kill: 1 });
      const lease = await create_linux_provider_cgroup({
        parent_path: fixture.parent,
        limits: valid_limits,
        cleanup_timeout_ms: 30,
      }, adapter);
      const leaf_path = path.join(fixture.parent, lease.leaf_name);

      await assert.rejects(
        lease.teardown(),
        error => error.code === 'ORIX_CGROUP_CLEANUP_TIMEOUT',
      );
      assert.ok((await readdir(fixture.parent)).includes(lease.leaf_name));
      assert.equal(await readFile(path.join(leaf_path, 'cgroup.events'), 'utf8'), 'populated 1\nfrozen 0\n');

      await writeFile(path.join(leaf_path, 'cgroup.events'), 'populated 0\nfrozen 0\n');
      const result = await lease.teardown();
      assert.equal(result.removed, true);
      assert.deepEqual(await readdir(fixture.parent), ['cgroup.procs']);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test('manager refuses an unready delegated parent before creating a leaf', { timeout: 10_000 }, async () => {
    const fixture = await make_fake_delegated_parent();
    try {
      await assert.rejects(
        create_linux_provider_cgroup({
          parent_path: fixture.parent,
          limits: valid_limits,
        }, { preflight: async () => ({ ready: false, reason: 'controllers-unavailable' }) }),
        error => error.code === 'ORIX_CGROUP_PARENT_NOT_READY',
      );
      assert.deepEqual(await readdir(fixture.parent), ['cgroup.procs']);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
}
