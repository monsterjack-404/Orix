import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  assess_cgroup_directory_permissions,
  inspect_linux_cgroup_v2,
  map_cgroup_path_to_mount,
  parse_cgroup2_mounts,
  parse_process_cgroup_path,
} from '../src/providers/linux-cgroup-v2-preflight.mjs';

test('cgroup2 mount parser ignores other filesystem types and decodes escaped mountpoints', () => {
  const input = [
    '29 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw',
    '30 23 0:27 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu',
    String.raw`31 23 0:28 /tenant /run/orix\040delegated rw - cgroup2 cgroup rw`,
  ].join('\n');
  assert.deepEqual(parse_cgroup2_mounts(input), [
    { root: '/', mountpoint: '/sys/fs/cgroup' },
    { root: '/tenant', mountpoint: '/run/orix delegated' },
  ]);
});

test('process cgroup parser selects the unified v2 hierarchy only', () => {
  assert.equal(parse_process_cgroup_path('5:cpu:/legacy\n0::/tenant/supervisor/orix\n'), '/tenant/supervisor/orix');
  assert.equal(parse_process_cgroup_path('2:cpu,cpuacct:/legacy\n'), null);
});

test('process cgroup parser rejects non-canonical paths instead of normalizing them', () => {
  for (const invalid of ['/tenant/../outside', '/tenant//provider', '/tenant/./provider', '/tenant/']) {
    assert.equal(parse_process_cgroup_path('0::' + invalid + '\n'), null);
  }
  assert.equal(parse_process_cgroup_path('0::/tenant/provider\n'), '/tenant/provider');
});

test('mount parser rejects non-canonical roots and mountpoints', () => {
  const input = [
    '40 23 0:40 /tenant/../outside /run/cgroup rw - cgroup2 cgroup rw',
    '41 23 0:41 /tenant /run/cgroup/../escape rw - cgroup2 cgroup rw',
    '42 23 0:42 /tenant /run/cgroup rw - cgroup2 cgroup rw',
  ].join('\n');
  assert.deepEqual(parse_cgroup2_mounts(input), [{ root: '/tenant', mountpoint: '/run/cgroup' }]);
});

test('cgroup path mapping honors mount roots and the most specific matching mount', () => {
  const mounts = [
    { root: '/', mountpoint: '/sys/fs/cgroup' },
    { root: '/tenant', mountpoint: '/run/delegated' },
  ];
  assert.equal(map_cgroup_path_to_mount('/tenant/provider', mounts), '/run/delegated/provider');
  assert.equal(map_cgroup_path_to_mount('/other/provider', mounts), '/sys/fs/cgroup/other/provider');
  assert.equal(map_cgroup_path_to_mount('/outside', [{ root: '/tenant', mountpoint: '/run/delegated' }]), null);
  assert.equal(map_cgroup_path_to_mount('/tenant/../outside', [{ root: '/tenant', mountpoint: '/run/delegated' }]), null);
  assert.equal(map_cgroup_path_to_mount('/tenant//provider', [{ root: '/tenant', mountpoint: '/run/delegated' }]), null);
  assert.equal(map_cgroup_path_to_mount('/tenant/provider', [{ root: '/tenant/../outside', mountpoint: '/run/delegated' }]), null);
});

test('cgroup parser rejects non-string input', () => {
  assert.throws(() => parse_cgroup2_mounts(null), /must be a string/);
  assert.throws(() => parse_process_cgroup_path(null), /must be a string/);
});


test('cgroup directory permission gate requires effective-UID ownership and no group/other write bits', () => {
  assert.deepEqual(
    assess_cgroup_directory_permissions({ uid: 1000, mode: 0o40755 }, 1000),
    { owner_matches_process: true, not_group_or_other_writable: true },
  );
  assert.deepEqual(
    assess_cgroup_directory_permissions({ uid: 1001, mode: 0o40755 }, 1000),
    { owner_matches_process: false, not_group_or_other_writable: true },
  );
  assert.deepEqual(
    assess_cgroup_directory_permissions({ uid: 1000, mode: 0o40775 }, 1000),
    { owner_matches_process: true, not_group_or_other_writable: false },
  );
  assert.deepEqual(
    assess_cgroup_directory_permissions(null, 1000),
    { owner_matches_process: false, not_group_or_other_writable: false },
  );
});

async function create_fake_delegated_host({ parent_mode = 0o700, supervisor_mode = 0o700, events_mode = 0o600, kill_mode = 0o600, process_cgroup = '0::/tenant/supervisor\n' } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'orix-cgroup-preflight-'));
  const mountpoint = path.join(root, 'cgroup2');
  const parent = path.join(mountpoint, 'tenant');
  const supervisor = path.join(parent, 'supervisor');
  const proc_self = path.join(root, 'proc', 'self');
  await mkdir(supervisor, { recursive: true });
  await mkdir(proc_self, { recursive: true });
  await chmod(parent, parent_mode);
  await chmod(supervisor, supervisor_mode);

  const files = {
    'cgroup.controllers': 'cpu memory pids\n',
    'cgroup.subtree_control': '+cpu +memory +pids\n',
    'cgroup.procs': '',
    'cgroup.type': 'domain\n',
    'cgroup.events': 'populated 0\nfrozen 0\n',
    'cgroup.kill': '',
  };
  await Promise.all(Object.entries(files).map(([name, contents]) =>
    writeFile(path.join(parent, name), contents)));
  await chmod(path.join(parent, 'cgroup.events'), events_mode);
  await chmod(path.join(parent, 'cgroup.kill'), kill_mode);
  await writeFile(
    path.join(proc_self, 'mountinfo'),
    '29 23 0:26 / ' + mountpoint + ' rw,nosuid,nodev - cgroup2 cgroup rw\n',
  );
  await writeFile(path.join(proc_self, 'cgroup'), process_cgroup);
  return { root, parent };
}

if (process.platform === 'linux') {
  test('read-only preflight accepts an owned, non-group-writable delegated parent with required event files', { timeout: 10_000 }, async () => {
    const fixture = await create_fake_delegated_host();
    try {
      const report = await inspect_linux_cgroup_v2({
        proc_root: path.join(fixture.root, 'proc'),
        parent_path: fixture.parent,
      });
      assert.equal(report.ready, true, report.reason);
      assert.equal(report.parent.owner_matches_process, true);
      assert.equal(report.parent.not_group_or_other_writable, true);
      assert.equal(report.parent.supervisor_owner_matches_process, true);
      assert.equal(report.parent.supervisor_not_group_or_other_writable, true);
      assert.equal(report.parent.cgroup_events_available, true);
      assert.equal(report.parent.cgroup_kill_available, true);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test('read-only preflight rejects a manager nested below supervisor because runtime requires direct membership', { timeout: 10_000 }, async () => {
    const fixture = await create_fake_delegated_host({ process_cgroup: '0::/tenant/supervisor/orix\n' });
    try {
      const report = await inspect_linux_cgroup_v2({
        proc_root: path.join(fixture.root, 'proc'),
        parent_path: fixture.parent,
      });
      assert.equal(report.ready, false);
      assert.equal(report.parent.supervisor_exists, true);
      assert.equal(report.parent.supervisor_contains_current_process, false);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test('read-only preflight rejects group-writable parent and world-writable supervisor', { timeout: 10_000 }, async () => {
    const fixture = await create_fake_delegated_host({ parent_mode: 0o770, supervisor_mode: 0o777 });
    try {
      const report = await inspect_linux_cgroup_v2({
        proc_root: path.join(fixture.root, 'proc'),
        parent_path: fixture.parent,
      });
      assert.equal(report.ready, false);
      assert.equal(report.parent.owner_matches_process, true);
      assert.equal(report.parent.not_group_or_other_writable, false);
      assert.equal(report.parent.supervisor_owner_matches_process, true);
      assert.equal(report.parent.supervisor_not_group_or_other_writable, false);
      assert.equal(report.reason, 'delegated-parent-does-not-meet-required-layout-and-controller-contract');
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
}


if (process.platform === 'linux') {
  test('read-only preflight requires readable cgroup.events and writable cgroup.kill', { timeout: 10_000 }, async () => {
    const fixture = await create_fake_delegated_host({ events_mode: 0o200, kill_mode: 0o400 });
    try {
      const report = await inspect_linux_cgroup_v2({
        proc_root: path.join(fixture.root, 'proc'),
        parent_path: fixture.parent,
      });
      assert.equal(report.ready, false);
      assert.equal(report.parent.cgroup_events_available, false);
      assert.equal(report.parent.cgroup_kill_available, false);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
}
