import test from 'node:test';
import assert from 'node:assert/strict';
import {
  map_cgroup_path_to_mount,
  parse_cgroup2_mounts,
  parse_process_cgroup_path,
} from '../src/providers/linux-cgroup-v2-preflight.mjs';

test('cgroup2 mount parser ignores other filesystem types and decodes escaped mountpoints', () => {
  const input = [
    '29 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw',
    '30 23 0:27 / /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu',
    '31 23 0:28 /tenant /run/orix\\040delegated rw - cgroup2 cgroup rw',
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
});

test('cgroup parser rejects non-string input', () => {
  assert.throws(() => parse_cgroup2_mounts(null), /must be a string/);
  assert.throws(() => parse_process_cgroup_path(null), /must be a string/);
});
