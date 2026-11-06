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
