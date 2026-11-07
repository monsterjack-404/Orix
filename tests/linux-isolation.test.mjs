// JavaScript, tests/linux-isolation.test.mjs, Node.js 20+, Bubblewrap rootfs trust checks.
import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  assess_bubblewrap_version,
  assess_rootfs_directory_permissions,
  prepare_linux_provider_isolation,
} from '../src/providers/linux-isolation.mjs';

test('Bubblewrap version policy blocks vulnerable releases below 0.12.0', () => {
  for (const output of [
    'bubblewrap 0.8.0',
    'bubblewrap 0.9.0',
    'bubblewrap 0.11.99',
    'bubblewrap 0.12.0-rc1',
    'bubblewrap unknown',
    '',
  ]) {
    assert.equal(assess_bubblewrap_version(output).supported, false, output);
  }
  assert.deepEqual(assess_bubblewrap_version('bubblewrap 0.12.0'), {
    version: '0.12.0',
    supported: true,
  });
  assert.equal(assess_bubblewrap_version('bubblewrap 0.12.1').supported, true);
  assert.equal(assess_bubblewrap_version('bubblewrap 1.0.0').supported, true);
});

test('rootfs trust assessment accepts service-owned and root-owned non-writable directories', () => {
  assert.deepEqual(
    assess_rootfs_directory_permissions({
      uid: 1000, mode: 0o40700, is_directory: true, is_symlink: false,
    }, 1000),
    {
      directory: true,
      symlink: false,
      owner_is_trusted: true,
      group_or_other_writable: false,
      sticky_root_exception: false,
      trusted: true,
    },
  );
  assert.equal(
    assess_rootfs_directory_permissions({
      uid: 0, mode: 0o40755, is_directory: true, is_symlink: false,
    }, 1000).trusted,
    true,
  );
});

test('rootfs trust assessment rejects foreign owners, symlinks, non-directories and writable roots', () => {
  const base = { mode: 0o40755, is_directory: true, is_symlink: false };
  assert.equal(assess_rootfs_directory_permissions({ ...base, uid: 1001 }, 1000).trusted, false);
  assert.equal(assess_rootfs_directory_permissions({ ...base, uid: 1000, mode: 0o40777 }, 1000).trusted, false);
  assert.equal(assess_rootfs_directory_permissions({ ...base, uid: 1000, is_symlink: true }, 1000).trusted, false);
  assert.equal(assess_rootfs_directory_permissions({ ...base, uid: 1000, is_directory: false }, 1000).trusted, false);
});

test('rootfs trust assessment permits only the root-owned sticky ancestor exception', () => {
  const sticky_tmp = {
    uid: 0, mode: 0o41777, is_directory: true, is_symlink: false,
  };
  assert.equal(assess_rootfs_directory_permissions(sticky_tmp, 1000, true).trusted, true);
  assert.equal(assess_rootfs_directory_permissions(sticky_tmp, 1000, false).trusted, false);
  assert.equal(assess_rootfs_directory_permissions({
    ...sticky_tmp, uid: 1000,
  }, 1000, true).trusted, false);
  assert.equal(assess_rootfs_directory_permissions({
    ...sticky_tmp, mode: 0o40777,
  }, 1000, true).trusted, false);
});

if (process.platform === 'linux') {
  test('Bubblewrap rejects a group/other-writable rootfs before resolving or launching bwrap', { timeout: 10_000 }, async () => {
    const base = await mkdtemp(path.join(tmpdir(), 'orix-rootfs-unsafe-'));
    const root = path.join(base, 'rootfs');
    try {
      await mkdir(root);
      await mkdir(path.join(root, 'proc'));
      await mkdir(path.join(root, 'dev'));
      await mkdir(path.join(root, 'tmp'));
      await chmod(root, 0o777);

      await assert.rejects(
        prepare_linux_provider_isolation({
          executable: path.join(root, 'usr/bin/rizin'),
          cwd: path.join(root, 'work'),
          sandbox_root: root,
          args: [],
          env: {},
        }),
        error => error.code === 'ORIX_PROVIDER_SANDBOX_ROOT_UNTRUSTED',
      );
    } finally {
      await chmod(root, 0o700).catch(() => {});
      await rm(base, { recursive: true, force: true });
    }
  });

  test('Bubblewrap rejects an unsafe writable ancestor of the rootfs', { timeout: 10_000 }, async () => {
    const base = await mkdtemp(path.join(tmpdir(), 'orix-rootfs-parent-'));
    const root = path.join(base, 'rootfs');
    try {
      await mkdir(root);
      await mkdir(path.join(root, 'proc'));
      await mkdir(path.join(root, 'dev'));
      await mkdir(path.join(root, 'tmp'));
      await chmod(base, 0o777);

      await assert.rejects(
        prepare_linux_provider_isolation({
          executable: path.join(root, 'usr/bin/rizin'),
          cwd: path.join(root, 'work'),
          sandbox_root: root,
          args: [],
          env: {},
        }),
        error => error.code === 'ORIX_PROVIDER_SANDBOX_ROOT_UNTRUSTED',
      );
    } finally {
      await chmod(base, 0o700).catch(() => {});
      await rm(base, { recursive: true, force: true });
    }
  });

  test('Bubblewrap refuses the filesystem root as a provider rootfs', { timeout: 10_000 }, async () => {
    await assert.rejects(
      prepare_linux_provider_isolation({
        executable: '/usr/bin/true',
        cwd: '/',
        sandbox_root: '/',
        args: [],
        env: {},
      }),
      error => error.code === 'ORIX_PROVIDER_SANDBOX_ROOT_INVALID',
    );
  });
}
