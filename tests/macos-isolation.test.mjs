// macOS provider rootfs permission policy tests; pure policy tests run on every CI OS.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assess_macos_rootfs_directory_permissions,
  cleanup_macos_compiler_workspace,
  assess_macos_rootfs_entry_permissions,
} from '../src/providers/macos-isolation.mjs';

test('macOS rootfs trust accepts root-owned and service-owned non-writable directories', () => {
  assert.equal(assess_macos_rootfs_directory_permissions({
    uid: 1000, mode: 0o40700, is_directory: true, is_symlink: false,
  }, 1000).trusted, true);
  assert.equal(assess_macos_rootfs_directory_permissions({
    uid: 0, mode: 0o40755, is_directory: true, is_symlink: false,
  }, 1000).trusted, true);
});

test('macOS rootfs trust rejects untrusted owners, writable roots, symlinks and non-directories', () => {
  const safe = { mode: 0o40755, is_directory: true, is_symlink: false };
  assert.equal(assess_macos_rootfs_directory_permissions({ ...safe, uid: 1001 }, 1000).trusted, false);
  assert.equal(assess_macos_rootfs_directory_permissions({ ...safe, uid: 1000, mode: 0o40777 }, 1000).trusted, false);
  assert.equal(assess_macos_rootfs_directory_permissions({ ...safe, uid: 1000, is_symlink: true }, 1000).trusted, false);
  assert.equal(assess_macos_rootfs_directory_permissions({ ...safe, uid: 1000, is_directory: false }, 1000).trusted, false);
  assert.equal(assess_macos_rootfs_directory_permissions(null, 1000).trusted, false);
});

test('macOS rootfs trust allows only root-owned sticky ancestors as a writable exception', () => {
  const sticky = { uid: 0, mode: 0o41777, is_directory: true, is_symlink: false };
  assert.equal(assess_macos_rootfs_directory_permissions(sticky, 1000, true).trusted, true);
  assert.equal(assess_macos_rootfs_directory_permissions(sticky, 1000, false).trusted, false);
  assert.equal(assess_macos_rootfs_directory_permissions({ ...sticky, uid: 1000 }, 1000, true).trusted, false);
  assert.equal(assess_macos_rootfs_directory_permissions({ ...sticky, mode: 0o40777 }, 1000, true).trusted, false);
});

test('macOS rootfs entry trust rejects writable, privileged, linked and untrusted files', () => {
  const safe = { uid: 1000, mode: 0o100755, is_file: true, is_directory: false, is_symlink: false, nlink: 1 };
  assert.equal(assess_macos_rootfs_entry_permissions(safe, 1000).trusted, true);
  assert.equal(assess_macos_rootfs_entry_permissions({ ...safe, mode: 0o100777 }, 1000).trusted, false);
  assert.equal(assess_macos_rootfs_entry_permissions({ ...safe, mode: 0o104755 }, 1000).trusted, false);
  assert.equal(assess_macos_rootfs_entry_permissions({ ...safe, uid: 1001 }, 1000).trusted, false);
  assert.equal(assess_macos_rootfs_entry_permissions({ ...safe, nlink: 2 }, 1000).trusted, false);
  assert.equal(assess_macos_rootfs_entry_permissions({ ...safe, is_symlink: true }, 1000).trusted, false);
  assert.equal(assess_macos_rootfs_entry_permissions(null, 1000).trusted, false);
});

test('macOS rootfs entry trust accepts root-owned, read-only directories', () => {
  assert.equal(assess_macos_rootfs_entry_permissions({
    uid: 0, mode: 0o40755, is_file: false, is_directory: true, is_symlink: false, nlink: 2,
  }, 1000).trusted, true);
});

test('macOS compiler workspace is preserved when process-group emptiness cannot be verified', async () => {
  let remove_called = false;
  const original = Object.assign(new Error('compiler process group is still present'), {
    code: 'ORIX_PROVIDER_MACOS_COMPILER_CLEANUP_FAILED',
    details: { process_group_id: 1234, verified_empty: false },
  });
  await assert.rejects(
    cleanup_macos_compiler_workspace(
      '/tmp/orix-provider-macos-recovery',
      original,
      async () => { remove_called = true; },
    ),
    error => {
      assert.equal(error.code, 'ORIX_PROVIDER_MACOS_COMPILER_CLEANUP_FAILED');
      assert.equal(error.details.workspace_path, '/tmp/orix-provider-macos-recovery');
      assert.equal(error.details.workspace_preserved, true);
      assert.equal(error.details.process_group_id, 1234);
      assert.equal(error.cause, original);
      return true;
    },
  );
  assert.equal(remove_called, false, 'Unverified compiler descendants must never race workspace deletion');
});

test('macOS compiler workspace is removed after verified compiler-group cleanup', async () => {
  let removed_path = null;
  let removed_options = null;
  const result = await cleanup_macos_compiler_workspace(
    '/tmp/orix-provider-macos-complete',
    new Error('ordinary compiler failure after process-group cleanup'),
    async (directory, options) => {
      removed_path = directory;
      removed_options = options;
    },
  );
  assert.equal(result.workspace_preserved, false);
  assert.equal(removed_path, '/tmp/orix-provider-macos-complete');
  assert.deepEqual(removed_options, { recursive: true, force: true });
});
