// macOS provider rootfs permission policy tests; pure policy tests run on every CI OS.
import test from 'node:test';
import assert from 'node:assert/strict';
import { assess_macos_rootfs_directory_permissions } from '../src/providers/macos-isolation.mjs';

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
