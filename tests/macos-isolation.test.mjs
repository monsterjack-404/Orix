// macOS provider rootfs permission policy tests; pure policy tests run on every CI OS.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import {
  assess_macos_rootfs_directory_permissions,
  assess_macos_rootfs_entry_permissions,
  build_macos_compiler_environment,
  cleanup_macos_compiler_process_group,
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

test('macOS compiler environment ignores inherited SDK and toolchain overrides', () => {
  const temporary = '/orix-test/private-compiler-tmp';
  const environment = build_macos_compiler_environment(temporary);
  assert.deepEqual(environment, {
    HOME: temporary,
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    LANG: 'C',
    TMPDIR: temporary,
    TMP: temporary,
    TEMP: temporary,
  });
  for (const key of [
    'DEVELOPER_DIR', 'SDKROOT', 'TOOLCHAINS', 'CPATH', 'CFLAGS',
    'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH',
  ]) {
    assert.equal(Object.hasOwn(environment, key), false, key + ' must not enter the host compiler environment');
  }
});

test('macOS compiler cleanup kills and verifies a same-group descendant after the leader exits', {
  skip: process.platform === 'win32',
  timeout: 10_000,
}, async () => {
  const script = [
    "const { spawn } = require('node:child_process');",
    "const descendant = spawn(process.execPath, ['-e', \"process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);\"], { stdio: 'ignore' });",
    "descendant.once('spawn', () => process.stdout.write('descendant-ready'));",
    "process.on('SIGTERM', () => process.exit(0));",
    "setInterval(() => {}, 1000);",
  ].join('\n');
  const child = spawn(process.execPath, ['-e', script], {
    detached: true,
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  try {
    await once(child, 'spawn');
    const ready = once(child.stdout, 'data');
    const closed = once(child, 'close');
    const [readyOutput] = await ready;
    assert.match(readyOutput.toString('utf8'), /descendant-ready/,
      'The descendant must be spawned before process-group cleanup begins');
    const report = await cleanup_macos_compiler_process_group(child.pid, {
      term_grace_ms: 50,
      verify_timeout_ms: 3000,
    });
    await closed;
    assert.equal(report.term_signal_sent, true);
    assert.equal(report.force_kill_sent, true);
    assert.equal(report.verified_empty, true);
  } finally {
    if (Number.isSafeInteger(child.pid)) {
      try { process.kill(-child.pid, 'SIGKILL'); } catch {}
    }
  }
});

test('macOS compiler cleanup rejects invalid process-group identifiers and limits', async () => {
  await assert.rejects(
    cleanup_macos_compiler_process_group(0),
    TypeError,
  );
  await assert.rejects(
    cleanup_macos_compiler_process_group(123, { term_grace_ms: 10_001 }),
    TypeError,
  );
});
