// Linux provider isolation through Bubblewrap. The supplied rootfs is the complete
// provider-visible filesystem; it is mounted read-only except for an ephemeral /tmp.
// No host home, project tree, credentials, or network namespace is exposed by default.

import { access, lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { OrixError } from '../core/errors.mjs';

function isolation_error(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' &&
    !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

async function resolve_bwrap() {
  for (const candidate of ['/usr/bin/bwrap', '/bin/bwrap']) {
    try {
      const info = await lstat(candidate);
      if (info.isSymbolicLink() || !info.isFile()) continue;
      const canonical = await realpath(candidate);
      await access(canonical, 1);
      return canonical;
    } catch {
      // Try the next fixed system location; never resolve through PATH.
    }
  }
  isolation_error(
    'ORIX_PROVIDER_ISOLATION_UNAVAILABLE',
    'Bubblewrap is not installed at a trusted system path; required isolation cannot start',
    { platform: process.platform, backend: 'bubblewrap' },
  );
}


/**
 * Check ownership and mode for one directory in the trusted rootfs path.
 * Ancestors may use the root-owned sticky-directory exception (for example /tmp).
 */
export function assess_rootfs_directory_permissions(metadata, expected_uid, allow_root_sticky = false) {
  const valid_expected_uid = Number.isSafeInteger(expected_uid) && expected_uid >= 0 && expected_uid <= 0xffff_ffff;
  const valid = metadata !== null && typeof metadata === 'object' &&
    Number.isSafeInteger(metadata.uid) && metadata.uid >= 0 && metadata.uid <= 0xffff_ffff &&
    Number.isSafeInteger(metadata.mode) && metadata.mode >= 0 && metadata.mode <= 0o177777 &&
    typeof metadata.is_directory === 'boolean' &&
    typeof metadata.is_symlink === 'boolean';
  const directory = valid && metadata.is_directory;
  const symlink = !valid || metadata.is_symlink;
  const owner_is_trusted = valid && valid_expected_uid &&
    (metadata.uid === 0 || metadata.uid === expected_uid);
  const group_or_other_writable = !valid || (metadata.mode & 0o022) !== 0;
  const sticky_root_exception = valid && allow_root_sticky &&
    metadata.uid === 0 && (metadata.mode & 0o1000) !== 0;
  const writable_by_untrusted = group_or_other_writable && !sticky_root_exception;
  return Object.freeze({
    directory,
    symlink,
    owner_is_trusted,
    group_or_other_writable,
    sticky_root_exception,
    trusted: directory && !symlink && owner_is_trusted && !writable_by_untrusted,
  });
}

async function validate_rootfs_path_trust(root) {
  if (root === path.parse(root).root) {
    isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID',
      'The filesystem root cannot be used as a provider sandbox root');
  }

  const expected_uid = process.geteuid();
  let current = root;
  let is_rootfs = true;
  for (;;) {
    let info;
    try {
      info = await lstat(current);
    } catch (error) {
      isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_UNTRUSTED',
        'A provider sandbox root path component cannot be inspected', {
          reason: error.code ?? 'filesystem-error',
        });
    }
    const assessment = assess_rootfs_directory_permissions({
      uid: info.uid,
      mode: info.mode,
      is_directory: info.isDirectory(),
      is_symlink: info.isSymbolicLink(),
    }, expected_uid, !is_rootfs);

    if (!assessment.trusted) {
      isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_UNTRUSTED',
        is_rootfs
          ? 'Provider sandbox root must be owned by root or the ORIX service account and not group/other writable'
          : 'Provider sandbox root ancestors must be trusted and not group/other writable (except root-owned sticky directories)',
        {
          component: current,
          owner_uid: info.uid,
          expected_uid,
          mode: info.mode & 0o7777,
          rootfs_component: is_rootfs,
        });
    }

    if (current === path.parse(current).root) break;
    current = path.dirname(current);
    is_rootfs = false;
  }
}

async function validate_rootfs(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    throw new TypeError('sandbox_root must be an absolute filesystem path');
  }
  let info;
  try { info = await lstat(value); }
  catch (error) {
    isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_UNAVAILABLE', 'Provider sandbox root cannot be inspected', {
      reason: error.code ?? 'filesystem-error',
    });
  }
  if (info.isSymbolicLink() || !info.isDirectory()) {
    isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID', 'Provider sandbox root must be a non-symlink directory');
  }
  const root = await realpath(value);
  let resolved_info;
  try {
    resolved_info = await lstat(root);
  } catch (error) {
    isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_UNAVAILABLE', 'Canonical provider sandbox root cannot be inspected', {
      reason: error.code ?? 'filesystem-error',
    });
  }
  if (resolved_info.isSymbolicLink() || !resolved_info.isDirectory() ||
      resolved_info.dev !== info.dev || resolved_info.ino !== info.ino) {
    isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_CHANGED',
      'Provider sandbox root identity changed while resolving its canonical path');
  }
  await validate_rootfs_path_trust(root);
  for (const required of ['proc', 'dev', 'tmp']) {
    let entry;
    try { entry = await lstat(path.join(root, required)); }
    catch {
      isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID', 'Sandbox root is missing a required mount point', {
        mount_point: '/' + required,
      });
    }
    if (entry.isSymbolicLink() || !entry.isDirectory()) {
      isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID', 'Sandbox mount points must be real directories', {
        mount_point: '/' + required,
      });
    }
  }
  return Object.freeze({ path: root, dev: resolved_info.dev, ino: resolved_info.ino });
}

function sandbox_path(root, host_path, label) {
  if (!within(root, host_path)) {
    isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED', label + ' must be inside sandbox_root');
  }
  const relative = path.relative(root, host_path).split(path.sep).join('/');
  return relative ? '/' + relative : '/';
}

export async function prepare_linux_provider_isolation({ executable, cwd, sandbox_root, args, env }) {
  if (process.platform !== 'linux') {
    isolation_error(
      'ORIX_PROVIDER_ISOLATION_UNAVAILABLE',
      'Required provider isolation currently has no enforced backend for this operating system',
      { platform: process.platform },
    );
  }
  const rootfs = await validate_rootfs(sandbox_root);
  const root = rootfs.path;
  const sandboxExecutable = sandbox_path(root, executable, 'executable');
  const sandboxCwd = sandbox_path(root, cwd, 'cwd');
  const bwrap = await resolve_bwrap();
  const bwrapArgs = [
    '--die-with-parent',
    '--new-session',
    // Require the user namespace rather than silently accepting a weaker setup.
    '--unshare-user',
    '--unshare-ipc',
    '--unshare-pid',
    '--unshare-net',
    '--unshare-uts',
    '--unshare-cgroup-try',
    // Prevent provider-created nested user namespaces from rearranging mounts.
    '--disable-userns',
    '--assert-userns-disabled',
    '--ro-bind', root, '/',
    '--proc', '/proc',
    '--dev', '/dev',
    '--tmpfs', '/tmp',
    '--chdir', sandboxCwd,
    '--clearenv',
    '--setenv', 'HOME', '/tmp',
    '--setenv', 'TMPDIR', '/tmp',
  ];
  for (const [key, value] of Object.entries(env)) {
    bwrapArgs.push('--setenv', key, value);
  }
  bwrapArgs.push('--', sandboxExecutable, ...args);

  // Re-check rootfs ownership/modes and every ancestor after preparing argv,
  // immediately before handing the launch plan back to the process runner.
  // This narrows (but cannot eliminate) the validation-to-spawn race.
  const final_root = await validate_rootfs(sandbox_root);
  if (final_root.path !== rootfs.path ||
      final_root.dev !== rootfs.dev ||
      final_root.ino !== rootfs.ino) {
    isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_CHANGED',
      'Provider sandbox root directory was replaced while its launch policy was being prepared');
  }

  return Object.freeze({
    executable: bwrap,
    args: Object.freeze(bwrapArgs),
    cwd: '/',
    env: Object.freeze({}),
  });
}
