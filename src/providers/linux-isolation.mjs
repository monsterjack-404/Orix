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
  return root;
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
  const root = await validate_rootfs(sandbox_root);
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
  return Object.freeze({
    executable: bwrap,
    args: Object.freeze(bwrapArgs),
    cwd: '/',
    env: Object.freeze({}),
  });
}
