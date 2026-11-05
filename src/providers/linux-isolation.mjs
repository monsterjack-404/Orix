// Linux provider isolation through Bubblewrap and inherited process resource limits.
// The supplied rootfs is the complete provider-visible filesystem; it is mounted
// read-only except for an ephemeral /tmp. Host home, project, credentials and
// network namespace are not exposed by default.

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

async function resolve_trusted_executable(candidates, label) {
  for (const candidate of candidates) {
    try {
      const info = await lstat(candidate);
      if (info.isSymbolicLink() || !info.isFile()) continue;
      const canonical = await realpath(candidate);
      await access(canonical, 1);
      return canonical;
    } catch {
      // Only fixed system paths are considered; never resolve through PATH.
    }
  }
  isolation_error(
    'ORIX_PROVIDER_ISOLATION_UNAVAILABLE',
    label + ' is not installed at a trusted system path; required isolation cannot start',
    { platform: process.platform, backend: label },
  );
}

async function resolve_bwrap() {
  return resolve_trusted_executable(['/usr/bin/bwrap', '/bin/bwrap'], 'bubblewrap');
}

async function resolve_prlimit() {
  return resolve_trusted_executable(['/usr/bin/prlimit', '/bin/prlimit'], 'prlimit');
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
  const prlimit = await resolve_prlimit();

  // These are per-process RLIMITs inherited by the provider and its descendants.
  // They are not aggregate cgroup quotas: memory/PID-wide accounting remains a
  // separate gate. CPU is capped at 60 seconds per process, file size at 64 MiB,
  // open descriptors at 256, and core dumps are disabled.
  const bwrapArgs = [
    '--die-with-parent',
    '--new-session',
    '--unshare-all',
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

  const limitArgs = [
    '--cpu=60:60',
    '--fsize=67108864:67108864',
    '--nofile=256:256',
    '--core=0:0',
    '--',
    bwrap,
    ...bwrapArgs,
  ];
  return Object.freeze({
    executable: prlimit,
    args: Object.freeze(limitArgs),
    cwd: '/',
    env: Object.freeze({}),
  });
}
