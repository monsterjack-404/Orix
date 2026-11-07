// Linux provider isolation through Bubblewrap. The supplied rootfs is the complete
// provider-visible filesystem; it is mounted read-only except for an ephemeral /tmp.
// No host home, project tree, credentials, or network namespace is exposed by default.

import { execFileSync } from 'node:child_process';
import { access, lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { OrixError } from '../core/errors.mjs';
import { validate_linux_rootfs_directory } from './linux-rootfs-trust.mjs';

function isolation_error(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' &&
    !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

const MINIMUM_BUBBLEWRAP_VERSION = Object.freeze([0, 12, 0]);

export function is_supported_bubblewrap_version(output) {
  if (typeof output !== 'string') return false;
  const match = /^\\s*bubblewrap\\s+v?(\\d+)\\.(\\d+)\\.(\\d+)(?:[-+][0-9A-Za-z.-]+)?\\s*$/im.exec(output);
  if (!match) return false;
  const version = match.slice(1, 4).map(Number);
  for (let index = 0; index < MINIMUM_BUBBLEWRAP_VERSION.length; index += 1) {
    if (version[index] > MINIMUM_BUBBLEWRAP_VERSION[index]) return true;
    if (version[index] < MINIMUM_BUBBLEWRAP_VERSION[index]) return false;
  }
  return true;
}

async function resolve_bwrap() {
  for (const candidate of ['/usr/local/bin/bwrap', '/usr/bin/bwrap', '/bin/bwrap']) {
    let canonical;
    try {
      const info = await lstat(candidate);
      if (info.isSymbolicLink() || !info.isFile()) continue;
      canonical = await realpath(candidate);
      await access(canonical, 1);
    } catch {
      // Try the next fixed system location; never resolve through PATH.
      continue;
    }

    let version_output;
    try {
      version_output = execFileSync(canonical, ['--version'], {
        encoding: 'utf8',
        timeout: 3000,
        maxBuffer: 4096,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
    } catch (error) {
      isolation_error(
        'ORIX_PROVIDER_BUBBLEWRAP_VERSION_UNVERIFIED',
        'Bubblewrap version could not be verified; required isolation will not start',
        { path: canonical, reason: error.code ?? error.name ?? 'version-probe-failed' },
      );
    }

    if (!is_supported_bubblewrap_version(version_output)) {
      isolation_error(
        'ORIX_PROVIDER_BUBBLEWRAP_VERSION_UNSUPPORTED',
        'Bubblewrap 0.12.0 or newer is required because older releases contain a sandbox-setup symlink escape',
        { path: canonical, reported_version: version_output.trim().slice(0, 128), minimum_version: '0.12.0' },
      );
    }
    return canonical;
  }
  isolation_error(
    'ORIX_PROVIDER_ISOLATION_UNAVAILABLE',
    'Bubblewrap is not installed at a trusted system path; required isolation cannot start',
    { platform: process.platform, backend: 'bubblewrap' },
  );
}

async function validate_rootfs(value) {
  return validate_linux_rootfs_directory(value);
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
  const final_rootfs = await validate_rootfs(sandbox_root);
  if (final_rootfs.path !== rootfs.path || final_rootfs.dev !== rootfs.dev || final_rootfs.ino !== rootfs.ino) {
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
