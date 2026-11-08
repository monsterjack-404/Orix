// Linux provider isolation through Bubblewrap. The supplied rootfs is the complete
// provider-visible filesystem; it is mounted read-only except for an ephemeral /tmp.
// No host home, project tree, credentials, or network namespace is exposed by default.

import { access, lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { OrixError } from '../core/errors.mjs';
import { prepare_linux_provider_cgroup } from './linux-cgroup-v2-manager.mjs';

function isolation_error(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' &&
    !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

export function assess_trusted_system_path_component(metadata, expected_type = 'directory') {
  const valid = metadata !== null && typeof metadata === 'object' &&
    Number.isSafeInteger(metadata.uid) && Number.isSafeInteger(metadata.mode);
  const is_directory = valid && metadata.is_directory === true;
  const is_file = valid && metadata.is_file === true;
  const is_symlink = !valid || metadata.is_symlink === true;
  const expected_type_matches = expected_type === 'directory'
    ? is_directory
    : expected_type === 'file' ? is_file : false;
  const owner_is_root = valid && metadata.uid === 0;
  const not_group_or_other_writable = valid && (metadata.mode & 0o022) === 0;
  return Object.freeze({
    expected_type_matches,
    is_symlink,
    owner_is_root,
    not_group_or_other_writable,
    trusted: expected_type_matches && !is_symlink && owner_is_root && not_group_or_other_writable,
  });
}

function stat_metadata(info) {
  return {
    uid: info.uid,
    mode: info.mode,
    is_directory: info.isDirectory(),
    is_file: info.isFile(),
    is_symlink: info.isSymbolicLink(),
  };
}

async function trusted_system_path(canonical) {
  const root = path.parse(canonical).root;
  if (!root) return { trusted: false, reason: 'canonical-path-has-no-filesystem-root' };
  let current = root;
  let info;
  try {
    info = await lstat(current);
    let assessment = assess_trusted_system_path_component(stat_metadata(info), 'directory');
    if (!assessment.trusted) {
      return { trusted: false, component: current, expected_type: 'directory', metadata: stat_metadata(info), assessment };
    }
    const relative = path.relative(root, canonical);
    const components = relative.split(path.sep).filter(Boolean);
    if (components.length === 0) return { trusted: false, reason: 'canonical-path-is-filesystem-root' };
    for (let index = 0; index < components.length; index += 1) {
      current = path.join(current, components[index]);
      info = await lstat(current);
      const expected_type = index === components.length - 1 ? 'file' : 'directory';
      assessment = assess_trusted_system_path_component(stat_metadata(info), expected_type);
      if (!assessment.trusted) {
        return { trusted: false, component: current, expected_type, metadata: stat_metadata(info), assessment };
      }
    }
    return { trusted: true };
  } catch (error) {
    return { trusted: false, component: current, reason: error.code ?? 'filesystem-error' };
  }
}

async function resolve_trusted_executable(candidates, label) {
  const rejected_candidates = [];
  for (const candidate of candidates) {
    try {
      const info = await lstat(candidate);
      if (info.isSymbolicLink() || !info.isFile()) {
        rejected_candidates.push({ candidate, reason: info.isSymbolicLink() ? 'candidate-is-symlink' : 'candidate-is-not-file' });
        continue;
      }
      const canonical = await realpath(candidate);
      const trust = await trusted_system_path(canonical);
      if (!trust.trusted) {
        rejected_candidates.push({ candidate, canonical, ...trust });
        continue;
      }
      await access(canonical, 1);
      return canonical;
    } catch (error) {
      rejected_candidates.push({ candidate, reason: error.code ?? 'filesystem-error' });
    }
  }
  isolation_error(
    'ORIX_PROVIDER_ISOLATION_UNAVAILABLE',
    label + ' is not installed at a trusted system path; required isolation cannot start',
    { platform: process.platform, backend: label, rejected_candidates },
  );
}

async function resolve_bwrap() {
  // CI builds a checksum-verified Bubblewrap into /usr/local/bin. Only fixed
  // root-owned, non-group/other-writable paths are trusted; PATH is never searched.
  return resolve_trusted_executable([
    '/usr/bin/bwrap',
    '/usr/local/bin/bwrap',
    '/bin/bwrap',
  ], 'bubblewrap');
}

async function resolve_prlimit() {
  return resolve_trusted_executable(['/usr/bin/prlimit', '/bin/prlimit'], 'prlimit');
}

/**
 * Check the ownership/mode of one directory in the trusted rootfs path.
 * Only the rootfs itself must be non-writable by group/other. Ancestors may
 * use the root-owned sticky-directory exception (for example, /tmp).
 */
export function assess_rootfs_directory_permissions(metadata, expected_uid, allow_root_sticky = false) {
  const valid = metadata !== null && typeof metadata === 'object' &&
    Number.isSafeInteger(metadata.uid) && Number.isSafeInteger(metadata.mode);
  const directory = valid && metadata.is_directory === true;
  const symlink = !valid || metadata.is_symlink === true;
  const owner_is_trusted = valid && (metadata.uid === 0 || metadata.uid === expected_uid);
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
  // These per-process RLIMITs complement aggregate cgroup CPU/memory/task quotas.
  const limitArgs = [
    '--cpu=60:60',
    '--fsize=67108864:67108864',
    '--nofile=256:256',
    '--core=0:0',
    '--',
    bwrap,
    ...bwrapArgs,
  ];
  const cgroup = await prepare_linux_provider_cgroup();
  const bootstrap = fileURLToPath(new URL('./linux-cgroup-v2-bootstrap.mjs', import.meta.url));
  return Object.freeze({
    executable: process.execPath,
    args: Object.freeze([bootstrap, '--attach-fd=3', '--', prlimit, ...limitArgs]),
    cwd: '/',
    env: Object.freeze({}),
    stdio: cgroup.stdio,
    close_parent_fd: cgroup.close_attach_fd,
    cleanup: cgroup.cleanup,
  });
}
