// macOS Seatbelt provider isolation with inherited per-process RLIMITs.
import { constants as FS_CONSTANTS } from 'node:fs';
import { access, lstat, mkdtemp, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { OrixError } from '../core/errors.mjs';

function isolation_error(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' &&
    !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

/**
 * Rootfs paths must not be replaceable by an untrusted group/other writer.
 * A root-owned sticky ancestor (for example /tmp) is the only writable
 * ancestor exception; the rootfs directory itself never gets that exception.
 */
export function assess_macos_rootfs_directory_permissions(metadata, expected_uid, allow_root_sticky = false) {
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
    const assessment = assess_macos_rootfs_directory_permissions({
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

async function validate_directory(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', label + ' must be an absolute path for required macOS isolation');
  }
  let info;
  try { info = await lstat(value); }
  catch (error) {
    const code = label === 'sandbox_root' ? 'ORIX_PROVIDER_SANDBOX_ROOT_UNAVAILABLE' : 'ORIX_PROVIDER_SANDBOX_PATH_UNAVAILABLE';
    isolation_error(code, label + ' cannot be inspected', { reason: error.code ?? 'filesystem-error' });
  }
  if (info.isSymbolicLink() || !info.isDirectory()) {
    const code = label === 'sandbox_root' ? 'ORIX_PROVIDER_SANDBOX_ROOT_INVALID' : 'ORIX_PROVIDER_SANDBOX_PATH_INVALID';
    isolation_error(code, label + ' must be a real non-symlink directory');
  }
  const canonical = await realpath(value);
  if (label === 'sandbox_root') await validate_rootfs_path_trust(canonical);
  return canonical;
}

export function assess_macos_rootfs_entry_permissions(metadata, expected_uid) {
  const valid = metadata !== null && typeof metadata === 'object' &&
    Number.isSafeInteger(metadata.uid) && Number.isSafeInteger(metadata.mode);
  const directory = valid && metadata.is_directory === true;
  const file = valid && metadata.is_file === true;
  const symlink = !valid || metadata.is_symlink === true;
  const owner_is_trusted = valid && (metadata.uid === 0 || metadata.uid === expected_uid);
  const group_or_other_writable = !valid || (metadata.mode & 0o022) !== 0;
  const privileged_mode = valid && (metadata.mode & 0o6000) !== 0;
  const multiply_linked = valid && file &&
    (!Number.isSafeInteger(metadata.nlink) || metadata.nlink !== 1);
  return Object.freeze({
    directory,
    file,
    symlink,
    owner_is_trusted,
    group_or_other_writable,
    privileged_mode,
    multiply_linked,
    trusted: (directory || file) && !symlink && owner_is_trusted &&
      !group_or_other_writable && !privileged_mode && !multiply_linked,
  });
}

async function validate_tree(root) {
  let entries_seen = 0;
  const expected_uid = process.geteuid();
  async function walk(directory, depth) {
    if (depth > 64) isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID', 'Provider rootfs exceeds the maximum directory depth');
    let entries;
    try { entries = await readdir(directory, { withFileTypes: true }); }
    catch (error) {
      isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED',
        'Provider rootfs directory could not be inventoried', {
          path: directory,
          reason: error.code ?? 'filesystem-error',
        });
    }
    for (const entry of entries) {
      entries_seen += 1;
      if (entries_seen > 100_000) isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID', 'Provider rootfs exceeds the maximum entry count');
      const full = path.join(directory, entry.name);
      let info;
      try { info = await lstat(full); }
      catch (error) {
        isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED',
          'Provider rootfs entry could not be inspected', {
            path: full,
            reason: error.code ?? 'filesystem-error',
          });
      }
      const assessment = assess_macos_rootfs_entry_permissions({
        uid: info.uid,
        mode: info.mode,
        nlink: info.nlink,
        is_file: info.isFile(),
        is_directory: info.isDirectory(),
        is_symlink: info.isSymbolicLink(),
      }, expected_uid);
      if (!assessment.trusted) {
        isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED',
          'Provider rootfs entries must be root/service-owned, non-writable by group or others, non-privileged and non-linked regular files/directories',
          {
            path: full,
            owner_uid: info.uid,
            expected_uid,
            mode: info.mode & 0o7777,
            link_count: info.nlink,
            entry_type: info.isDirectory() ? 'directory' : info.isFile() ? 'file' : 'other',
          });
      }
      if (info.isDirectory()) await walk(full, depth + 1);
    }
  }
  const rootInfo = await lstat(root);
  const rootAssessment = assess_macos_rootfs_entry_permissions({
    uid: rootInfo.uid,
    mode: rootInfo.mode,
    nlink: rootInfo.nlink,
    is_file: rootInfo.isFile(),
    is_directory: rootInfo.isDirectory(),
    is_symlink: rootInfo.isSymbolicLink(),
  }, expected_uid);
  if (!rootAssessment.trusted) {
    isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED',
      'Provider rootfs must be a trusted, non-writable regular directory', {
        path: root,
        owner_uid: rootInfo.uid,
        expected_uid,
        mode: rootInfo.mode & 0o7777,
      });
  }
  await walk(root, 0);
}

function process_group_exists(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return false;
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    return error?.code !== 'ESRCH';
  }
}

/**
 * Terminate and verify an isolated host-side compiler process group. Never
 * allow temporary compiler inputs/outputs to be removed while descendants
 * from that group may still be running.
 */
export async function cleanup_macos_compiler_process_group(pid, options = {}) {
  const term_grace_ms = options.term_grace_ms ?? 500;
  const verify_timeout_ms = options.verify_timeout_ms ?? 5000;
  if (!Number.isSafeInteger(pid) || pid < 1 ||
      !Number.isSafeInteger(term_grace_ms) || term_grace_ms < 0 || term_grace_ms > 10_000 ||
      !Number.isSafeInteger(verify_timeout_ms) || verify_timeout_ms < 1 || verify_timeout_ms > 30_000) {
    throw new TypeError('invalid macOS compiler process-group cleanup limits');
  }
  const wait_until_empty = async deadline => {
    while (process_group_exists(pid)) {
      if (Date.now() >= deadline) return false;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    return true;
  };
  if (!process_group_exists(pid)) {
    return Object.freeze({ term_signal_sent: false, force_kill_sent: false, verified_empty: true });
  }
  let term_signal_sent = false;
  try {
    process.kill(-pid, 'SIGTERM');
    term_signal_sent = true;
  } catch (error) {
    if (error?.code !== 'ESRCH') {
      // Continue to the verification/escalation phase. Failure to signal is
      // not treated as proof that the process group has disappeared.
    }
  }
  if (await wait_until_empty(Date.now() + term_grace_ms)) {
    return Object.freeze({ term_signal_sent, force_kill_sent: false, verified_empty: true });
  }
  let force_kill_sent = false;
  try {
    process.kill(-pid, 'SIGKILL');
    force_kill_sent = true;
  } catch (error) {
    if (error?.code !== 'ESRCH') {
      // The final bounded existence check below reports failure if it remains.
    }
  }
  const verified_empty = await wait_until_empty(Date.now() + verify_timeout_ms);
  if (!verified_empty) {
    isolation_error('ORIX_PROVIDER_MACOS_COMPILER_CLEANUP_FAILED',
      'Compiler process group remained present after SIGTERM/SIGKILL cleanup', {
        process_group_id: pid,
        term_signal_sent,
        force_kill_sent,
        verified_empty: false,
      });
  }
  return Object.freeze({ term_signal_sent, force_kill_sent, verified_empty: true });
}


/**
 * Remove compiler inputs/outputs only after the compiler process group is
 * known to be empty. On an unverified teardown, retain the private workspace
 * so a surviving descendant cannot race its deletion.
 */
export async function cleanup_macos_compiler_workspace(temporary, compiler_error, remove = rm) {
  if (typeof temporary !== 'string' || !path.isAbsolute(temporary) || typeof remove !== 'function') {
    throw new TypeError('invalid macOS compiler workspace cleanup arguments');
  }
  if (compiler_error?.code === 'ORIX_PROVIDER_MACOS_COMPILER_CLEANUP_FAILED') {
    throw new OrixError(
      'ORIX_PROVIDER_MACOS_COMPILER_CLEANUP_FAILED',
      'Compiler process group could not be proven empty; temporary workspace was preserved for operator recovery',
      {
        details: {
          ...(compiler_error.details ?? {}),
          workspace_path: temporary,
          workspace_preserved: true,
        },
        cause: compiler_error,
        recoverable: true,
      },
    );
  }
  try {
    await remove(temporary, { recursive: true, force: true });
  } catch (error) {
    throw new OrixError(
      'ORIX_PROVIDER_MACOS_CLEANUP_FAILED',
      'Could not remove the temporary Seatbelt compiler workspace',
      {
        details: { workspace_path: temporary, reason: error.code ?? error.name },
        cause: error,
        recoverable: true,
      },
    );
  }
  return Object.freeze({ workspace_preserved: false });
}

async function run_compiler(executable, args, cwd, env) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    let settled = false;
    let timedOut = false;
    let childClosed = false;
    let groupCleanupComplete = false;
    let groupCleanupError = null;
    let spawnError = null;
    let closeResult = null;
    let groupCleanupPromise = null;
    let timer = null;
    let child;

    const finish = () => {
      if (settled || !childClosed || !groupCleanupComplete) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (groupCleanupError) {
        reject(groupCleanupError);
      } else if (timedOut) {
        reject(new OrixError('ORIX_PROVIDER_MACOS_COMPILER_TIMEOUT',
          'macOS isolation launcher compilation exceeded 30 seconds; its process group was cleaned up', {
            details: { stdout, stderr, exit_code: closeResult?.code ?? null, signal: closeResult?.signal ?? null },
            recoverable: true,
          }));
      } else if (spawnError) {
        reject(new OrixError('ORIX_PROVIDER_MACOS_COMPILER_FAILED',
          'Could not start the macOS isolation launcher compiler', {
            details: { reason: spawnError.code ?? spawnError.name, stdout, stderr },
            cause: spawnError,
            recoverable: true,
          }));
      } else if (closeResult?.code === 0) {
        resolve();
      } else {
        reject(new OrixError('ORIX_PROVIDER_MACOS_COMPILER_FAILED',
          'Could not compile the macOS Seatbelt launcher', {
            details: { exit_code: closeResult?.code ?? null, signal: closeResult?.signal ?? null, stdout, stderr },
            recoverable: true,
          }));
      }
    };

    const start_group_cleanup = () => {
      if (groupCleanupPromise) return groupCleanupPromise;
      if (!Number.isSafeInteger(child?.pid) || child.pid < 1) {
        groupCleanupComplete = true;
        finish();
        return Promise.resolve();
      }
      groupCleanupComplete = false;
      groupCleanupPromise = cleanup_macos_compiler_process_group(child.pid)
        .catch(error => { groupCleanupError = error; })
        .finally(() => {
          groupCleanupComplete = true;
          finish();
        });
      return groupCleanupPromise;
    };

    try {
      child = spawn(executable, args, {
        cwd, env, shell: false, windowsHide: true, detached: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      spawnError = error;
      childClosed = true;
      groupCleanupComplete = true;
      finish();
      return;
    }

    child.stdout.on('data', chunk => {
      if (stdout.length < 8192) stdout += chunk.toString('utf8').slice(0, 8192 - stdout.length);
    });
    child.stderr.on('data', chunk => {
      if (stderr.length < 8192) stderr += chunk.toString('utf8').slice(0, 8192 - stderr.length);
    });
    child.once('error', error => {
      spawnError = error;
      childClosed = true;
      // The close/error event can arrive after timeout cleanup has already
      // completed. Always re-run finish after the shared cleanup promise.
      void start_group_cleanup().finally(finish);
    });
    child.once('close', (code, signal) => {
      closeResult = { code, signal };
      childClosed = true;
      // Even a successful compiler leader may have left a same-group child.
      // Verify group emptiness before its temporary directory can be removed.
      // Chain finish explicitly: timeout cleanup may have settled before this
      // close event, in which case the shared promise's original finally ran
      // while childClosed was still false.
      void start_group_cleanup().finally(finish);
    });

    timer = setTimeout(() => {
      if (settled || childClosed) return;
      timedOut = true;
      // Cleanup sends SIGTERM, escalates to SIGKILL only if needed, and waits
      // until the OS reports the complete compiler process group gone.
      void start_group_cleanup();
    }, 30_000);
    timer.unref?.();
  });
}
async function resolve_compiler() {
  const candidate = '/usr/bin/clang';
  try {
    const canonical = await realpath(candidate);
    await access(canonical, FS_CONSTANTS.X_OK);
    return canonical;
  } catch (error) {
    isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'Xcode Command Line Tools clang is required for macOS provider isolation', {
      reason: error.code ?? error.name,
    });
  }
}

const PROFILE = `(version 1)
(deny default)
(allow process-fork)
(allow process-exec (subpath (param "ORIX_ROOT")))
(allow file-read* (subpath (param "ORIX_ROOT")))
; macOS requires root-directory metadata and system runtime files (including
; dyld shared-cache content below /System/Volumes/Preboot/Cryptexes).
(allow file-read* (literal "/"))
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/usr/lib"))
(allow file-read* (subpath "/usr/bin"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/private/var/db/dyld"))
(allow file-read* (literal "/dev/null"))
(allow file-read* (literal "/dev/zero"))
(allow file-read* (literal "/dev/random"))
(allow file-read* (literal "/dev/urandom"))
(allow file-write* (subpath (param "ORIX_TMP")))
(allow file-read* (subpath (param "ORIX_TMP")))
(allow sysctl-read)
(allow mach-lookup (global-name "com.apple.system.logger"))
`;

export async function prepare_macos_provider_isolation({
  executable, cwd, sandbox_root, args, env,
}) {
  if (process.platform !== 'darwin') {
    isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'macOS Seatbelt isolation is only available on macOS', {
      platform: process.platform,
    });
  }
  const root = await validate_directory(sandbox_root, 'sandbox_root');
  const scratch = await validate_directory(path.join(root, 'tmp'), 'sandbox_root/tmp');
  const work = await validate_directory(cwd, 'provider working directory');
  const provider = await realpath(executable);
  if (!within(root, provider) || !within(root, work) || !within(root, scratch)) {
    isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED',
      'macOS provider executable, working directory and temporary directory must be inside sandbox_root');
  }
  await validate_tree(root);

  const compiler = await resolve_compiler();
  const temporary = await mkdtemp(path.join(tmpdir(), 'orix-provider-macos-'));
  const profilePath = path.join(temporary, 'provider.sb');
  const launcher = path.join(temporary, 'orix-macos-provider-launcher');
  // Compile only with the trusted service environment. Provider-supplied SDK,
  // toolchain and temp variables must not influence this host-side compiler.
  const hostEnvironment = Object.create(null);
  for (const key of ['HOME', 'PATH', 'DEVELOPER_DIR', 'SDKROOT', 'TOOLCHAINS', 'LANG']) {
    if (typeof process.env[key] === 'string') hostEnvironment[key] = process.env[key];
  }
  hostEnvironment.TMPDIR = temporary;
  hostEnvironment.TMP = temporary;
  hostEnvironment.TEMP = temporary;
  const source = fileURLToPath(new URL('../../native/macos-provider-launcher.c', import.meta.url));
  try {
    await writeFile(profilePath, PROFILE, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    await run_compiler(compiler, ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', source, '-lsandbox', '-o', launcher],
      temporary, hostEnvironment);
  } catch (error) {
    // Never delete compiler files while a descendant may still be using them.
    await cleanup_macos_compiler_workspace(temporary, error);
    throw error;
  }

  let cleanupPromise = null;
  const cleanup = () => {
    if (cleanupPromise) return cleanupPromise;
    cleanupPromise = rm(temporary, { recursive: true, force: true }).catch(error => {
      cleanupPromise = null;
      throw new OrixError('ORIX_PROVIDER_MACOS_CLEANUP_FAILED', 'Could not remove the temporary Seatbelt launcher files', {
        details: { reason: error.code ?? error.name }, cause: error, recoverable: true,
      });
    });
    return cleanupPromise;
  };

  return Object.freeze({
    executable: launcher,
    args: Object.freeze([profilePath, root, scratch, provider, ...args]),
    cwd: work,
    env: Object.freeze({
      ...env,
      TMPDIR: scratch,
      TMP: scratch,
      TEMP: scratch,
      HOME: scratch,
    }),
    cleanup,
    cleanup_on_terminate: false,
  });
}
