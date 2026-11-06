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

async function validate_directory(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', label + ' must be an absolute path for required macOS isolation');
  }
  let info;
  try { info = await lstat(value); }
  catch (error) {
    isolation_error('ORIX_PROVIDER_SANDBOX_PATH_UNAVAILABLE', label + ' cannot be inspected', {
      reason: error.code ?? 'filesystem-error',
    });
  }
  if (info.isSymbolicLink() || !info.isDirectory()) {
    isolation_error('ORIX_PROVIDER_SANDBOX_PATH_INVALID', label + ' must be a real non-symlink directory');
  }
  return realpath(value);
}

async function validate_tree(root) {
  let entries_seen = 0;
  async function walk(directory, depth) {
    if (depth > 64) isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID', 'Provider rootfs exceeds the maximum directory depth');
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      entries_seen += 1;
      if (entries_seen > 100_000) isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID', 'Provider rootfs exceeds the maximum entry count');
      const full = path.join(directory, entry.name);
      const info = await lstat(full);
      if (info.isSymbolicLink()) isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED', 'Provider rootfs must not contain symbolic links');
      if (!info.isFile() && !info.isDirectory()) isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED', 'Provider rootfs must contain only regular files and directories');
      if (info.isFile() && info.nlink > 1) isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED', 'Provider rootfs must not contain hard-linked files');
      if (info.isDirectory()) await walk(full, depth + 1);
    }
  }
  await walk(root, 0);
}

async function run_compiler(executable, args, cwd, env) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    let settled = false;
    const child = spawn(executable, args, {
      cwd, env, shell: false, windowsHide: true, detached: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', chunk => { if (stdout.length < 8192) stdout += chunk.toString('utf8').slice(0, 8192 - stdout.length); });
    child.stderr.on('data', chunk => { if (stderr.length < 8192) stderr += chunk.toString('utf8').slice(0, 8192 - stderr.length); });
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(new OrixError('ORIX_PROVIDER_MACOS_COMPILER_TIMEOUT', 'macOS isolation launcher compilation exceeded 30 seconds', {
        details: { stdout, stderr }, recoverable: true,
      }));
    }, 30_000);
    child.once('error', error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new OrixError('ORIX_PROVIDER_MACOS_COMPILER_FAILED', 'Could not start the macOS isolation launcher compiler', {
        details: { reason: error.code ?? error.name, stdout, stderr }, cause: error, recoverable: true,
      }));
    });
    child.once('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new OrixError('ORIX_PROVIDER_MACOS_COMPILER_FAILED', 'Could not compile the macOS Seatbelt launcher', {
        details: { exit_code: code, signal, stdout, stderr }, recoverable: true,
      }));
    });
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
    await rm(temporary, { recursive: true, force: true }).catch(() => {});
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
