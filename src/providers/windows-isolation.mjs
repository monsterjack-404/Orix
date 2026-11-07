// Windows provider isolation through AppContainer and Job Objects.
import { lstat, mkdtemp, open, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { OrixError } from '../core/errors.mjs';
import { decodeWindowsProviderLauncher, WINDOWS_PROVIDER_LAUNCHER_SHA256, WINDOWS_PROVIDER_LAUNCHER_GZIP_SHA256, WINDOWS_PROVIDER_LAUNCHER_MAX_COMPRESSED_BYTES } from './windows-launcher-integrity.mjs';

function isolation_error(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}
function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}
async function validate_directory(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', label + ' must be an absolute path for required Windows isolation');
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
  return realpath(value);
}
async function validate_tree(root) {
  let entries_seen = 0;
  async function walk(directory, depth) {
    if (depth > 64) isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID', 'Provider rootfs exceeds the maximum directory depth');
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (++entries_seen > 100_000) isolation_error('ORIX_PROVIDER_SANDBOX_ROOT_INVALID', 'Provider rootfs exceeds the maximum entry count');
      const full = path.join(directory, entry.name);
      const info = await lstat(full);
      if (info.isSymbolicLink()) isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED', 'Provider rootfs must not contain reparse points or symbolic links');
      if (!info.isFile() && !info.isDirectory()) isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED', 'Provider rootfs must contain only regular files and directories');
      if (info.isFile() && info.nlink > 1) isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED', 'Provider rootfs must not contain hard-linked files');
      if (info.isDirectory()) await walk(full, depth + 1);
    }
  }
  await walk(root, 0);
}
function same_file_identity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}
async function load_windows_launcher_payload() {
  const payloadPath = fileURLToPath(new URL('../../native/bin/win32-anycpu/orix-windows-provider-launcher.exe.gz', import.meta.url));
  let handle;
  try {
    // Open first, then inspect the opened object. All bytes are read from this
    // retained handle, so a later path replacement cannot redirect the read.
    handle = await open(payloadPath, 'r');
    const opened = await handle.stat();
    const pathEntry = await lstat(payloadPath);
    if (pathEntry.isSymbolicLink() || !pathEntry.isFile() ||
        !opened.isFile() || !same_file_identity(opened, pathEntry) ||
        opened.size <= 0 || opened.size > WINDOWS_PROVIDER_LAUNCHER_MAX_COMPRESSED_BYTES) {
      isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'The packaged Windows AppContainer launcher payload is not a stable bounded regular file');
    }
    const compressed = await handle.readFile();
    const afterHandle = await handle.stat();
    if (!same_file_identity(opened, afterHandle) || compressed.length !== afterHandle.size) {
      isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'The opened Windows launcher payload changed while being read');
    }
    try {
      const launcherBytes = decodeWindowsProviderLauncher(compressed);
      if (createHash('sha256').update(compressed).digest('hex') !== WINDOWS_PROVIDER_LAUNCHER_GZIP_SHA256 ||
          createHash('sha256').update(launcherBytes).digest('hex') !== WINDOWS_PROVIDER_LAUNCHER_SHA256) {
        isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'The packaged Windows launcher failed its source-pinned integrity check');
      }
      return launcherBytes;
    } catch (error) {
      if (error instanceof OrixError) throw error;
      isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'The packaged Windows launcher failed its source-pinned integrity check', { reason: error.message });
    }
  } catch (error) {
    if (error instanceof OrixError) throw error;
    isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'The Windows launcher payload could not be safely read', { reason: error.code ?? error.name });
  } finally {
    await handle?.close().catch(() => {});
  }
}
async function run_native_helper(executable, args, cwd, environment, logPath, timeoutMs = 30_000) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    let settled = false;
    let timedOut = false;
    const child = spawn(executable, args, { cwd, env: environment, shell: false, windowsHide: true, detached: false, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', chunk => { if (stdout.length < 8192) stdout += chunk.toString('utf8').slice(0, 8192 - stdout.length); });
    child.stderr.on('data', chunk => { if (stderr.length < 8192) stderr += chunk.toString('utf8').slice(0, 8192 - stderr.length); });
    const timer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      // Do not settle or let callers remove the helper's working directory yet.
      // Wait for 'close' so the process has exited and its stdio handles are closed.
      child.kill();
    }, timeoutMs);
    child.once('error', error => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      reject(new OrixError('ORIX_PROVIDER_WINDOWS_HELPER_FAILED', 'Could not start the trusted Windows provider helper', {
        details: { reason: error.code ?? error.name, stdout, stderr }, cause: error, recoverable: true,
      }));
    });
    child.once('close', async (code, signal) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      child.stdout.destroy(); child.stderr.destroy();
      if (timedOut) {
        const helperLog = logPath ? await readFile(logPath, 'utf8').catch(() => '') : '';
        reject(new OrixError('ORIX_PROVIDER_WINDOWS_HELPER_TIMEOUT', 'Windows native provider helper exceeded its time limit', {
          details: { timeout_ms: timeoutMs, exit_code: code, signal, stdout, stderr, helper_log: helperLog.slice(-8192) }, recoverable: true,
        }));
      } else if (code === 0) resolve({ stdout, stderr });
      else reject(new OrixError('ORIX_PROVIDER_WINDOWS_HELPER_FAILED', 'Windows native provider helper returned a failure status', {
        details: { exit_code: code, signal, stdout, stderr }, recoverable: true,
      }));
    });
  });
}

export async function prepare_windows_provider_isolation({ executable, cwd, sandbox_root, args, env }) {
  if (process.platform !== 'win32') isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'Windows AppContainer isolation is only available on Windows', { platform: process.platform });
  if (typeof sandbox_root !== 'string' || !path.isAbsolute(sandbox_root)) isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'Windows AppContainer isolation requires an explicit absolute sandbox_root');
  const root = await validate_directory(sandbox_root, 'sandbox_root');
  const work = await validate_directory(cwd, 'provider working directory');
  const provider = await realpath(executable);
  if (!within(root, provider) || !within(root, work)) isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED', 'Windows provider executable and working directory must be inside sandbox_root');
  await validate_tree(root);
  const hostEnvironment = Object.create(null);
  for (const key of ['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP']) {
    if (typeof process.env[key] === 'string') hostEnvironment[key] = process.env[key];
  }
  const launcherBytes = await load_windows_launcher_payload();
  const temporary = await mkdtemp(path.join(tmpdir(), 'orix-provider-win-'));
  const configPath = path.join(temporary, 'provider.json');
  const logPath = path.join(temporary, 'provider.log');
  const launcher = path.join(temporary, 'orix-windows-provider-launcher.exe');
  const profileName = 'ORIX-' + randomUUID().replaceAll('-', '');
  const providerEnvironment = Object.create(null);
  for (const key of ['SystemRoot', 'WINDIR']) {
    const value = process.env[key];
    if (typeof value === 'string' && value.length > 0) providerEnvironment[key] = value;
  }
  // Provider overrides must not replace the host's Windows runtime identity.
  // Windows environment names are case-insensitive, so reject every spelling
  // of these reserved keys before adding the trusted values below.
  for (const [key, value] of Object.entries(env)) {
    const normalizedKey = key.toLowerCase();
    if (normalizedKey === 'systemroot' || normalizedKey === 'windir') continue;
    providerEnvironment[key] = value;
  }
  const trustedSystemRoot = [process.env.SystemRoot, process.env.WINDIR].find(value => typeof value === 'string' && value.trim().length > 0);
  if (typeof trustedSystemRoot === 'string') {
    providerEnvironment.SystemRoot = trustedSystemRoot;
    providerEnvironment.WINDIR = trustedSystemRoot;
  }
  Object.assign(providerEnvironment, {
    HOME: root,
    USERPROFILE: root,
    APPDATA: root,
    LOCALAPPDATA: root,
    TEMP: root,
    TMP: root,
  });
  try {
    await writeFile(configPath, JSON.stringify({
      executable: provider, args, cwd: work, sandboxRoot: root, profileName, logPath, environment: providerEnvironment,
    }), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    // Create exclusively and verify through the same open handle. Do not
    // lstat/readFile the path after creation: the descriptor pins the object
    // while it is written, chmodded and read back.
    const stagedHandle = await open(launcher, 'wx+', 0o500);
    try {
      await stagedHandle.writeFile(launcherBytes);
      await stagedHandle.sync();
      await stagedHandle.chmod(0o500);
      const stagedInfo = await stagedHandle.stat();
      const stagedBytes = Buffer.alloc(launcherBytes.length);
      let stagedOffset = 0;
      while (stagedOffset < stagedBytes.length) {
        const { bytesRead } = await stagedHandle.read(
          stagedBytes, stagedOffset, stagedBytes.length - stagedOffset, stagedOffset,
        );
        if (bytesRead === 0) throw new Error('Staged Windows launcher read-back was truncated');
        stagedOffset += bytesRead;
      }
      if (!stagedInfo.isFile() || stagedInfo.size !== launcherBytes.length ||
          !stagedBytes.equals(launcherBytes) ||
          createHash('sha256').update(stagedBytes).digest('hex') !== WINDOWS_PROVIDER_LAUNCHER_SHA256) {
        throw new Error('Staged Windows launcher failed its source-pinned integrity check');
      }
    } finally {
      await stagedHandle.close();
    }
  } catch (error) {
    await rm(temporary, { recursive: true, force: true }).catch(() => {});
    if (error instanceof OrixError) throw error;
    throw new OrixError('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'Could not stage the source-pinned Windows AppContainer launcher', {
      details: { reason: error.code ?? error.name }, cause: error, recoverable: true,
    });
  }
  let cleanupPromise = null;
  const cleanup = () => {
    if (cleanupPromise) return cleanupPromise;
    cleanupPromise = (async () => {
      try { await run_native_helper(launcher, ['cleanup', configPath], temporary, hostEnvironment, logPath, 30_000); }
      finally { cleanup.last_log = await readFile(logPath, 'utf8').catch(() => ''); }
      await rm(temporary, { recursive: true, force: true });
    })().catch(error => { cleanupPromise = null; throw error; });
    return cleanupPromise;
  };
  return Object.freeze({
    executable: launcher,
    args: Object.freeze(['run', configPath]),
    cwd: temporary,
    env: Object.freeze({ ...env }),
    cleanup,
    cleanup_on_terminate: false,
  });
}
