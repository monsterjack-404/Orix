// Windows provider isolation through AppContainer and Job Objects.
import { constants as FS_CONSTANTS } from 'node:fs';
import { access, lstat, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { OrixError } from '../core/errors.mjs';

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
  catch (error) { isolation_error('ORIX_PROVIDER_SANDBOX_PATH_UNAVAILABLE', label + ' cannot be inspected', { reason: error.code ?? 'filesystem-error' }); }
  if (info.isSymbolicLink() || !info.isDirectory()) isolation_error('ORIX_PROVIDER_SANDBOX_PATH_INVALID', label + ' must be a real non-symlink directory');
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
async function resolve_csc(environment) {
  const systemRoot = environment.SystemRoot ?? environment.WINDIR ?? process.env.SystemRoot ?? process.env.WINDIR;
  if (!systemRoot) isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'SystemRoot is required to locate the trusted .NET Framework compiler');
  for (const candidate of [
    path.join(systemRoot, 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe'),
    path.join(systemRoot, 'Microsoft.NET', 'Framework', 'v4.0.30319', 'csc.exe'),
  ]) {
    try {
      const info = await lstat(candidate);
      if (info.isSymbolicLink() || !info.isFile()) continue;
      const canonical = await realpath(candidate);
      await access(canonical, FS_CONSTANTS.X_OK);
      return canonical;
    } catch { /* fixed trusted compiler paths only */ }
  }
  isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'A trusted .NET Framework csc.exe compiler is required for Windows AppContainer isolation');
}
async function run_native_helper(executable, args, cwd, environment, logPath, timeoutMs = 30_000) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    let settled = false;
    const child = spawn(executable, args, { cwd, env: environment, shell: false, windowsHide: true, detached: false, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', chunk => { if (stdout.length < 8192) stdout += chunk.toString('utf8').slice(0, 8192 - stdout.length); });
    child.stderr.on('data', chunk => { if (stderr.length < 8192) stderr += chunk.toString('utf8').slice(0, 8192 - stderr.length); });
    const timer = setTimeout(async () => {
      if (settled) return;
      settled = true;
      child.kill();
      const helperLog = logPath ? await readFile(logPath, 'utf8').catch(() => '') : '';
      reject(new OrixError('ORIX_PROVIDER_WINDOWS_HELPER_TIMEOUT', 'Windows native provider helper exceeded its time limit', {
        details: { timeout_ms: timeoutMs, stdout, stderr, helper_log: helperLog.slice(-8192) }, recoverable: true,
      }));
    }, timeoutMs);
    child.once('error', error => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      reject(new OrixError('ORIX_PROVIDER_WINDOWS_HELPER_FAILED', 'Could not start the trusted Windows provider helper', {
        details: { reason: error.code ?? error.name, stdout, stderr }, cause: error, recoverable: true,
      }));
    });
    child.once('exit', (code, signal) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      child.stdout.destroy(); child.stderr.destroy();
      if (code === 0) resolve({ stdout, stderr });
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
  const compiler = await resolve_csc(env);
  const temporary = await mkdtemp(path.join(tmpdir(), 'orix-provider-win-'));
  const configPath = path.join(temporary, 'provider.json');
  const logPath = path.join(temporary, 'provider.log');
  const launcher = path.join(temporary, 'orix-windows-provider-launcher.exe');
  const source = fileURLToPath(new URL('../../native/windows-provider-launcher.cs', import.meta.url));
  const profileName = 'ORIX-' + randomUUID().replaceAll('-', '');
  const providerEnvironment = { ...env, HOME: root, USERPROFILE: root, APPDATA: root, LOCALAPPDATA: root, TEMP: root, TMP: root };
  try {
    await writeFile(configPath, JSON.stringify({
      executable: provider, args, cwd: work, sandboxRoot: root, profileName, logPath, environment: providerEnvironment,
    }), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    await run_native_helper(compiler, [
      '/nologo', '/target:exe', '/out:' + launcher,
      '/r:System.Core.dll', '/r:System.Security.dll', '/r:System.Web.Extensions.dll', source,
    ], temporary, env, null, 30_000);
  } catch (error) {
    await rm(temporary, { recursive: true, force: true }).catch(() => {});
    throw new OrixError('ORIX_PROVIDER_WINDOWS_COMPILER_FAILED', 'Could not build the native Windows AppContainer launcher', {
      details: { reason: error.code ?? error.name, diagnostic: error.details ?? null }, cause: error, recoverable: true,
    });
  }
  let cleanupPromise = null;
  const cleanup = () => {
    if (cleanupPromise) return cleanupPromise;
    cleanupPromise = (async () => {
      try { await run_native_helper(launcher, ['cleanup', configPath], temporary, env, logPath, 30_000); }
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
