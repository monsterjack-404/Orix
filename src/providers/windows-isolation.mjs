// Windows provider isolation through AppContainer and Job Objects.
import { constants as FS_CONSTANTS } from 'node:fs';
import { access, lstat, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
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
  return relative === '' || (relative !== '..' &&
    !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

async function validate_directory(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    throw new TypeError(label + ' must be an absolute filesystem path');
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

async function resolve_powershell(environment) {
  const systemRoot = environment.SystemRoot ?? environment.WINDIR;
  if (typeof systemRoot !== 'string' || !path.isAbsolute(systemRoot)) {
    isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'Windows SystemRoot is missing from the safe provider environment');
  }
  const candidate = path.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  try {
    const info = await lstat(candidate);
    if (info.isSymbolicLink() || !info.isFile()) throw new Error('not-a-regular-file');
    const canonical = await realpath(candidate);
    await access(canonical, FS_CONSTANTS.X_OK);
    return canonical;
  } catch (error) {
    isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE', 'Windows PowerShell 5.1 is required for the AppContainer launcher', {
      reason: error.code ?? error.name ?? 'powershell-unavailable',
    });
  }
}

function run_powershell(executable, script, mode, config_path, cwd, environment) {
  return new Promise((resolve, reject) => {
    let stderr = '';
    let settled = false;
    const child = spawn(executable, [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', script, mode, config_path,
    ], {
      cwd,
      env: environment,
      shell: false,
      windowsHide: true,
      detached: false,
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    child.stderr.on('data', chunk => {
      if (stderr.length < 8192) stderr += chunk.toString('utf8').slice(0, 8192 - stderr.length);
    });
    child.once('error', error => {
      if (settled) return;
      settled = true;
      reject(new OrixError('ORIX_PROVIDER_WINDOWS_LAUNCHER_FAILED',
        'Windows AppContainer helper could not be started', {
          details: { reason: error.code ?? error.name ?? 'spawn-error' },
          cause: error,
          recoverable: true,
        }));
    });
    child.once('close', (code, signal) => {
      if (settled) return;
      settled = true;
      if (code === 0) resolve();
      else reject(new OrixError('ORIX_PROVIDER_WINDOWS_LAUNCHER_FAILED',
        'Windows AppContainer helper exited without completing its operation', {
          details: { exit_code: code, signal, stderr: stderr.slice(0, 8192) },
          recoverable: true,
        }));
    });
  });
}

export async function prepare_windows_provider_isolation({
  executable, cwd, sandbox_root, args, env,
}) {
  if (process.platform !== 'win32') {
    isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE',
      'Windows AppContainer isolation is only available on Windows', { platform: process.platform });
  }
  const root = await validate_directory(sandbox_root, 'sandbox_root');
  const work = await validate_directory(cwd, 'provider working directory');
  const provider = await realpath(executable);
  if (!within(root, provider) || !within(root, work)) {
    isolation_error('ORIX_PROVIDER_SANDBOX_PATH_DENIED',
      'Windows provider executable and working directory must be inside sandbox_root');
  }

  const powershell = await resolve_powershell(env);
  const script = fileURLToPath(new URL('../../scripts/windows-provider-launcher.ps1', import.meta.url));
  const temporary = await mkdtemp(path.join(tmpdir(), 'orix-provider-win-'));
  const configPath = path.join(temporary, 'provider.json');
  const profileName = 'ORIX-' + randomUUID().replaceAll('-', '');
  const providerEnvironment = {
    ...env,
    HOME: root,
    USERPROFILE: root,
  };
  const config = {
    executable: provider,
    args,
    cwd: work,
    sandboxRoot: root,
    profileName,
    environment: providerEnvironment,
  };

  try {
    await writeFile(configPath, JSON.stringify(config), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  } catch (error) {
    await rm(temporary, { recursive: true, force: true }).catch(() => {});
    isolation_error('ORIX_PROVIDER_WINDOWS_CONFIG_FAILED',
      'Could not prepare the private AppContainer launch configuration', {
        reason: error.code ?? error.name ?? 'write-failed',
      });
  }

  let cleanupPromise = null;
  const cleanup = () => {
    if (cleanupPromise) return cleanupPromise;
    cleanupPromise = (async () => {
      await run_powershell(powershell, script, 'cleanup', configPath, temporary, env);
      await rm(temporary, { recursive: true, force: true });
    })().catch(error => {
      cleanupPromise = null;
      throw error;
    });
    return cleanupPromise;
  };

  return Object.freeze({
    executable: powershell,
    args: Object.freeze([
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', script, 'run', configPath,
    ]),
    cwd: temporary,
    env: Object.freeze({ ...env }),
    cleanup,
    cleanup_on_terminate: false,
  });
}
