// JavaScript, src/providers/process-runner.mjs, Node.js 20+, bounded static-provider process execution.

import { constants as FS_CONSTANTS } from 'node:fs';
import { access, lstat, realpath, stat } from 'node:fs/promises';
import { prepare_linux_provider_isolation } from './linux-isolation.mjs';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { OrixError } from '../core/errors.mjs';
import { validate_provider_manifest } from './manifest.mjs';

const ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;
const BLOCKED_ENVIRONMENT_KEYS = new Set([
  'PATH', 'PATHEXT', 'NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH',
  'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'DYLD_FRAMEWORK_PATH',
  'PYTHONPATH', 'PYTHONHOME', 'PERL5OPT', 'RUBYOPT', 'BASH_ENV', 'ENV', 'IFS',
]);
const MAX_ARGUMENTS = 256;
const MAX_ARGUMENT_BYTES = 32 * 1024;
const MAX_TOTAL_ARGUMENT_BYTES = 64 * 1024;
const MAX_ENVIRONMENT_ENTRIES = 64;
const MAX_ENVIRONMENT_BYTES = 32 * 1024;

function runner_error(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function plain_options(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Provider process options must be an object');
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError('Provider process options must be a plain object');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const allowed = new Set([
    'manifest', 'executable', 'args', 'cwd', 'env',
    'allowed_executables', 'allowed_working_directories', 'executable_args',
    'timeout_ms', 'max_output_bytes', 'kill_grace_ms', 'signal', 'isolation', 'sandbox_root',
  ]);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowed.has(key)) {
      throw new TypeError('Unknown provider process option: ' + String(key));
    }
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      throw new TypeError('Provider process options must use enumerable data properties');
    }
  }
  return descriptors;
}

function validate_arguments(value) {
  if (!Array.isArray(value) || value.length > MAX_ARGUMENTS) {
    throw new TypeError('args must be an array with at most ' + MAX_ARGUMENTS + ' strings');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(value)) {
    if (key === 'length') continue;
    if (typeof key !== 'string' ||
        !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length) {
      throw new TypeError('args must not contain custom array properties');
    }
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      throw new TypeError('args must contain enumerable data elements only');
    }
  }
  let total = 0;
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor) throw new TypeError('args must not be sparse');
    const argument = descriptor.value;
    if (typeof argument !== 'string' || argument.includes('\0')) {
      throw new TypeError('args[' + index + '] must be a string without NUL bytes');
    }
    const bytes = Buffer.byteLength(argument, 'utf8');
    if (bytes > MAX_ARGUMENT_BYTES) {
      throw new TypeError('args[' + index + '] exceeds the per-argument byte limit');
    }
    total += bytes;
    if (total > MAX_TOTAL_ARGUMENT_BYTES) {
      throw new TypeError('args exceed the total argument byte limit');
    }
    result.push(argument);
  }
  return result;
}

function validate_environment(value) {
  if (value === undefined) return Object.freeze({});
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('env must be a plain object of string values');
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError('env must be a plain object');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const entries = Reflect.ownKeys(value);
  if (entries.length > MAX_ENVIRONMENT_ENTRIES) {
    throw new TypeError('env contains too many entries');
  }
  const result = Object.create(null);
  let total = 0;
  for (const key of entries) {
    const descriptor = descriptors[key];
    if (typeof key !== 'string' || !ENV_KEY.test(key) || BLOCKED_ENVIRONMENT_KEYS.has(key.toUpperCase()) ||
        !descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      throw new TypeError('env must contain enumerable string data properties with valid names');
    }
    const item = descriptor.value;
    if (typeof item !== 'string' || item.includes('\0')) {
      throw new TypeError('env values must be strings without NUL bytes');
    }
    total += Buffer.byteLength(key, 'utf8') + Buffer.byteLength(item, 'utf8');
    if (total > MAX_ENVIRONMENT_BYTES) throw new TypeError('env exceeds the total byte limit');
    result[key] = item;
  }
  return Object.freeze(result);
}

function validate_absolute_path_list(value, label, maximum) {
  if (!Array.isArray(value) || value.length === 0 || value.length > maximum) {
    throw new TypeError(label + ' must contain between 1 and ' + maximum + ' absolute paths');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(value)) {
    if (key === 'length') continue;
    if (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length) {
      throw new TypeError(label + ' must not contain custom array properties');
    }
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      throw new TypeError(label + ' must contain enumerable data entries only');
    }
  }
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor) throw new TypeError(label + ' must not be sparse');
    const item = descriptor.value;
    if (typeof item !== 'string' || !path.isAbsolute(item) || item.includes('\0') || item.length > 4096) {
      throw new TypeError(label + ' entries must be absolute paths without NUL bytes');
    }
    result.push(item);
  }
  return result;
}

function is_within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' &&
    !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

async function validate_executable(value, allowed_executables) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    throw new TypeError('executable must be an absolute filesystem path');
  }
  let details;
  try { details = await lstat(value); }
  catch (error) {
    runner_error('ORIX_PROVIDER_EXECUTABLE_UNAVAILABLE', 'Provider executable cannot be inspected', {
      path: value, reason: error.code ?? 'filesystem-error',
    });
  }
  if (details.isSymbolicLink() || !details.isFile()) {
    runner_error('ORIX_PROVIDER_EXECUTABLE_NOT_REGULAR', 'Provider executable must be a regular non-symlink file', { path: value });
  }
  let canonical;
  let canonical_details;
  try {
    canonical = await realpath(value);
    canonical_details = await stat(canonical);
  } catch (error) {
    runner_error('ORIX_PROVIDER_EXECUTABLE_UNAVAILABLE', 'Provider executable could not be resolved', {
      path: value, reason: error.code ?? 'filesystem-error',
    });
  }
  if (!canonical_details.isFile()) {
    runner_error('ORIX_PROVIDER_EXECUTABLE_NOT_REGULAR', 'Resolved provider executable is not a regular file', { path: canonical });
  }
  if (process.platform !== 'win32') {
    try { await access(canonical, FS_CONSTANTS.X_OK); }
    catch {
      runner_error('ORIX_PROVIDER_EXECUTABLE_NOT_RUNNABLE', 'Provider executable does not have execute permission', { path: canonical });
    }
  }
  if (process.platform === 'win32' && /\.(bat|cmd|ps1)$/i.test(canonical)) {
    runner_error('ORIX_PROVIDER_EXECUTABLE_SCRIPT', 'Script launchers are not accepted as provider executables on Windows', { path: canonical });
  }

  const allowed = validate_absolute_path_list(allowed_executables, 'allowed_executables', 128);
  let matched = false;
  for (const candidate of allowed) {
    let candidate_details;
    try { candidate_details = await lstat(candidate); }
    catch (error) {
      runner_error('ORIX_PROVIDER_ALLOWLIST_UNAVAILABLE', 'An allowlisted executable cannot be inspected', {
        path: candidate, reason: error.code ?? 'filesystem-error',
      });
    }
    if (candidate_details.isSymbolicLink() || !candidate_details.isFile()) {
      runner_error('ORIX_PROVIDER_ALLOWLIST_UNSAFE', 'Allowlisted executables must be regular non-symlink files', { path: candidate });
    }
    if (await realpath(candidate) === canonical) matched = true;
  }
  if (!matched) {
    runner_error('ORIX_PROVIDER_EXECUTABLE_DENIED', 'Executable is not present in the explicit executable allowlist', { path: canonical });
  }
  return canonical;
}

async function validate_working_directory(value, allowed_roots) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0')) {
    throw new TypeError('cwd must be an absolute filesystem path');
  }
  let details;
  try { details = await lstat(value); }
  catch (error) {
    runner_error('ORIX_PROVIDER_CWD_UNAVAILABLE', 'Provider working directory cannot be inspected', {
      path: value, reason: error.code ?? 'filesystem-error',
    });
  }
  if (details.isSymbolicLink() || !details.isDirectory()) {
    runner_error('ORIX_PROVIDER_CWD_INVALID', 'Provider working directory must be a non-symlink directory', { path: value });
  }
  let canonical;
  try { canonical = await realpath(value); }
  catch (error) {
    runner_error('ORIX_PROVIDER_CWD_UNAVAILABLE', 'Provider working directory could not be resolved', {
      path: value, reason: error.code ?? 'filesystem-error',
    });
  }
  const roots = validate_absolute_path_list(allowed_roots, 'allowed_working_directories', 64);
  let matched = false;
  for (const root of roots) {
    let root_details;
    try { root_details = await lstat(root); }
    catch (error) {
      runner_error('ORIX_PROVIDER_CWD_ALLOWLIST_UNAVAILABLE', 'An allowed working-directory root cannot be inspected', {
        path: root, reason: error.code ?? 'filesystem-error',
      });
    }
    if (root_details.isSymbolicLink() || !root_details.isDirectory()) {
      runner_error('ORIX_PROVIDER_CWD_ALLOWLIST_UNSAFE', 'Allowed working-directory roots must be non-symlink directories', { path: root });
    }
    if (is_within(await realpath(root), canonical)) matched = true;
  }
  if (!matched) {
    runner_error('ORIX_PROVIDER_CWD_DENIED', 'Provider working directory is outside the explicit allowlist', { cwd: canonical });
  }
  return canonical;
}

function validate_runtime_limits(manifest, options) {
  const timeout_ms = options.timeout_ms ?? manifest.limits.timeout_ms;
  const max_output_bytes = options.max_output_bytes ?? manifest.limits.max_output_bytes;
  const kill_grace_ms = options.kill_grace_ms ?? 500;
  if (!Number.isSafeInteger(timeout_ms) || timeout_ms < 1 || timeout_ms > manifest.limits.timeout_ms) {
    throw new TypeError('timeout_ms must be between 1 and the provider manifest timeout limit');
  }
  if (!Number.isSafeInteger(max_output_bytes) || max_output_bytes < 1 || max_output_bytes > manifest.limits.max_output_bytes) {
    throw new TypeError('max_output_bytes must be between 1 and the provider manifest output limit');
  }
  if (!Number.isSafeInteger(kill_grace_ms) || kill_grace_ms < 0 || kill_grace_ms > 10_000) {
    throw new TypeError('kill_grace_ms must be an integer between 0 and 10000');
  }
  return { timeout_ms, max_output_bytes, kill_grace_ms };
}

function minimal_environment(overrides) {
  const result = Object.create(null);
  if (process.platform === 'win32') {
    for (const key of ['SystemRoot', 'WINDIR', 'TEMP', 'TMP']) {
      if (typeof process.env[key] === 'string') result[key] = process.env[key];
    }
  }
  for (const [key, value] of Object.entries(overrides)) result[key] = value;
  return result;
}

function process_group_exists(pid) {
  if (process.platform === 'win32' || !Number.isSafeInteger(pid) || pid < 1) return false;
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    return error?.code !== 'ESRCH';
  }
}

function signal_process_group(pid, signal) {
  if (process.platform === 'win32' || !Number.isSafeInteger(pid) || pid < 1) return false;
  try {
    process.kill(-pid, signal);
    return true;
  } catch {
    return false;
  }
}

function signal_process(child, detached, signal) {
  if (!child.pid) return;
  if (detached && process.platform !== 'win32') {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch {
      // Fall through to direct child signalling.
    }
  }
  try { if (process.platform === 'win32') child.kill(); else child.kill(signal); } catch {
    // The process may have exited between the state check and signal.
  }
}

/**
 * Run an explicitly declared read-only static provider.
 *
 * The child is started with an argument vector and shell:false. This function
 * bounds time and captured output. OS isolation is opt-in and fail-closed;
 * without isolation:'required', this remains process control rather than a sandbox.
 */
export async function run_static_provider(options) {
  const descriptors = plain_options(options);
  const manifest = validate_provider_manifest(descriptors.manifest?.value);
  if (manifest.execution.mode !== 'static' ||
      manifest.execution.executes_target || manifest.execution.writes_target ||
      manifest.execution.uses_network || manifest.execution.requires_authorization) {
    runner_error('ORIX_PROVIDER_EXECUTION_NOT_STATIC', 'Only providers declared as read-only static and non-network are accepted');
  }
  const executable_value = descriptors.executable?.value;
  const cwd_value = descriptors.cwd?.value ?? process.cwd();
  const executable = await validate_executable(
    executable_value,
    descriptors.allowed_executables?.value ?? [executable_value],
  );
  const executable_args = validate_arguments(descriptors.executable_args?.value ?? []);
  const args = validate_arguments(descriptors.args?.value ?? []);
  if (executable_args.length + args.length > MAX_ARGUMENTS ||
      executable_args.reduce((sum, item) => sum + Buffer.byteLength(item, 'utf8'), 0) +
      args.reduce((sum, item) => sum + Buffer.byteLength(item, 'utf8'), 0) > MAX_TOTAL_ARGUMENT_BYTES) {
    throw new TypeError('executable_args and args exceed the combined argument limits');
  }
  const cwd = await validate_working_directory(
    cwd_value,
    descriptors.allowed_working_directories?.value ?? [cwd_value],
  );
  const env = validate_environment(descriptors.env?.value);
  const limits = validate_runtime_limits(manifest, {
    timeout_ms: descriptors.timeout_ms?.value,
    max_output_bytes: descriptors.max_output_bytes?.value,
    kill_grace_ms: descriptors.kill_grace_ms?.value,
  });
  const isolation = descriptors.isolation?.value ?? 'none';
  if (isolation !== 'none' && isolation !== 'required') {
    throw new TypeError('isolation must be either none or required');
  }
  let launch_executable = executable;
  let launch_args = [...executable_args, ...args];
  let launch_cwd = cwd;
  let launch_env = minimal_environment(env);
  let launch_stdio = ['ignore', 'pipe', 'pipe'];
  let close_parent_fd = null;
  let isolation_cleanup = null;
  let isolation_cleanup_on_terminate = true;
  const signal = descriptors.signal?.value;
  if (signal !== undefined && !(signal instanceof AbortSignal)) {
    throw new TypeError('signal must be an AbortSignal');
  }
  if (isolation === 'required') {
    const prepared = await prepare_linux_provider_isolation({
      executable,
      cwd,
      sandbox_root: descriptors.sandbox_root?.value,
      args: launch_args,
      env,
    });
    launch_executable = prepared.executable;
    launch_args = prepared.args;
    launch_cwd = prepared.cwd;
    launch_env = prepared.env;
    launch_stdio = prepared.stdio ?? launch_stdio;
    close_parent_fd = prepared.close_parent_fd ?? null;
    isolation_cleanup = prepared.cleanup ?? null;
    isolation_cleanup_on_terminate = prepared.cleanup_on_terminate !== false;
  }
  if (signal?.aborted) {
    try { close_parent_fd?.(); } catch { /* cleanup below remains authoritative */ }
    if (isolation_cleanup) await isolation_cleanup();
    runner_error('ORIX_PROVIDER_CANCELLED', 'Provider process was cancelled before launch', {
      provider_id: manifest.id,
    });
  }

  const started_at = new Date().toISOString();
  const started_clock = performance.now();
  const windows = process.platform === 'win32';
  const detached = !windows;

  return await new Promise((resolve, reject) => {
    let child;
    let settled = false;
    let termination_started = false;
    let timed_out = false;
    let cancelled = false;
    let output_limited = false;
    let launch_setup_failed = false;
    let captured_bytes = 0;
    let stdout_bytes = 0;
    let stderr_bytes = 0;
    const stdout_chunks = [];
    const stderr_chunks = [];
    let timeout_timer = null;
    let kill_timer = null;
    let process_group_cleanup_timer = null;
    let process_group_cleanup_started = false;
    let process_group_cleanup_complete = windows;
    let process_group_cleanup_verified = windows ? null : false;
    let process_group_cleanup_failed = false;
    let process_group_force_kill_sent = false;
    let isolation_cleanup_complete = !isolation_cleanup;
    let isolation_cleanup_started = false;
    let isolation_cleanup_failed = false;
    let isolation_cleanup_error = null;
    let isolation_cleanup_report = null;
    let isolation_cleanup_promise = null;
    let close_result = null;

    function cleanup() {
      if (timeout_timer) clearTimeout(timeout_timer);
      if (kill_timer) clearTimeout(kill_timer);
      if (process_group_cleanup_timer) clearTimeout(process_group_cleanup_timer);
      if (signal) signal.removeEventListener('abort', on_abort);
    }

    function finish_close() {
      if (settled || close_result === null || !process_group_cleanup_complete || !isolation_cleanup_complete) return;
      settled = true;
      cleanup();
      const { exit_code, exit_signal } = close_result;
      const completed_at = new Date().toISOString();
      const termination_reason = isolation_cleanup_failed
        ? 'isolation-cleanup-failed'
        : process_group_cleanup_failed
          ? 'process-group-cleanup-failed'
          : launch_setup_failed ? 'launch-setup-failed'
            : timed_out ? 'timeout' : cancelled ? 'cancelled' : output_limited ? 'output-limit' : null;
      const success = exit_code === 0 && termination_reason === null;
      const stdout = Buffer.concat(stdout_chunks).toString('utf8');
      const stderr = Buffer.concat(stderr_chunks).toString('utf8');
      resolve({
        schema_version: 'orix.provider-execution.v1',
        provider: { id: manifest.id, version: manifest.version },
        executable,
        args_count: executable_args.length + args.length,
        started_at,
        completed_at,
        duration_ms: Math.max(0, performance.now() - started_clock),
        exit_code,
        signal: exit_signal,
        termination_reason,
        success,
        timed_out,
        cancelled,
        output_limited,
        launch_setup_failed,
        process_group_cleanup: {
          attempted: process_group_cleanup_started,
          force_kill_sent: process_group_force_kill_sent,
          verified_empty: process_group_cleanup_verified,
          failed: process_group_cleanup_failed,
        },
        isolation_cleanup: {
          attempted: isolation_cleanup_started,
          complete: isolation_cleanup_complete,
          failed: isolation_cleanup_failed,
          reason: isolation_cleanup_error?.code ?? null,
          report: isolation_cleanup_report,
        },
        ok: success,
        output: {
          stdout,
          stderr,
          stdout_bytes,
          stderr_bytes,
          bytes_observed: stdout_bytes + stderr_bytes,
          bytes_captured: captured_bytes,
          truncated: output_limited,
        },
        stdout,
        stderr,
        stdout_bytes,
        stderr_bytes,
        captured_bytes,
        output_truncated: output_limited,
        limits: {
          timeout_ms: limits.timeout_ms,
          max_output_bytes: limits.max_output_bytes,
          kill_grace_ms: limits.kill_grace_ms,
        },
      });
    }

    function start_isolation_cleanup(on_terminate) {
      if (!isolation_cleanup || (on_terminate && !isolation_cleanup_on_terminate)) {
        isolation_cleanup_complete = true;
        finish_close();
        return Promise.resolve();
      }
      if (isolation_cleanup_promise) return isolation_cleanup_promise;
      isolation_cleanup_started = true;
      isolation_cleanup_complete = false;
      isolation_cleanup_promise = Promise.resolve()
        .then(() => isolation_cleanup())
        .then(report => { isolation_cleanup_report = report ?? null; })
        .catch(error => {
          isolation_cleanup_failed = true;
          isolation_cleanup_error = error;
        })
        .finally(() => {
          isolation_cleanup_complete = true;
          finish_close();
        });
      return isolation_cleanup_promise;
    }

    function complete_process_group_cleanup() {
      // On cancellation/timeout, first stop the bootstrap process group so a
      // not-yet-attached bootstrap cannot join the cgroup after it was emptied.
      if (termination_started) start_isolation_cleanup(true);
      finish_close();
    }

    function start_process_group_cleanup() {
      if (process_group_cleanup_started || process_group_cleanup_complete) return;
      if (windows || !detached || !child?.pid) {
        process_group_cleanup_complete = true;
        complete_process_group_cleanup();
        return;
      }

      if (!process_group_exists(child.pid)) {
        process_group_cleanup_verified = true;
        process_group_cleanup_complete = true;
        complete_process_group_cleanup();
        return;
      }

      process_group_cleanup_started = true;
      signal_process_group(child.pid, 'SIGTERM');
      let phase = 'term';
      let deadline = performance.now() + limits.kill_grace_ms;

      function check_process_group() {
        if (!process_group_exists(child.pid)) {
          process_group_cleanup_verified = true;
          process_group_cleanup_complete = true;
          process_group_cleanup_timer = null;
          complete_process_group_cleanup();
          return;
        }
        if (performance.now() >= deadline) {
          if (phase === 'term') {
            // Escalate only while the original process-group id is still present.
            process_group_force_kill_sent = signal_process_group(child.pid, 'SIGKILL');
            phase = 'verify';
            deadline = performance.now() + 5_000;
          } else {
            // Do not report success when the kernel still reports the group alive.
            process_group_cleanup_failed = true;
            process_group_cleanup_complete = true;
            process_group_cleanup_timer = null;
            complete_process_group_cleanup();
            return;
          }
        }
        process_group_cleanup_timer = setTimeout(
          check_process_group,
          Math.min(20, Math.max(1, deadline - performance.now())),
        );
      }

      check_process_group();
    }

    function finish_error(error) {
      if (settled) return;
      settled = true;
      cleanup();
      Promise.resolve(start_isolation_cleanup(false)).then(() => {
        const final_error = isolation_cleanup_error ?? error;
        reject(new OrixError('ORIX_PROVIDER_SPAWN_FAILED', 'Provider process could not be started or cleaned up safely', {
          details: {
            provider_id: manifest.id,
            executable,
            reason: final_error?.code ?? final_error?.name ?? 'spawn-error',
          },
          cause: final_error,
          recoverable: true,
        }));
      });
    }

    function terminate() {
      if (termination_started || !child || settled) return;
      termination_started = true;
      if (windows) {
        signal_process(child, detached, 'SIGTERM');
        kill_timer = setTimeout(() => signal_process(child, detached, 'SIGKILL'), limits.kill_grace_ms);
        kill_timer.unref?.();
        start_isolation_cleanup(true);
        return;
      }
      // Prevent an un-attached bootstrap from joining after cgroup.kill has
      // observed an empty cgroup. The cgroup-wide kill follows group teardown.
      start_process_group_cleanup();
    }

    function on_abort() {
      cancelled = true;
      terminate();
    }

    function capture(stream, chunk) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (stream === 'stdout') stdout_bytes += buffer.length;
      else stderr_bytes += buffer.length;
      const remaining = limits.max_output_bytes - captured_bytes;
      if (remaining > 0) {
        const retained = buffer.subarray(0, remaining);
        if (retained.length > 0) {
          (stream === 'stdout' ? stdout_chunks : stderr_chunks).push(retained);
          captured_bytes += retained.length;
        }
      }
      if (buffer.length > remaining) {
        output_limited = true;
        terminate();
      }
    }

    if (signal) signal.addEventListener('abort', on_abort, { once: true });
    try {
      child = spawn(launch_executable, launch_args, {
        cwd: launch_cwd,
        env: launch_env,
        shell: false,
        windowsHide: true,
        detached,
        stdio: launch_stdio,
      });
    } catch (error) {
      try { close_parent_fd?.(); } catch { /* preserve the spawn error */ }
      close_parent_fd = null;
      finish_error(error);
      return;
    }

    // A parent-FD close failure happens after spawn has succeeded. Treat it as
    // a launch failure, but keep the child's exit/group listeners so teardown
    // stops a possibly not-yet-attached bootstrap before cgroup cleanup.
    let parent_fd_close_error = null;
    try { close_parent_fd?.(); }
    catch (error) { parent_fd_close_error = error; }
    close_parent_fd = null;

    child.stdout.on('data', chunk => capture('stdout', chunk));
    child.stderr.on('data', chunk => capture('stderr', chunk));
    child.once('error', finish_error);
    child.once('exit', () => {
      if (timeout_timer) clearTimeout(timeout_timer);
      timeout_timer = null;
      if (signal) signal.removeEventListener('abort', on_abort);
      if (!termination_started) {
        termination_started = true;
        // Normal completion is different: the bootstrap has exited, so no
        // process can still consume the one-shot attach capability.
        start_isolation_cleanup(false);
      }
      start_process_group_cleanup();
    });
    child.once('close', (exit_code, exit_signal) => {
      if (settled) return;
      close_result = { exit_code, exit_signal };
      finish_close();
    });

    if (!termination_started) timeout_timer = setTimeout(() => {
      timed_out = true;
      terminate();
    }, limits.timeout_ms);
    timeout_timer?.unref?.();
    if (parent_fd_close_error) {
      launch_setup_failed = true;
      terminate();
    }
    if (cancelled || signal?.aborted) on_abort();
  });
}
