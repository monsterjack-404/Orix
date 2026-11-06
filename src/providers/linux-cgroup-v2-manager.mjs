// JavaScript, src/providers/linux-cgroup-v2-manager.mjs, Linux-only delegated cgroup v2 lease manager.
import { constants as FS_CONSTANTS, closeSync, openSync } from 'node:fs';
import { open, lstat, mkdir, readFile, realpath, rmdir, stat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { OrixError } from '../core/errors.mjs';
import {
  assess_cgroup_directory_permissions,
  inspect_linux_cgroup_v2,
} from './linux-cgroup-v2-preflight.mjs';

const REQUIRED_CONTROLLERS = Object.freeze(['cpu', 'memory', 'pids']);
const REQUIRED_CONTROL_FILES = Object.freeze([
  'cgroup.controllers', 'cgroup.type', 'cgroup.procs', 'cgroup.events',
  'cgroup.kill', 'cpu.max', 'memory.max', 'pids.max',
]);
const DIRECTORY_FLAGS = FS_CONSTANTS.O_RDONLY |
  (FS_CONSTANTS.O_DIRECTORY ?? 0) |
  (FS_CONSTANTS.O_NOFOLLOW ?? 0);
const WRITE_FLAGS = FS_CONSTANTS.O_WRONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0);

function fail(code, message, details = {}, cause = undefined) {
  throw new OrixError(code, message, {
    recoverable: true,
    details: { ...details, ...(cause ? { reason: cause.code ?? cause.name ?? 'filesystem-error' } : {}) },
    ...(cause ? { cause } : {}),
  });
}

function plain_record(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function validate_linux_cgroup_v2_limits(value) {
  const keys = ['cpu_quota_us', 'cpu_period_us', 'memory_max_bytes', 'pids_max'];
  if (!plain_record(value)) {
    fail('ORIX_CGROUP_LIMITS_INVALID', 'Cgroup resource limits must be a plain object');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const own_keys = Reflect.ownKeys(descriptors);
  if (own_keys.length !== keys.length || own_keys.some(key => !keys.includes(key))) {
    fail('ORIX_CGROUP_LIMITS_INVALID', 'Cgroup limits must contain exactly cpu_quota_us, cpu_period_us, memory_max_bytes and pids_max');
  }
  const limits = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('ORIX_CGROUP_LIMITS_INVALID', 'Cgroup limit fields must be enumerable data properties', { field: key });
    }
    if (!Number.isSafeInteger(descriptor.value) || descriptor.value <= 0) {
      fail('ORIX_CGROUP_LIMITS_INVALID', 'Cgroup limit fields must be positive safe integers', { field: key });
    }
    limits[key] = descriptor.value;
  }
  if (limits.cpu_period_us < 1000 || limits.cpu_period_us > 1_000_000) {
    fail('ORIX_CGROUP_LIMITS_INVALID', 'cpu_period_us must be between 1000 and 1000000 microseconds');
  }
  return Object.freeze(limits);
}

export function serialize_linux_cgroup_v2_limits(value) {
  const limits = validate_linux_cgroup_v2_limits(value);
  return Object.freeze({
    'cpu.max': String(limits.cpu_quota_us) + ' ' + String(limits.cpu_period_us),
    'memory.max': String(limits.memory_max_bytes),
    'pids.max': String(limits.pids_max),
  });
}

export function parse_linux_cgroup_v2_populated(contents) {
  if (typeof contents !== 'string') {
    fail('ORIX_CGROUP_EVENTS_INVALID', 'cgroup.events contents must be text');
  }
  const records = contents.split('\n').map(line => line.trim()).filter(Boolean);
  const matches = records.filter(line => line.startsWith('populated '));
  if (matches.length !== 1 || !/^populated [01]$/.test(matches[0])) {
    fail('ORIX_CGROUP_EVENTS_INVALID', 'cgroup.events must contain exactly one populated value of 0 or 1');
  }
  return matches[0].endsWith(' 0') ? 0 : 1;
}

function single_component(value, label) {
  if (typeof value !== 'string' || value.length === 0 ||
      value === '.' || value === '..' || value.includes('/') ||
      value.includes('\\') || value.includes('\0')) {
    fail('ORIX_CGROUP_PATH_COMPONENT_INVALID', label + ' must be one safe path component');
  }
}

async function read_text(file_path) {
  return (await readFile(file_path, 'utf8')).trim();
}

async function verify_control_file(leaf_fd_path, name) {
  const file_path = path.join(leaf_fd_path, name);
  let info;
  try {
    info = await lstat(file_path);
  } catch (error) {
    fail('ORIX_CGROUP_CONTROL_FILE_MISSING', 'Required cgroup control file is unavailable', { file: name }, error);
  }
  if (info.isSymbolicLink() || !info.isFile()) {
    fail('ORIX_CGROUP_CONTROL_FILE_INVALID', 'Required cgroup control file must be a regular non-symlink file', { file: name });
  }
  return file_path;
}

async function write_control_value(leaf_fd_path, name, value) {
  const file_path = await verify_control_file(leaf_fd_path, name);
  const handle = await open(file_path, WRITE_FLAGS);
  try {
    const payload = Buffer.from(String(value) + '\n', 'ascii');
    const result = await handle.write(payload, 0, payload.length, null);
    if (result.bytesWritten !== payload.length) {
      fail('ORIX_CGROUP_CONTROL_SHORT_WRITE', 'A cgroup control write was incomplete', {
        file: name, expected_bytes: payload.length, written_bytes: result.bytesWritten,
      });
    }
  } finally {
    await handle.close();
  }
  if (name !== 'cgroup.kill') {
    const actual = await read_text(file_path);
    if (actual !== String(value)) {
      fail('ORIX_CGROUP_LIMIT_READBACK_MISMATCH', 'The cgroup kernel interface did not retain the requested value', {
        file: name, expected: String(value), actual,
      });
    }
  }
  if (test_adapter?.after_control_write) {
    await test_adapter.after_control_write({ leaf_fd_path, name, value: String(value) });
  }
}

function sleep(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

async function wait_for_empty(leaf_fd_path, timeout_ms) {
  const events_path = path.join(leaf_fd_path, 'cgroup.events');
  const deadline = Date.now() + timeout_ms;
  for (;;) {
    const populated = parse_linux_cgroup_v2_populated(await readFile(events_path, 'utf8'));
    if (populated === 0) return;
    if (Date.now() >= deadline) {
      fail('ORIX_CGROUP_CLEANUP_TIMEOUT', 'The provider cgroup did not reach populated 0 before the cleanup deadline', {
        timeout_ms,
      });
    }
    await sleep(Math.min(20, Math.max(1, deadline - Date.now())));
  }
}

/**
 * Creates one configured leaf beneath an administrator-delegated empty inner cgroup.
 * The optional adapter is test-only and emulates kernel-created control files on tmpfs.
 */
export async function create_linux_provider_cgroup(options = {}, test_adapter = null) {
  if (process.platform !== 'linux') {
    fail('ORIX_CGROUP_PLATFORM_UNSUPPORTED', 'Cgroup v2 provider resource isolation is Linux-only');
  }
  const parent_path = options.parent_path ?? process.env.ORIX_CGROUP_PARENT;
  if (typeof parent_path !== 'string' || !path.isAbsolute(parent_path) ||
      path.normalize(parent_path) !== parent_path || parent_path === path.parse(parent_path).root) {
    fail('ORIX_CGROUP_PARENT_INVALID', 'ORIX_CGROUP_PARENT must be a canonical absolute delegated cgroup path');
  }
  const limits = validate_linux_cgroup_v2_limits(options.limits);
  const serialized = serialize_linux_cgroup_v2_limits(limits);
  const cleanup_timeout_ms = options.cleanup_timeout_ms ?? 5_000;
  if (!Number.isSafeInteger(cleanup_timeout_ms) || cleanup_timeout_ms < 1 || cleanup_timeout_ms > 60_000) {
    fail('ORIX_CGROUP_CLEANUP_TIMEOUT_INVALID', 'Cgroup cleanup timeout must be between 1 and 60000 milliseconds');
  }

  const preflight = test_adapter?.preflight
    ? await test_adapter.preflight(parent_path)
    : await inspect_linux_cgroup_v2({
      parent_path,
      ...(test_adapter?.proc_root ? { proc_root: test_adapter.proc_root } : {}),
    });
  if (!preflight?.ready) {
    fail('ORIX_CGROUP_PARENT_NOT_READY', 'The delegated cgroup v2 parent did not pass read-only preflight', {
      reason: preflight?.reason ?? 'preflight-result-invalid',
    });
  }

  let parent_handle = null;
  let leaf_handle = null;
  let attach_fd = null;
  let attach_fd_closed = false;
  let leaf_created = false;
  let leaf_name = null;
  let leaf_path = null;
  let leaf_fd_path = null;
  let teardown_promise = null;

  function close_attach_fd() {
    if (attach_fd === null || attach_fd_closed) return;
    closeSync(attach_fd);
    attach_fd_closed = true;
  }

  async function close_directory_handles() {
    if (leaf_handle) {
      await leaf_handle.close().catch(() => {});
      leaf_handle = null;
    }
    if (parent_handle) {
      await parent_handle.close().catch(() => {});
      parent_handle = null;
    }
  }

  async function remove_empty_unlaunched_leaf() {
    if (!leaf_created || !leaf_path || !leaf_fd_path) return false;
    try {
      const populated = parse_linux_cgroup_v2_populated(
        await readFile(path.join(leaf_fd_path, 'cgroup.events'), 'utf8'),
      );
      const procs = await read_text(path.join(leaf_fd_path, 'cgroup.procs'));
      if (populated !== 0 || procs !== '') return false;
      close_attach_fd();
      await close_directory_handles();
      if (test_adapter?.remove_leaf) {
        await test_adapter.remove_leaf(leaf_path);
      } else {
        await rmdir(leaf_path);
      }
      leaf_created = false;
      return true;
    } catch {
      return false;
    }
  }

  try {
    const canonical_parent = await realpath(parent_path);
    if (canonical_parent !== parent_path) {
      fail('ORIX_CGROUP_PARENT_PATH_CHANGED', 'The delegated parent path changed after preflight');
    }

    parent_handle = await open(parent_path, DIRECTORY_FLAGS);
    const parent_info = await parent_handle.stat();
    const parent_permissions = assess_cgroup_directory_permissions(parent_info, process.geteuid());
    if (!parent_info.isDirectory() || !parent_permissions.owner_matches_process ||
        !parent_permissions.not_group_or_other_writable) {
      fail('ORIX_CGROUP_PARENT_TRUST_CHANGED', 'The delegated parent ownership or permissions changed after preflight');
    }

    const parent_fd_path = '/proc/self/fd/' + String(parent_handle.fd);
    const parent_descriptor_info = await stat(parent_fd_path);
    if (!parent_descriptor_info.isDirectory() ||
        parent_descriptor_info.dev !== parent_info.dev ||
        parent_descriptor_info.ino !== parent_info.ino) {
      fail('ORIX_CGROUP_DESCRIPTOR_PATH_UNAVAILABLE', 'The delegated parent directory descriptor could not be verified through procfs');
    }
    if (await read_text(path.join(parent_fd_path, 'cgroup.procs')) !== '') {
      fail('ORIX_CGROUP_PARENT_NOT_EMPTY', 'The delegated cgroup parent became populated after preflight');
    }

    leaf_name = 'provider-' + String(process.pid) + '-' + randomUUID();
    single_component(leaf_name, 'Generated cgroup name');
    leaf_path = path.join(parent_fd_path, leaf_name);
    await mkdir(leaf_path, { mode: 0o700 });
    leaf_created = true;

    if (test_adapter?.after_create_leaf) await test_adapter.after_create_leaf(leaf_path);

    leaf_handle = await open(leaf_path, DIRECTORY_FLAGS);
    const leaf_info = await leaf_handle.stat();
    const leaf_permissions = assess_cgroup_directory_permissions(leaf_info, process.geteuid());
    if (!leaf_info.isDirectory() || !leaf_permissions.owner_matches_process ||
        !leaf_permissions.not_group_or_other_writable) {
      fail('ORIX_CGROUP_LEAF_TRUST_INVALID', 'The created provider cgroup has unsafe ownership or permissions');
    }

    leaf_fd_path = '/proc/self/fd/' + String(leaf_handle.fd);
    const leaf_descriptor_info = await stat(leaf_fd_path);
    if (!leaf_descriptor_info.isDirectory() ||
        leaf_descriptor_info.dev !== leaf_info.dev ||
        leaf_descriptor_info.ino !== leaf_info.ino) {
      fail('ORIX_CGROUP_DESCRIPTOR_PATH_UNAVAILABLE', 'The provider cgroup descriptor could not be verified through procfs');
    }

    for (const name of REQUIRED_CONTROL_FILES) await verify_control_file(leaf_fd_path, name);
    if (await read_text(path.join(leaf_fd_path, 'cgroup.type')) !== 'domain') {
      fail('ORIX_CGROUP_LEAF_TYPE_INVALID', 'The provider cgroup must be a domain cgroup');
    }
    const available = (await read_text(path.join(leaf_fd_path, 'cgroup.controllers')))
      .split(/\s+/).filter(Boolean);
    if (!REQUIRED_CONTROLLERS.every(controller => available.includes(controller))) {
      fail('ORIX_CGROUP_LEAF_CONTROLLERS_MISSING', 'The new provider cgroup does not expose cpu, memory and pids controllers', {
        available,
      });
    }
    if (parse_linux_cgroup_v2_populated(await readFile(path.join(leaf_fd_path, 'cgroup.events'), 'utf8')) !== 0 ||
        await read_text(path.join(leaf_fd_path, 'cgroup.procs')) !== '') {
      fail('ORIX_CGROUP_LEAF_NOT_EMPTY', 'The provider cgroup must be empty before bootstrap attachment');
    }

    for (const [name, value] of Object.entries(serialized)) {
      await write_control_value(leaf_fd_path, name, value);
    }
    const procs_path = await verify_control_file(leaf_fd_path, 'cgroup.procs');
    attach_fd = openSync(procs_path, WRITE_FLAGS);

    async function teardown() {
      if (teardown_promise) return teardown_promise;
      const pending = (async () => {
        close_attach_fd();
        await write_control_value(leaf_fd_path, 'cgroup.kill', '1');
        await wait_for_empty(leaf_fd_path, cleanup_timeout_ms);
        if (leaf_handle) {
          await leaf_handle.close();
          leaf_handle = null;
        }
        if (test_adapter?.remove_leaf) {
          await test_adapter.remove_leaf(leaf_path);
        } else {
          await rmdir(leaf_path);
        }
        leaf_created = false;
        await close_directory_handles();
        return Object.freeze({ removed: true, leaf_name });
      })();
      teardown_promise = pending.catch(error => {
        teardown_promise = null;
        throw error;
      });
      return teardown_promise;
    }

    return Object.freeze({
      leaf_name,
      limits,
      get attach_fd() {
        if (attach_fd === null || attach_fd_closed) {
          fail('ORIX_CGROUP_ATTACH_DESCRIPTOR_CLOSED', 'The bootstrap attach descriptor is already closed');
        }
        return attach_fd;
      },
      close_attach_fd,
      teardown,
    });
  } catch (error) {
    close_attach_fd();
    const removed = await remove_empty_unlaunched_leaf();
    await close_directory_handles();
    if (error instanceof OrixError) {
      if (!removed && leaf_created) {
        fail('ORIX_CGROUP_SETUP_CLEANUP_FAILED', 'Cgroup setup failed and its empty leaf could not be safely removed', {
          leaf_name, original_code: error.code,
        }, error);
      }
      throw error;
    }
    fail('ORIX_CGROUP_SETUP_FAILED', 'The provider cgroup could not be created and configured', {
      leaf_name, removed_empty_leaf: removed,
    }, error);
  }
}
