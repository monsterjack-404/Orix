// Linux cgroup v2 run manager. All mutable cgroup operations are anchored to retained directory FDs.
import {
  closeSync,
  constants as FS,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  rmdirSync,
  statfsSync,
  writeSync,
} from 'node:fs';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { OrixError } from '../core/errors.mjs';
import { inspect_linux_cgroup_v2 } from './linux-cgroup-v2-preflight.mjs';

const CGROUP2_SUPER_MAGIC = 0x63677270;
const REQUIRED_CONTROLLERS = ['cpu', 'memory', 'pids'];
export const LINUX_PROVIDER_CGROUP_LIMITS = Object.freeze({
  'cpu.max': '50000 100000',
  'memory.max': '536870912',
  'memory.swap.max': '0',
  'memory.oom.group': '1',
  'pids.max': '64',
});
const DIRECTORY_FLAGS = FS.O_RDONLY | FS.O_DIRECTORY | FS.O_NOFOLLOW | (FS.O_CLOEXEC ?? 0);
const READ_FLAGS = FS.O_RDONLY | FS.O_NOFOLLOW | (FS.O_CLOEXEC ?? 0);
const WRITE_FLAGS = FS.O_WRONLY | FS.O_NOFOLLOW | (FS.O_CLOEXEC ?? 0);

export function parse_cgroup_process_ids(contents) {
  if (typeof contents !== 'string') {
    throw new TypeError('cgroup process list must be a string');
  }
  const process_ids = contents.split(/\s+/).filter(Boolean);
  if (process_ids.some(value => !/^[1-9]\d*$/.test(value))) {
    throw new TypeError('cgroup process list contains an invalid process ID');
  }
  return process_ids;
}

function cgroup_error(code, message, details = {}, cause) {
  throw new OrixError(code, message, { details, cause, recoverable: true });
}

function fd_path(fd, child = '') {
  return child ? '/proc/self/fd/' + fd + '/' + child : '/proc/self/fd/' + fd;
}

function valid_component(value) {
  return typeof value === 'string' && value.length > 0 &&
    value !== '.' && value !== '..' && !value.includes('/') &&
    !value.includes('\\') && !value.includes('\0');
}

function open_directory_at(parent_fd, component) {
  if (!valid_component(component)) {
    cgroup_error('ORIX_CGROUP_PATH_COMPONENT_INVALID', 'Cgroup path traversal requires a single safe path component');
  }
  let fd;
  try {
    fd = openSync(fd_path(parent_fd, component), DIRECTORY_FLAGS);
    if (!fstatSync(fd).isDirectory()) cgroup_error('ORIX_CGROUP_DIRECTORY_INVALID', 'A cgroup path component is not a directory');
    return fd;
  } catch (error) {
    if (error instanceof OrixError) throw error;
    cgroup_error('ORIX_CGROUP_DIRECTORY_OPEN_FAILED', 'Could not open a cgroup directory through its retained parent descriptor', {
      component, reason: error.code ?? error.name ?? 'open-failed',
    }, error);
  }
}

function open_absolute_directory(value) {
  if (typeof value !== 'string' || !path.posix.isAbsolute(value) ||
      path.posix.normalize(value) !== value || value.includes('\0')) {
    cgroup_error('ORIX_CGROUP_PATH_INVALID', 'Cgroup mountpoint must be a canonical absolute path');
  }
  let current;
  try { current = openSync('/', DIRECTORY_FLAGS); }
  catch (error) {
    cgroup_error('ORIX_CGROUP_MOUNT_OPEN_FAILED', 'Could not open the filesystem root for descriptor-anchored cgroup traversal', {
      reason: error.code ?? error.name ?? 'open-failed',
    }, error);
  }
  try {
    for (const component of value.split('/').filter(Boolean)) {
      const next = open_directory_at(current, component);
      closeSync(current);
      current = next;
    }
    return current;
  } catch (error) {
    try { closeSync(current); } catch { /* preserve the original failure */ }
    throw error;
  }
}

function read_control(directory_fd, name) {
  if (!valid_component(name)) cgroup_error('ORIX_CGROUP_CONTROL_INVALID', 'Invalid cgroup control filename');
  let fd;
  try {
    fd = openSync(fd_path(directory_fd, name), READ_FLAGS);
    return readFileSync(fd, 'utf8').trim();
  } catch (error) {
    if (error instanceof OrixError) throw error;
    cgroup_error('ORIX_CGROUP_CONTROL_READ_FAILED', 'Could not read cgroup control: ' + name, {
      reason: error.code ?? error.name ?? 'read-failed',
    }, error);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* close best-effort */ }
  }
}

function write_control(directory_fd, name, value) {
  if (!valid_component(name) || typeof value !== 'string' || value.includes('\0')) {
    cgroup_error('ORIX_CGROUP_CONTROL_INVALID', 'Invalid cgroup control write');
  }
  let fd;
  try {
    fd = openSync(fd_path(directory_fd, name), WRITE_FLAGS);
    const bytes = Buffer.from(value + '\n', 'ascii');
    const written = writeSync(fd, bytes, 0, bytes.length);
    if (written !== bytes.length) {
      cgroup_error('ORIX_CGROUP_CONTROL_SHORT_WRITE', 'Cgroup control write was incomplete: ' + name);
    }
  } catch (error) {
    if (error instanceof OrixError) throw error;
    cgroup_error('ORIX_CGROUP_CONTROL_WRITE_FAILED', 'Could not write cgroup control: ' + name, {
      reason: error.code ?? error.name ?? 'write-failed',
    }, error);
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* close best-effort */ }
  }
}

function assert_service_owned_directory(fd, label) {
  const info = fstatSync(fd);
  const expected_uid = process.geteuid();
  if (!info.isDirectory() || info.uid !== expected_uid || (info.mode & 0o022) !== 0) {
    cgroup_error('ORIX_CGROUP_DIRECTORY_UNTRUSTED',
      label + ' must be a directory owned by the ORIX service UID and not group/other writable', {
        owner_uid: info.uid, expected_uid, mode: info.mode & 0o7777,
      });
  }
}

function assert_cgroup2_filesystem(fd) {
  let info;
  try { info = statfsSync(fd_path(fd)); }
  catch (error) {
    cgroup_error('ORIX_CGROUP_FILESYSTEM_UNVERIFIED', 'Could not verify the delegated parent filesystem type', {
      reason: error.code ?? error.name ?? 'statfs-failed',
    }, error);
  }
  if (info.type !== CGROUP2_SUPER_MAGIC) {
    cgroup_error('ORIX_CGROUP_FILESYSTEM_INVALID', 'Delegated parent is not on a cgroup v2 filesystem', {
      filesystem_magic: info.type,
    });
  }
}

function open_attach_descriptor(child_fd) {
  try { return openSync(fd_path(child_fd, 'cgroup.procs'), WRITE_FLAGS); }
  catch (error) {
    cgroup_error('ORIX_CGROUP_ATTACH_DESCRIPTOR_FAILED', 'Could not open the leaf cgroup.procs write-only attach capability', {
      reason: error.code ?? error.name ?? 'open-failed',
    }, error);
  }
}

/**
 * Create one aggregate-limited provider cgroup beneath the administrator's
 * delegated parent. The caller receives only a write-only cgroup.procs FD.
 */
export async function prepare_linux_provider_cgroup(parent_path = process.env.ORIX_CGROUP_PARENT) {
  if (process.platform !== 'linux') {
    cgroup_error('ORIX_CGROUP_PLATFORM_UNSUPPORTED', 'cgroup v2 provider limits are Linux-only');
  }
  if (typeof parent_path !== 'string' || !path.posix.isAbsolute(parent_path)) {
    cgroup_error('ORIX_CGROUP_PARENT_REQUIRED', 'Required Linux isolation needs administrator-configured ORIX_CGROUP_PARENT');
  }

  const preflight = await inspect_linux_cgroup_v2({ parent_path });
  if (!preflight.ready) {
    cgroup_error('ORIX_CGROUP_PREFLIGHT_FAILED', 'Administrator-delegated cgroup v2 parent did not pass read-only preflight', {
      reason: preflight.reason,
      parent: preflight.parent,
    });
  }

  const mount = preflight.cgroup2_mounts
    .filter(item => parent_path === item.mountpoint ||
      parent_path.startsWith(item.mountpoint.replace(/\/$/, '') + '/'))
    .sort((left, right) => right.mountpoint.length - left.mountpoint.length)[0];
  if (!mount) {
    cgroup_error('ORIX_CGROUP_MOUNT_NOT_FOUND', 'Could not map the delegated parent to its cgroup v2 mount');
  }
  const relative = path.posix.relative(mount.mountpoint, parent_path);
  if (!relative || relative === '..' || relative.startsWith('../') || path.posix.isAbsolute(relative)) {
    cgroup_error('ORIX_CGROUP_PARENT_INVALID', 'Delegated parent must be a child of the cgroup v2 mount root');
  }

  let mount_fd;
  let parent_fd;
  let supervisor_fd;
  let child_fd;
  let attach_fd;
  let child_name = null;
  let child_created = false;
  try {
    mount_fd = open_absolute_directory(mount.mountpoint);
    assert_cgroup2_filesystem(mount_fd);
    parent_fd = mount_fd;
    mount_fd = undefined;
    for (const component of relative.split('/')) {
      const next = open_directory_at(parent_fd, component);
      closeSync(parent_fd);
      parent_fd = next;
    }
    assert_cgroup2_filesystem(parent_fd);
    assert_service_owned_directory(parent_fd, 'Delegated cgroup parent');

    if (read_control(parent_fd, 'cgroup.type') !== 'domain') {
      cgroup_error('ORIX_CGROUP_PARENT_TYPE_INVALID', 'Delegated parent must be a domain cgroup');
    }
    if (read_control(parent_fd, 'cgroup.procs') !== '') {
      cgroup_error('ORIX_CGROUP_PARENT_BUSY', 'Delegated parent must not contain processes directly');
    }
    const available = read_control(parent_fd, 'cgroup.controllers').split(/\s+/).filter(Boolean);
    const enabled = read_control(parent_fd, 'cgroup.subtree_control').split(/\s+/).filter(Boolean).map(value => value.replace(/^\+/, ''));
    const missing = REQUIRED_CONTROLLERS.filter(name => !available.includes(name) || !enabled.includes(name));
    if (missing.length) {
      cgroup_error('ORIX_CGROUP_CONTROLLERS_UNAVAILABLE', 'Delegated parent must expose and enable cpu, memory and pids controllers', {
        missing_controllers: missing,
      });
    }

    supervisor_fd = open_directory_at(parent_fd, 'supervisor');
    assert_cgroup2_filesystem(supervisor_fd);
    assert_service_owned_directory(supervisor_fd, 'Delegated supervisor child');
    const supervisor_processes = parse_cgroup_process_ids(read_control(supervisor_fd, 'cgroup.procs'));
    if (!supervisor_processes.includes(String(process.pid))) {
      cgroup_error('ORIX_CGROUP_SUPERVISOR_MEMBERSHIP_INVALID',
        'The current ORIX manager process must remain in the delegated supervisor sibling');
    }

    child_name = 'orix-provider-' + randomUUID();
    mkdirSync(fd_path(parent_fd, child_name), { mode: 0o700 });
    child_created = true;
    child_fd = open_directory_at(parent_fd, child_name);
    assert_cgroup2_filesystem(child_fd);

    for (const [name, value] of Object.entries(LINUX_PROVIDER_CGROUP_LIMITS)) write_control(child_fd, name, value);
    for (const [name, expected] of Object.entries(LINUX_PROVIDER_CGROUP_LIMITS)) {
      const actual = read_control(child_fd, name);
      if (actual !== expected) {
        cgroup_error('ORIX_CGROUP_LIMIT_MISMATCH', 'Kernel did not retain the requested provider cgroup limit: ' + name, {
          expected, actual,
        });
      }
    }

    if (!/^populated 0$/m.test(read_control(child_fd, 'cgroup.events'))) {
      cgroup_error('ORIX_CGROUP_CHILD_INITIAL_STATE_INVALID', 'New provider cgroup must start unpopulated');
    }
    let kill_probe_fd;
    try {
      kill_probe_fd = openSync(fd_path(child_fd, 'cgroup.kill'), WRITE_FLAGS);
    } catch (error) {
      cgroup_error('ORIX_CGROUP_KILL_UNAVAILABLE', 'New provider cgroup does not expose a writable cgroup.kill control', {
        reason: error.code ?? error.name ?? 'open-failed',
      }, error);
    } finally {
      if (kill_probe_fd !== undefined) try { closeSync(kill_probe_fd); } catch { /* no provider launched yet */ }
    }
    attach_fd = open_attach_descriptor(child_fd);
    // Re-check the descriptor-anchored supervisor membership after child setup,
    // not only during the earlier path-based deployment preflight.
    const supervisor_processes_after_setup = parse_cgroup_process_ids(read_control(supervisor_fd, 'cgroup.procs'));
    if (!supervisor_processes_after_setup.includes(String(process.pid))) {
      cgroup_error('ORIX_CGROUP_SUPERVISOR_MEMBERSHIP_INVALID',
        'The ORIX manager moved out of the delegated supervisor during cgroup setup');
    }
    closeSync(supervisor_fd);
    supervisor_fd = undefined;
    const attach_fd_value = attach_fd;
    let attach_open = true;
    let cleanup_promise = null;
    const cleanup_report = {
      memory_events: null,
      cpu_stat: null,
      pids_events: null,
      limits: LINUX_PROVIDER_CGROUP_LIMITS,
    };
    const close_attach_fd = () => {
      if (!attach_open) return;
      closeSync(attach_fd_value);
      attach_open = false;
    };
    const cleanup = () => {
      if (cleanup_promise) return cleanup_promise;
      cleanup_promise = (async () => {
        const deadline = Date.now() + 5000;
        try {
          close_attach_fd();
          write_control(child_fd, 'cgroup.kill', '1');
          while (Date.now() < deadline) {
            const events = read_control(child_fd, 'cgroup.events');
            if (/^populated 0$/m.test(events)) {
              cleanup_report.memory_events = read_control(child_fd, 'memory.events');
              cleanup_report.cpu_stat = read_control(child_fd, 'cpu.stat');
              cleanup_report.pids_events = read_control(child_fd, 'pids.events');
              closeSync(child_fd);
              child_fd = undefined;
              rmdirSync(fd_path(parent_fd, child_name));
              child_created = false;
              closeSync(parent_fd);
              parent_fd = undefined;
              return Object.freeze({
                memory_events: cleanup_report.memory_events,
                cpu_stat: cleanup_report.cpu_stat,
                pids_events: cleanup_report.pids_events,
                limits: cleanup_report.limits,
                removed: true,
              });
            }
            await new Promise(resolve => setTimeout(resolve, 25));
          }
          cgroup_error('ORIX_CGROUP_CLEANUP_TIMEOUT',
            'Provider cgroup remained populated after the kernel kill request', { cgroup: parent_path + '/' + child_name });
        } catch (error) {
          throw error;
        } finally {
          if (attach_open) {
            try { close_attach_fd(); } catch { /* preserve cleanup failure */ }
          }
          if (child_fd !== undefined) {
            try { closeSync(child_fd); } catch { /* preserve cleanup failure */ }
            child_fd = undefined;
          }
          if (parent_fd !== undefined) {
            try { closeSync(parent_fd); } catch { /* preserve cleanup failure */ }
            parent_fd = undefined;
          }
        }
      })();
      return cleanup_promise;
    };

    return Object.freeze({
      path: parent_path + '/' + child_name,
      attach_fd: attach_fd_value,
      stdio: Object.freeze(['ignore', 'pipe', 'pipe', attach_fd_value]),
      close_attach_fd,
      cleanup,
    });
  } catch (error) {
    if (attach_fd !== undefined) try { closeSync(attach_fd); } catch { /* preserve setup failure */ }
    if (supervisor_fd !== undefined) try { closeSync(supervisor_fd); } catch { /* preserve setup failure */ }
    if (child_fd !== undefined) try { closeSync(child_fd); } catch { /* preserve setup failure */ }
    if (child_created && parent_fd !== undefined && child_name !== null) {
      try { rmdirSync(fd_path(parent_fd, child_name)); } catch { /* retain setup error; never remove a populated cgroup */ }
    }
    if (parent_fd !== undefined) try { closeSync(parent_fd); } catch { /* preserve setup failure */ }
    if (mount_fd !== undefined) try { closeSync(mount_fd); } catch { /* preserve setup failure */ }
    if (error instanceof OrixError) throw error;
    cgroup_error('ORIX_CGROUP_SETUP_FAILED', 'Could not prepare the delegated provider cgroup', {
      reason: error.code ?? error.name ?? 'setup-failed',
    }, error);
  }
}
