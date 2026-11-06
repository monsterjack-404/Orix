// Linux cgroup v2 deployment preflight. Read-only: this module never mutates cgroups.
import { constants as FS_CONSTANTS } from 'node:fs';
import { access, lstat, readFile } from 'node:fs/promises';
import path from 'node:path';

const REQUIRED_CONTROLLERS = Object.freeze(['cpu', 'memory', 'pids']);

function canonical_posix_absolute(value) {
  return typeof value === 'string' && value.length > 0 &&
    !value.includes('\0') && path.posix.isAbsolute(value) &&
    (value === '/' || !value.endsWith('/')) &&
    path.posix.normalize(value) === value;
}

function decode_mount_field(value) {
  return value.replace(/\\([0-7]{3})/g, (_match, octal) => String.fromCharCode(Number.parseInt(octal, 8)));
}

export function parse_cgroup2_mounts(mountinfo) {
  if (typeof mountinfo !== 'string') throw new TypeError('mountinfo must be a string');
  const mounts = [];
  for (const line of mountinfo.split('\n')) {
    if (!line) continue;
    const separator = line.indexOf(' - ');
    if (separator < 0) continue;
    const left = line.slice(0, separator).split(' ');
    const right = line.slice(separator + 3).split(' ');
    if (right[0] !== 'cgroup2' || left.length < 6 || right.length < 3) continue;
    const root = decode_mount_field(left[3]);
    const mountpoint = decode_mount_field(left[4]);
    if (!canonical_posix_absolute(root) || !canonical_posix_absolute(mountpoint)) continue;
    mounts.push(Object.freeze({ root, mountpoint }));
  }
  return mounts;
}

export function parse_process_cgroup_path(contents) {
  if (typeof contents !== 'string') throw new TypeError('cgroup contents must be a string');
  for (const line of contents.split('\n')) {
    const match = line.match(/^0::(\/.*)$/);
    if (match) return canonical_posix_absolute(match[1]) ? match[1] : null;
  }
  return null;
}

export function map_cgroup_path_to_mount(cgroup_path, mounts) {
  if (!canonical_posix_absolute(cgroup_path) || !Array.isArray(mounts)) return null;
  const candidates = mounts
    .filter(mount => mount && canonical_posix_absolute(mount.root) &&
      canonical_posix_absolute(mount.mountpoint) &&
      (cgroup_path === mount.root || cgroup_path.startsWith(mount.root === '/' ? '/' : mount.root + '/')))
    .sort((a, b) => b.root.length - a.root.length);
  if (candidates.length === 0) return null;
  const mount = candidates[0];
  const suffix = mount.root === '/' ? cgroup_path.slice(1) : cgroup_path.slice(mount.root.length).replace(/^\//, '');
  return path.posix.resolve(mount.mountpoint, suffix);
}

async function read_text(file) {
  return (await readFile(file, 'utf8')).trim();
}

async function no_symlink_components(target, boundary) {
  const relative = path.relative(boundary, target);
  if (relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) return false;
  let current = boundary;
  const boundaryInfo = await lstat(current);
  if (boundaryInfo.isSymbolicLink() || !boundaryInfo.isDirectory()) return false;
  for (const component of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    const details = await lstat(current);
    if (details.isSymbolicLink() || !details.isDirectory()) return false;
  }
  return true;
}

/**
 * Read-only deployment diagnostic. It does not create directories, move tasks,
 * write controller files, or claim kernel enforcement.
 */
export async function inspect_linux_cgroup_v2(options = {}) {
  if (process.platform !== 'linux') {
    return Object.freeze({ supported: false, ready: false, reason: 'linux-only' });
  }
  const proc_root = options.proc_root ?? '/proc';
  const configured_parent = options.parent_path ?? process.env.ORIX_CGROUP_PARENT ?? null;
  const mountinfo = await read_text(path.join(proc_root, 'self/mountinfo'));
  const process_cgroup = await read_text(path.join(proc_root, 'self/cgroup'));
  const mounts = parse_cgroup2_mounts(mountinfo);
  const process_cgroup_path = parse_process_cgroup_path(process_cgroup);
  const current_directory = process_cgroup_path ? map_cgroup_path_to_mount(process_cgroup_path, mounts) : null;
  const report = {
    supported: true,
    ready: false,
    cgroup2_mounts: mounts,
    process_cgroup_path,
    current_directory,
    configured_parent: configured_parent || null,
    parent: null,
    reason: null,
  };
  if (mounts.length === 0 || !current_directory) {
    report.reason = 'cgroup-v2-mount-or-process-membership-not-found';
    return Object.freeze(report);
  }
  if (typeof configured_parent !== 'string' || !path.isAbsolute(configured_parent) ||
      path.normalize(configured_parent) !== configured_parent) {
    report.reason = 'ORIX_CGROUP_PARENT-not-configured-as-an-absolute-path';
    return Object.freeze(report);
  }
  const mount = mounts
    .filter(item => configured_parent === item.mountpoint ||
      configured_parent.startsWith(item.mountpoint.replace(/\/$/, '') + '/'))
    .sort((a, b) => b.mountpoint.length - a.mountpoint.length)[0];
  if (!mount) {
    report.reason = 'configured-parent-is-outside-cgroup2-mount';
    return Object.freeze(report);
  }
  const relative = path.relative(mount.mountpoint, configured_parent).split(path.sep).join('/');
  const parent_cgroup_path = path.posix.resolve(mount.root, relative);
  if (configured_parent === mount.mountpoint || parent_cgroup_path === '/') {
    report.reason = 'configured-parent-must-not-be-cgroup2-mount-root';
    return Object.freeze(report);
  }
  const supervisor_path = path.join(configured_parent, 'supervisor');
  const parent = {
    path: configured_parent,
    cgroup_path: parent_cgroup_path,
    no_symlink_components: false,
    empty: false,
    controllers: [],
    enabled_controllers: [],
    required_controllers_available: false,
    required_controllers_enabled: false,
    domain_type: false,
    supervisor_exists: false,
    supervisor_contains_current_process: false,
    writable: false,
    cgroup_kill_available: false,
  };
  report.parent = parent;
  try {
    parent.no_symlink_components = await no_symlink_components(configured_parent, mount.mountpoint);
    if (!parent.no_symlink_components) {
      report.reason = 'configured-parent-has-symlink-or-unsafe-path-component';
      return Object.freeze(report);
    }
    const [controllers, enabled, procs, type] = await Promise.all([
      read_text(path.join(configured_parent, 'cgroup.controllers')),
      read_text(path.join(configured_parent, 'cgroup.subtree_control')),
      read_text(path.join(configured_parent, 'cgroup.procs')),
      read_text(path.join(configured_parent, 'cgroup.type')),
    ]);
    parent.controllers = controllers.split(/\s+/).filter(Boolean);
    parent.enabled_controllers = enabled.split(/\s+/).filter(Boolean).map(item => item.replace(/^\+/, ''));
    parent.empty = procs.length === 0;
    parent.required_controllers_available = REQUIRED_CONTROLLERS.every(item => parent.controllers.includes(item));
    parent.required_controllers_enabled = REQUIRED_CONTROLLERS.every(item => parent.enabled_controllers.includes(item));
    parent.domain_type = type === 'domain';
    const supervisor_info = await lstat(supervisor_path);
    parent.supervisor_exists = !supervisor_info.isSymbolicLink() && supervisor_info.isDirectory();
    parent.supervisor_contains_current_process = process_cgroup_path === parent_cgroup_path + '/supervisor' ||
      process_cgroup_path.startsWith(parent_cgroup_path + '/supervisor/');
    parent.writable = await access(configured_parent, FS_CONSTANTS.W_OK | FS_CONSTANTS.X_OK).then(() => true, () => false);
    parent.cgroup_kill_available = await access(path.join(configured_parent, 'cgroup.kill')).then(() => true, () => false);
  } catch (error) {
    report.reason = 'delegated-parent-inspection-failed:' + (error.code ?? error.name ?? 'unknown');
    return Object.freeze(report);
  }
  parent.ready = parent.no_symlink_components && parent.empty &&
    parent.required_controllers_available && parent.required_controllers_enabled &&
    parent.domain_type && parent.supervisor_exists && parent.supervisor_contains_current_process &&
    parent.writable && parent.cgroup_kill_available;
  report.ready = parent.ready;
  report.reason = parent.ready ? null : 'delegated-parent-does-not-meet-required-layout-and-controller-contract';
  return Object.freeze(report);
}
