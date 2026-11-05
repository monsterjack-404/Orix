// Linux provider isolation: Bubblewrap namespaces plus delegated cgroup-v2 quotas.
import { access, lstat, mkdir, readFile, realpath, rmdir, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { OrixError } from '../core/errors.mjs';

const REQUIRED_CONTROLLERS = ['cpu', 'memory', 'pids'];
const RESOURCE_LIMITS = Object.freeze({
  memory_max: '536870912',
  memory_swap_max: '0',
  memory_oom_group: '1',
  pids_max: '64',
  cpu_max: '50000 100000',
});

function isolation_error(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' &&
    !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

async function resolve_trusted_executable(candidates, label) {
  for (const candidate of candidates) {
    try {
      const info = await lstat(candidate);
      if (info.isSymbolicLink() || !info.isFile()) continue;
      const canonical = await realpath(candidate);
      await access(canonical, 1);
      return canonical;
    } catch {
      // Only fixed system paths are considered; never resolve through PATH.
    }
  }
  isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE',
    label + ' is not installed at a trusted system path; required isolation cannot start',
    { platform: process.platform, backend: label });
}

async function resolve_bwrap() {
  return resolve_trusted_executable(['/usr/bin/bwrap', '/bin/bwrap'], 'bubblewrap');
}

async function resolve_prlimit() {
  return resolve_trusted_executable(['/usr/bin/prlimit', '/bin/prlimit'], 'prlimit');
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

async function read_control(directory, name) {
  try { return (await readFile(path.join(directory, name), 'utf8')).trim().split(/\s+/); }
  catch (error) {
    isolation_error('ORIX_PROVIDER_CGROUP_UNAVAILABLE', 'Required cgroup-v2 control is unavailable: ' + name, {
      reason: error.code ?? 'read-failed',
    });
  }
}

async function prepare_provider_cgroup(parentValue) {
  if (typeof parentValue !== 'string' || !path.isAbsolute(parentValue) || parentValue.includes('\0')) {
    isolation_error('ORIX_PROVIDER_CGROUP_REQUIRED', 'Required isolation needs an explicit delegated cgroup-v2 parent directory');
  }
  let info;
  try { info = await lstat(parentValue); }
  catch (error) {
    isolation_error('ORIX_PROVIDER_CGROUP_UNAVAILABLE', 'Delegated cgroup parent cannot be inspected', {
      reason: error.code ?? 'filesystem-error',
    });
  }
  if (info.isSymbolicLink() || !info.isDirectory()) {
    isolation_error('ORIX_PROVIDER_CGROUP_INVALID', 'Delegated cgroup parent must be a real non-symlink directory');
  }
  const parent = await realpath(parentValue);
  const mountInfo = await readFile('/proc/self/mountinfo', 'utf8');
  const cgroupMountPoints = mountInfo.split('\n')
    .filter(line => line.split(' - ')[1]?.split(' ')[0] === 'cgroup2')
    .map(line => {
      const fields = line.split(' - ')[0].split(' ');
      const mountPoint = fields[4]?.replace(/\\([0-7]{3})/g, (_, octal) => String.fromCharCode(Number.parseInt(octal, 8)));
      return mountPoint ? path.resolve(mountPoint) : null;
    })
    .filter(Boolean);
  const containingMount = cgroupMountPoints
    .filter(mountPoint => within(mountPoint, parent))
    .sort((left, right) => right.length - left.length)[0];
  if (!containingMount) {
    isolation_error('ORIX_PROVIDER_CGROUP_NOT_CGROUP2',
      'The delegated parent is not located on a mounted cgroup-v2 filesystem', { parent });
  }
  if (containingMount === parent) {
    isolation_error('ORIX_PROVIDER_CGROUP_INVALID',
      'The cgroup-v2 mount root is not an acceptable delegated parent; use a dedicated delegated subdirectory');
  }
  const type = await read_control(parent, 'cgroup.type');
  if (type[0] !== 'domain') {
    isolation_error('ORIX_PROVIDER_CGROUP_INVALID', 'Delegated cgroup parent must be a domain cgroup', { type: type.join(' ') });
  }
  const parentEvents = (await readFile(path.join(parent, 'cgroup.events'), 'utf8')).trim();
  const parentProcesses = (await readFile(path.join(parent, 'cgroup.procs'), 'utf8')).trim();
  if (!/^populated 0$/m.test(parentEvents) || parentProcesses !== '') {
    isolation_error('ORIX_PROVIDER_CGROUP_PARENT_BUSY',
      'Delegated cgroup parent must be empty before ORIX creates a child cgroup', {
        populated: !/^populated 0$/m.test(parentEvents),
        has_processes: parentProcesses !== '',
      });
  }
  const controllers = await read_control(parent, 'cgroup.controllers');
  const enabled = await read_control(parent, 'cgroup.subtree_control');
  const missing = REQUIRED_CONTROLLERS.filter(item => !controllers.includes(item) || !enabled.includes(item));
  if (missing.length) {
    isolation_error('ORIX_PROVIDER_CGROUP_CONTROLLERS_UNAVAILABLE',
      'Delegated cgroup-v2 parent must have cpu, memory and pids controllers available and enabled',
      { missing_controllers: missing });
  }
  for (const required of ['cgroup.procs', 'cgroup.events', 'cgroup.kill']) {
    try { await access(path.join(parent, required)); }
    catch {
      isolation_error('ORIX_PROVIDER_CGROUP_UNAVAILABLE', 'Required cgroup-v2 control is unavailable: ' + required);
    }
  }

  const child = path.join(parent, 'orix-provider-' + randomUUID());
  try {
    await mkdir(child, { mode: 0o700 });
    await writeFile(path.join(child, 'memory.max'), RESOURCE_LIMITS.memory_max);
    await writeFile(path.join(child, 'memory.swap.max'), RESOURCE_LIMITS.memory_swap_max);
    await writeFile(path.join(child, 'memory.oom.group'), RESOURCE_LIMITS.memory_oom_group);
    await writeFile(path.join(child, 'pids.max'), RESOURCE_LIMITS.pids_max);
    await writeFile(path.join(child, 'cpu.max'), RESOURCE_LIMITS.cpu_max);
    for (const name of ['memory.max', 'memory.swap.max', 'memory.oom.group', 'pids.max', 'cpu.max']) {
      const value = (await readFile(path.join(child, name), 'utf8')).trim();
      if (value !== RESOURCE_LIMITS[name.replaceAll('.', '_')]) {
        isolation_error('ORIX_PROVIDER_CGROUP_LIMIT_MISMATCH', 'Kernel did not retain requested cgroup-v2 limit: ' + name, {
          expected: RESOURCE_LIMITS[name.replaceAll('.', '_')], actual: value,
        });
      }
    }
  } catch (error) {
    try {
      await writeFile(path.join(child, 'cgroup.kill'), '1');
      await rmdir(child);
    } catch { /* Preserve the original setup failure; the caller must inspect the delegated parent. */ }
    if (error instanceof OrixError) throw error;
    isolation_error('ORIX_PROVIDER_CGROUP_SETUP_FAILED', 'Could not configure the provider cgroup-v2 resource limits', {
      reason: error.code ?? error.name ?? 'setup-failed',
    });
  }

  let cleanupPromise = null;
  const cleanup = () => {
    if (cleanupPromise) return cleanupPromise;
    cleanupPromise = (async () => {
      await writeFile(path.join(child, 'cgroup.kill'), '1');
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        const events = (await readFile(path.join(child, 'cgroup.events'), 'utf8')).trim();
        if (/^populated 0$/m.test(events)) {
          await rmdir(child);
          return;
        }
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      isolation_error('ORIX_PROVIDER_CGROUP_CLEANUP_TIMEOUT',
        'Provider cgroup did not become empty after the kernel kill request', { cgroup: child });
    })().catch(error => {
      cleanupPromise = null;
      throw error;
    });
    return cleanupPromise;
  };
  return Object.freeze({ path: child, cleanup });
}

export async function prepare_linux_provider_isolation({
  executable, cwd, sandbox_root, sandbox_cgroup_parent, args, env,
}) {
  if (process.platform !== 'linux') {
    isolation_error('ORIX_PROVIDER_ISOLATION_UNAVAILABLE',
      'Required provider isolation currently has no enforced backend for this operating system',
      { platform: process.platform });
  }
  const root = await validate_rootfs(sandbox_root);
  const sandboxExecutable = sandbox_path(root, executable, 'executable');
  const sandboxCwd = sandbox_path(root, cwd, 'cwd');
  const bwrap = await resolve_bwrap();
  const prlimit = await resolve_prlimit();
  const cgroup = await prepare_provider_cgroup(sandbox_cgroup_parent);

  const bwrapArgs = [
    '--die-with-parent', '--new-session', '--unshare-all',
    '--ro-bind', root, '/', '--proc', '/proc', '--dev', '/dev',
    '--tmpfs', '/tmp', '--chdir', sandboxCwd,
    '--clearenv', '--setenv', 'HOME', '/tmp', '--setenv', 'TMPDIR', '/tmp',
  ];
  for (const [key, value] of Object.entries(env)) bwrapArgs.push('--setenv', key, value);
  bwrapArgs.push('--', sandboxExecutable, ...args);

  const limitArgs = [
    '--cpu=60:60', '--fsize=67108864:67108864', '--nofile=256:256', '--core=0:0',
    '--', bwrap, ...bwrapArgs,
  ];
  const wrapper = fileURLToPath(new URL('../../scripts/provider-cgroup-exec.mjs', import.meta.url));
  return Object.freeze({
    executable: process.execPath,
    args: Object.freeze([wrapper, cgroup.path, prlimit, ...limitArgs]),
    cwd: '/',
    env: Object.freeze({}),
    cleanup: cgroup.cleanup,
  });
}
