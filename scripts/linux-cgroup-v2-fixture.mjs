// Test-only Linux cgroup v2 delegation fixture. Run as root on a writable cgroup2 host.
import { lstat, mkdir, readFile, readdir, rmdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parse_cgroup2_mounts } from '../src/providers/linux-cgroup-v2-preflight.mjs';

const REQUIRED = ['cpu', 'memory', 'pids'];

async function write_control(file, value) {
  await writeFile(file, value + '\n');
}

async function read_control(file) {
  return (await readFile(file, 'utf8')).trim();
}

async function child_directories(parent) {
  const names = await readdir(parent);
  const directories = [];
  for (const name of names) {
    try {
      if ((await lstat(path.join(parent, name))).isDirectory()) directories.push(name);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return directories;
}

export async function create_delegated_parent() {
  if (process.platform !== 'linux' || typeof process.geteuid !== 'function' || process.geteuid() !== 0) {
    throw new Error('Real cgroup v2 integration requires a Linux root process');
  }
  const mountinfo = await readFile('/proc/self/mountinfo', 'utf8');
  const mounts = parse_cgroup2_mounts(mountinfo);
  const mount = mounts.find(item => item.root === '/') ?? mounts[0];
  if (!mount) throw new Error('No cgroup v2 mount was found');
  const root = mount.mountpoint;
  const available = (await read_control(path.join(root, 'cgroup.controllers'))).split(/\s+/).filter(Boolean);
  for (const name of REQUIRED) {
    if (!available.includes(name)) throw new Error('Host cgroup2 lacks controller: ' + name);
  }
  const enabledBefore = (await read_control(path.join(root, 'cgroup.subtree_control')))
    .split(/\s+/).filter(Boolean).map(item => item.replace(/^\+/, ''));
  const added = REQUIRED.filter(name => !enabledBefore.includes(name));
  if (added.length) await write_control(path.join(root, 'cgroup.subtree_control'), '+' + added.join(' +'));

  const parent = path.join(root, 'orix-ci-' + process.pid);
  const supervisor = path.join(parent, 'supervisor');
  await mkdir(parent, { mode: 0o755 });
  try {
    await mkdir(supervisor, { mode: 0o755 });
    await write_control(path.join(supervisor, 'cgroup.procs'), String(process.pid));
    await write_control(path.join(parent, 'cgroup.subtree_control'), '+' + REQUIRED.join(' +'));
    const parentControllers = (await read_control(path.join(parent, 'cgroup.controllers'))).split(/\s+/);
    for (const name of REQUIRED) {
      if (!parentControllers.includes(name)) throw new Error('Delegated parent did not expose controller: ' + name);
    }
    return Object.freeze({ root, parent, supervisor, added: Object.freeze(added) });
  } catch (error) {
    try { await write_control(path.join(root, 'cgroup.procs'), String(process.pid)); } catch { /* preserve setup error */ }
    try { await rmdir(supervisor); } catch { /* preserve setup error */ }
    try { await rmdir(parent); } catch { /* preserve setup error */ }
    if (added.length) try { await write_control(path.join(root, 'cgroup.subtree_control'), '-' + added.join(' -')); } catch { /* preserve setup error */ }
    throw error;
  }
}

export async function remove_delegated_parent(state) {
  const { root, parent, supervisor, added } = state;
  const remaining = (await child_directories(parent)).filter(name => name !== 'supervisor');
  if (remaining.length) {
    throw new Error('Provider cgroups remain after integration cleanup: ' + remaining.join(', '));
  }
  await write_control(path.join(root, 'cgroup.procs'), String(process.pid));
  await rmdir(supervisor);
  await write_control(path.join(parent, 'cgroup.subtree_control'), '-' + REQUIRED.join(' -'));
  await rmdir(parent);
  if (added.length) await write_control(path.join(root, 'cgroup.subtree_control'), '-' + added.join(' -'));
}
