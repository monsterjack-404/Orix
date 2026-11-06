// Real-kernel cgroup v2 integration gate. Run as root on a writable cgroup2 host.
import assert from 'node:assert/strict';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { run_static_provider } from '../src/providers/process-runner.mjs';
import { parse_cgroup2_mounts } from '../src/providers/linux-cgroup-v2-preflight.mjs';

const REQUIRED = ['cpu', 'memory', 'pids'];
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function manifest() {
  return {
    contract_version: 'orix.provider.v1',
    id: 'test.linux-cgroup-v2',
    name: 'Linux cgroup v2 integration test',
    version: '1.0.0',
    description: 'Hostile-process verification for Bubblewrap plus aggregate cgroup v2 limits.',
    capabilities: ['test.process'],
    supported_platforms: ['linux'],
    input_formats: ['test'],
    execution: {
      mode: 'static',
      requires_authorization: false,
      executes_target: false,
      writes_target: false,
      uses_network: false,
    },
    limits: { timeout_ms: 10_000, max_input_bytes: 1024, max_output_bytes: 16_384 },
    license: { spdx_id: 'MIT', redistribution: 'external-install' },
  };
}

async function write_control(file, value) {
  await writeFile(file, value + '\n');
}

async function read_control(file) {
  return (await readFile(file, 'utf8')).trim();
}

async function make_minimal_rootfs(root) {
  for (const directory of ['proc', 'dev', 'tmp', 'work', 'usr/bin']) {
    await mkdir(path.join(root, directory), { recursive: true });
  }
  const binaries = [process.execPath, '/usr/bin/sleep'];
  const paths = new Set(binaries);
  for (const binary of binaries) {
    const dependencies = execFileSync('ldd', [binary], { encoding: 'utf8' });
    for (const line of dependencies.split('\n')) {
      const match = line.match(/(?:=>\s*)?(\/\S+)\s+\(/);
      if (match) paths.add(match[1]);
    }
  }
  const nodePath = path.join(root, 'usr/bin/node');
  await copyFile(process.execPath, nodePath);
  await chmod(nodePath, 0o755);
  for (const source of paths) {
    if (source === process.execPath) continue;
    const destination = path.join(root, source.slice(1));
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(source, destination);
    await chmod(destination, 0o755);
  }
  return nodePath;
}

async function find_provider_cgroup(parent) {
  const names = await readdir(parent);
  const name = names.find(item => item.startsWith('orix-provider-'));
  return name ? path.join(parent, name) : null;
}

async function sample_cgroup(parent, marker) {
  const cgroup = await find_provider_cgroup(parent);
  if (!cgroup) return null;
  let provider_seen = false;
  let sleep_pids = [];
  const pids = (await read_control(path.join(cgroup, 'cgroup.procs'))).split('\n').filter(Boolean);
  for (const pid of pids) {
    try {
      const command = await readFile('/proc/' + pid + '/cmdline', 'utf8');
      if (command.includes(marker)) provider_seen = true;
      if (command.includes('/usr/bin/sleep')) sleep_pids.push(Number(pid));
    } catch { /* process may have exited between cgroup.procs and procfs read */ }
  }
  const cpu = await read_control(path.join(cgroup, 'cpu.stat'));
  const throttled = Number(cpu.match(/^nr_throttled (\d+)$/m)?.[1] || 0);
  const memory = Number(await read_control(path.join(cgroup, 'memory.current')));
  const pidsCurrent = Number(await read_control(path.join(cgroup, 'pids.current')));
  const memoryEvents = await read_control(path.join(cgroup, 'memory.events'));
  const oomKills = Number(memoryEvents.match(/^oom_kill (\d+)$/m)?.[1] || 0);
  return { cgroup, provider_seen, sleep_pids, throttled, memory, pidsCurrent, oomKills };
}

async function create_delegated_parent() {
  assert.equal(process.platform, 'linux');
  assert.equal(typeof process.geteuid, 'function');
  assert.equal(process.geteuid(), 0, 'The real cgroup integration gate must run as root');
  const mountinfo = await readFile('/proc/self/mountinfo', 'utf8');
  const mounts = parse_cgroup2_mounts(mountinfo);
  const mount = mounts.find(item => item.root === '/') ?? mounts[0];
  assert.ok(mount, 'No cgroup v2 mount was found');
  const root = mount.mountpoint;
  const available = (await read_control(path.join(root, 'cgroup.controllers'))).split(/\s+/).filter(Boolean);
  for (const name of REQUIRED) assert.ok(available.includes(name), 'Host cgroup2 lacks controller: ' + name);
  const enabledBefore = (await read_control(path.join(root, 'cgroup.subtree_control'))).split(/\s+/).filter(Boolean).map(item => item.replace(/^\+/, ''));
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
    for (const name of REQUIRED) assert.ok(parentControllers.includes(name), 'Delegated parent did not expose controller: ' + name);
    return { root, parent, supervisor, added };
  } catch (error) {
    try { await write_control(path.join(root, 'cgroup.procs'), String(process.pid)); } catch { /* best-effort recovery */ }
    try { await rm(parent, { recursive: true, force: true }); } catch { /* preserve setup error */ }
    if (added.length) try { await write_control(path.join(root, 'cgroup.subtree_control'), '-' + added.join(' -')); } catch { /* preserve setup error */ }
    throw error;
  }
}

async function remove_delegated_parent(state) {
  const { root, parent, supervisor, added } = state;
  // All run cgroups must have been removed by the provider manager before this point.
  const remaining = (await readdir(parent)).filter(name => name !== 'supervisor');
  assert.deepEqual(remaining, [], 'Provider cgroups remain after integration cleanup');
  await write_control(path.join(root, 'cgroup.procs'), String(process.pid));
  await rm(supervisor, { recursive: true, force: true });
  await write_control(path.join(parent, 'cgroup.subtree_control'), '-' + REQUIRED.join(' -'));
  await rm(parent, { recursive: true, force: true });
  if (added.length) await write_control(path.join(root, 'cgroup.subtree_control'), '-' + added.join(' -'));
}

async function main() {
  assert.equal(process.platform, 'linux', 'This integration gate must run on Linux');
  const delegated = await create_delegated_parent();
  process.env.ORIX_CGROUP_PARENT = delegated.parent;
  const base = await mkdtemp(path.join(os.tmpdir(), 'orix-cgroup-integration-'));
  const root = path.join(base, 'rootfs');
  const hostSecret = path.join(os.tmpdir(), 'orix-cgroup-host-secret-' + process.pid);
  const hostSecretValue = 'host-only-secret-' + process.pid;
  let server;
  try {
    await mkdir(root);
    const nodePath = await make_minimal_rootfs(root);
    await writeFile(hostSecret, hostSecretValue, { mode: 0o600 });

    server = net.createServer();
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;
    const marker = 'ORIX_CGROUP_PROVIDER_PROBE_' + process.pid;
    const probe = `
      import fs from 'node:fs';
      import net from 'node:net';
      import { spawn } from 'node:child_process';
      const marker = ${JSON.stringify(marker)};
      const result = { marker, namespace_pid: process.pid, namespace_parent_pid: process.ppid };
      try { fs.readFileSync(${JSON.stringify(hostSecret)}, 'utf8'); result.host_file = 'readable'; }
      catch (error) { result.host_file = error.code || 'blocked'; }
      try { fs.writeFileSync('/work/host-write-probe', 'escape'); result.root_write = 'writable'; }
      catch (error) { result.root_write = error.code || 'blocked'; }
      try { fs.writeFileSync('/tmp/provider-write-probe', 'allowed'); result.tmp_write = 'allowed'; }
      catch (error) { result.tmp_write = error.code || 'blocked'; }
      const limits = fs.readFileSync('/proc/self/limits', 'utf8');
      const limit = label => {
        const line = limits.split('\\n').find(item => item.startsWith(label));
        const columns = label.split(' ').length;
        return line ? line.trim().split(/\\s+/).slice(columns, columns + 2) : null;
      };
      result.rlimits = {
        cpu_seconds: limit('Max cpu time'),
        core_bytes: limit('Max core file size'),
        file_size_bytes: limit('Max file size'),
        open_files: limit('Max open files')
      };
      const memory = Buffer.alloc(300 * 1024 * 1024, 0x5a);
      result.memory_probe_ok = memory.length === 300 * 1024 * 1024 && memory[0] === 0x5a;
      const children = [];
      let pids_limit_hits = 0;
      for (let index = 0; index < 100; index += 1) {
        const child = spawn('/usr/bin/sleep', ['30'], { stdio: 'ignore' });
        child.on('error', error => { if (error.code === 'EAGAIN') pids_limit_hits += 1; });
        children.push(child);
      }
      await new Promise(resolve => setTimeout(resolve, 250));
      result.pids_limit_hits = pids_limit_hits;
      const cpuStart = Date.now();
      let cpuIterations = 0;
      while (Date.now() - cpuStart < 1500) cpuIterations += 1;
      result.cpu_probe = cpuIterations > 0;
      result.host_network = await new Promise(resolve => {
        const socket = net.createConnection({ host: '127.0.0.1', port: ${port} });
        socket.setTimeout(700, () => { socket.destroy(); resolve('blocked'); });
        socket.once('error', () => resolve('blocked'));
        socket.once('connect', () => { socket.destroy(); resolve('connected'); });
      });
      await new Promise(resolve => setTimeout(resolve, 800));
      fs.writeSync(1, JSON.stringify(result));
      process.exit(0);
    `;

    const runPromise = run_static_provider({
      manifest: manifest(),
      executable: nodePath,
      cwd: path.join(root, 'work'),
      sandbox_root: root,
      isolation: 'required',
      args: ['--input-type=module', '-e', probe],
      timeout_ms: 9_000,
      max_output_bytes: 8_192,
    });

    let latest = null;
    let peakMemory = 0;
    let throttledPeriods = 0;
    let peakPids = 0;
    let providerSeen = false;
    let sleepPids = [];
    let finished = false;
    let execution = null;
    runPromise.then(value => { execution = value; finished = true; }, error => { execution = error; finished = true; });
    for (let attempt = 0; attempt < 350 && !finished; attempt += 1) {
      try {
        latest = await sample_cgroup(delegated.parent, marker);
        if (latest) {
          peakMemory = Math.max(peakMemory, latest.memory);
          throttledPeriods = Math.max(throttledPeriods, latest.throttled);
          peakPids = Math.max(peakPids, latest.pidsCurrent);
          providerSeen ||= latest.provider_seen;
          sleepPids = [...new Set([...sleepPids, ...latest.sleep_pids])];
        }
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      await delay(20);
    }
    if (!finished) execution = await runPromise;
    else if (execution instanceof Error) throw execution;
    else execution = await runPromise;

    assert.equal(execution.ok, true, execution.stderr || 'Cgroup-isolated provider failed');
    const result = JSON.parse(execution.stdout);
    assert.equal(providerSeen, true, 'Provider process was not observed in its run cgroup before execution completed');
    assert.ok(peakMemory > 250 * 1024 * 1024, 'Kernel did not account the provider memory allocation in memory.current');
    assert.ok(throttledPeriods > 0, 'cpu.max did not throttle the busy provider');
    assert.ok(peakPids >= 32, 'pids.current did not reflect provider-created descendants');
    assert.ok(result.pids_limit_hits > 0, 'pids.max did not reject excess process creation');
    assert.ok(sleepPids.length > 0, 'Provider descendants were not observed inside the run cgroup');
    assert.notEqual(result.namespace_parent_pid, process.pid, 'Provider is not isolated in a private PID namespace');
    assert.notEqual(result.host_file, 'readable', 'Provider read a host file outside its rootfs');
    assert.notEqual(result.root_write, 'writable', 'Provider modified the read-only sandbox rootfs');
    assert.equal(result.tmp_write, 'allowed', 'Ephemeral /tmp should remain writable');
    assert.equal(result.host_network, 'blocked', 'Provider reached the host loopback network');
    assert.deepEqual(result.rlimits.cpu_seconds, ['60', '60']);
    assert.deepEqual(result.rlimits.core_bytes, ['0', '0']);
    assert.deepEqual(result.rlimits.file_size_bytes, ['67108864', '67108864']);
    assert.deepEqual(result.rlimits.open_files, ['256', '256']);
    const runCgroup = latest?.cgroup ?? await find_provider_cgroup(delegated.parent);
    assert.ok(runCgroup, 'Run cgroup path was not observed');
    await assert.rejects(readFile(path.join(runCgroup, 'cgroup.events'), 'utf8'), error => error.code === 'ENOENT');
    for (const pid of sleepPids) {
      await assert.rejects(readFile('/proc/' + pid + '/cmdline', 'utf8'), error => error.code === 'ENOENT');
    }

    // A separate provider intentionally exceeds memory.max. memory.oom.group=1
    // should kill the run cgroup, while the host supervisor remains alive.
    const oomMarker = 'ORIX_CGROUP_OOM_PROBE_' + process.pid;
    const oomProbe = `
      const marker = ${JSON.stringify(oomMarker)};
      const block = Buffer.alloc(700 * 1024 * 1024, 0x5a);
      process.stdout.write(marker + String(block[0]));
      setTimeout(() => {}, 5000);
    `;
    const oomPromise = run_static_provider({
      manifest: manifest(),
      executable: nodePath,
      cwd: path.join(root, 'work'),
      sandbox_root: root,
      isolation: 'required',
      args: ['-e', oomProbe],
      timeout_ms: 8_000,
      max_output_bytes: 4_096,
    });
    let oomObserved = false;
    let oomRunCgroup = null;
    let oomDone = false;
    let oomExecution;
    oomPromise.then(value => { oomExecution = value; oomDone = true; }, error => { oomExecution = error; oomDone = true; });
    for (let attempt = 0; attempt < 250 && !oomDone; attempt += 1) {
      try {
        const candidate = await find_provider_cgroup(delegated.parent);
        if (candidate) {
          oomRunCgroup = candidate;
          const events = await read_control(path.join(candidate, 'memory.events'));
          const count = Number(events.match(/^oom_kill (\\d+)$/m)?.[1] || 0);
          if (count > 0) oomObserved = true;
        }
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      await delay(20);
    }
    if (!oomDone) oomExecution = await oomPromise;
    else if (oomExecution instanceof Error) throw oomExecution;
    else oomExecution = await oomPromise;
    assert.equal(oomExecution.ok, false, 'Provider unexpectedly survived an allocation above memory.max');
    assert.equal(oomObserved, true, 'memory.max did not produce a kernel OOM kill event');
    assert.ok(oomRunCgroup, 'OOM run cgroup was not observed');
    await assert.rejects(readFile(path.join(oomRunCgroup, 'cgroup.events'), 'utf8'), error => error.code === 'ENOENT');

    process.stdout.write('Linux cgroup v2 integration passed: FD attach-before-exec, rootfs/network isolation, RLIMITs, cpu.max throttling, memory.max OOM, pids.max rejection, descendant teardown and empty-cgroup removal.\\n');
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await rm(hostSecret, { force: true });
    await rm(base, { recursive: true, force: true });
    await remove_delegated_parent(delegated);
  }
}

await main();
