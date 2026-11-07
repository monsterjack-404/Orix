// Real-kernel cgroup v2 integration gate. Run as root on a writable cgroup2 host.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, rmdir, rm, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { run_static_provider } from '../src/providers/process-runner.mjs';
import { prepare_linux_provider_cgroup } from '../src/providers/linux-cgroup-v2-manager.mjs';
import { parse_cgroup2_mounts } from '../src/providers/linux-cgroup-v2-preflight.mjs';
import { assert_linux_cgroup_integration_authorized } from '../src/providers/linux-cgroup-v2-test-gate.mjs';

const REQUIRED = ['cpu', 'memory', 'pids'];
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

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
  const binaries = [
    { source: process.execPath, target: path.join(root, 'usr/bin/node') },
    { source: '/usr/bin/sleep', target: path.join(root, 'usr/bin/sleep') },
    { source: '/usr/bin/unshare', target: path.join(root, 'usr/bin/unshare') },
  ];
  const paths = new Set();
  for (const binary of binaries) {
    paths.add(binary.source);
    const dependencies = execFileSync('ldd', [binary.source], { encoding: 'utf8' });
    for (const line of dependencies.split('\n')) {
      const match = line.match(/(?:=>\s*)?(\/\S+)\s+\(/);
      if (match) paths.add(match[1]);
    }
    await copyFile(binary.source, binary.target);
    await chmod(binary.target, 0o755);
  }
  for (const source of paths) {
    if (binaries.some(binary => binary.source === source)) continue;
    const destination = path.join(root, source.slice(1));
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(source, destination);
    await chmod(destination, 0o755);
  }
  return binaries[0].target;
}

async function find_provider_cgroup(parent) {
  const names = await readdir(parent);
  const name = names.find(item => item.startsWith('orix-provider-'));
  return name ? path.join(parent, name) : null;
}

async function sample_cgroup(parent, marker) {
  let cgroup;
  try {
    cgroup = await find_provider_cgroup(parent);
  } catch (error) {
    // A provider may finish and remove its unique leaf between readdir and
    // inspection. cgroupfs can report ENODEV as well as ENOENT for that race.
    if (error.code === 'ENOENT' || error.code === 'ENODEV') return null;
    throw error;
  }
  if (!cgroup) return null;
  try {
    let provider_seen = false;
    let sleep_pids = [];
    const pids = (await read_control(path.join(cgroup, 'cgroup.procs'))).split('\n').filter(Boolean);
    for (const pid of pids) {
      try {
        const command = await readFile('/proc/' + pid + '/cmdline', 'utf8');
        if (command.includes(marker)) provider_seen = true;
        if (command.includes('/usr/bin/sleep')) sleep_pids.push(Number(pid));
      } catch (error) {
        if (error.code !== 'ENOENT' && error.code !== 'ESRCH') throw error;
        // The process may exit after cgroup.procs is sampled.
      }
    }
    const cpu = await read_control(path.join(cgroup, 'cpu.stat'));
    const throttled = Number(cpu.match(/^nr_throttled (\\d+)$/m)?.[1] || 0);
    const memory = Number(await read_control(path.join(cgroup, 'memory.current')));
    const pidsCurrent = Number(await read_control(path.join(cgroup, 'pids.current')));
    const memoryEvents = await read_control(path.join(cgroup, 'memory.events'));
    const oomKills = Number(memoryEvents.match(/^oom_kill (\\d+)$/m)?.[1] || 0);
    return { cgroup, provider_seen, sleep_pids, throttled, memory, pidsCurrent, oomKills };
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENODEV') {
      // A disappearing control file is benign only when the leaf itself is gone.
      try {
        await lstat(cgroup);
      } catch (directoryError) {
        if (directoryError.code === 'ENOENT' || directoryError.code === 'ENODEV') return null;
        throw directoryError;
      }
    }
    throw error;
  }
}
  }
}
async function create_delegated_parent() {
  assert.equal(process.platform, 'linux');
  assert.equal(typeof process.geteuid, 'function');
  assert.equal(process.geteuid(), 0, 'The real cgroup integration gate must run as root');
  const mountinfo = await readFile('/proc/self/mountinfo', 'utf8');
  const mounts = parse_cgroup2_mounts(mountinfo);
  const mount = mounts.find(item => item.root === '/') ?? mounts[0];
  assert.ok(mount, 'No cgroup v2 mount was found');
  // Test-only: this harness runs as root on a disposable hosted CI VM. It
  // creates and restores a temporary hierarchy below the cgroup mount root;
  // production ORIX must use an administrator/systemd-delegated subtree.
  const root = mount.mountpoint;
  const available = (await read_control(path.join(root, 'cgroup.controllers'))).split(/\s+/).filter(Boolean);
  for (const name of REQUIRED) assert.ok(available.includes(name), 'Host cgroup2 lacks controller: ' + name);
  const enabledBefore = (await read_control(path.join(root, 'cgroup.subtree_control'))).split(/\s+/).filter(Boolean).map(item => item.replace(/^\+/, ''));
  const added = REQUIRED.filter(name => !enabledBefore.includes(name));

  // A per-run random suffix prevents a stale PID-named cgroup from being
  // mistaken for a directory created by this invocation.
  const parent = path.join(root, 'orix-ci-' + process.pid + '-' + randomUUID());
  const supervisor = path.join(parent, 'supervisor');
  let parentCreated = false;
  let supervisorCreated = false;
  let processMoved = false;
  let rootEnableAttempted = false;

  try {
    // Track ownership before each mutation. Setup failures must restore only
    // directories and controller changes made by this invocation.
    if (added.length) {
      rootEnableAttempted = true;
      await write_control(path.join(root, 'cgroup.subtree_control'), '+' + added.join(' +'));
    }
    await mkdir(parent, { mode: 0o755 });
    parentCreated = true;
    await mkdir(supervisor, { mode: 0o755 });
    supervisorCreated = true;
    await write_control(path.join(supervisor, 'cgroup.procs'), String(process.pid));
    processMoved = true;
    await write_control(path.join(parent, 'cgroup.subtree_control'), '+' + REQUIRED.join(' +'));
    const parentControllers = (await read_control(path.join(parent, 'cgroup.controllers'))).split(/\s+/);
    for (const name of REQUIRED) assert.ok(parentControllers.includes(name), 'Delegated parent did not expose controller: ' + name);
    return { root, parent, supervisor, added };
  } catch (setupError) {
    const cleanupErrors = [];

    // Move only this process back, and only when the attach to our supervisor
    // child completed. Never touch a pre-existing path after mkdir failed.
    if (processMoved) {
      try { await write_control(path.join(root, 'cgroup.procs'), String(process.pid)); }
      catch (error) { cleanupErrors.push(error); }
    }

    // A controller write can partially succeed. Read actual state and disable
    // only the required controllers that are currently enabled on our parent.
    let parentRemoved = !parentCreated;
    if (parentCreated) {
      try {
        const enabledNow = (await read_control(path.join(parent, 'cgroup.subtree_control')))
          .split(/\s+/).filter(Boolean).map(item => item.replace(/^\+/, ''));
        const ours = REQUIRED.filter(name => enabledNow.includes(name));
        if (ours.length) await write_control(path.join(parent, 'cgroup.subtree_control'), '-' + ours.join(' -'));
      } catch (error) { cleanupErrors.push(error); }
    }
    if (supervisorCreated) {
      try { await rmdir(supervisor); }
      catch (error) { cleanupErrors.push(error); }
    }
    if (parentCreated) {
      try { await rmdir(parent); parentRemoved = true; }
      catch (error) { cleanupErrors.push(error); }
    }

    // Restore root-level controllers only after our child hierarchy is gone.
    // If removal failed, leaving controllers enabled is safer than disabling
    // controls that a still-existing child hierarchy may require.
    if (rootEnableAttempted && parentRemoved) {
      try {
        const rootEnabledNow = (await read_control(path.join(root, 'cgroup.subtree_control')))
          .split(/\s+/).filter(Boolean).map(item => item.replace(/^\+/, ''));
        const ours = added.filter(name => rootEnabledNow.includes(name));
        if (ours.length) await write_control(path.join(root, 'cgroup.subtree_control'), '-' + ours.join(' -'));
      } catch (error) { cleanupErrors.push(error); }
    }

    if (cleanupErrors.length) {
      throw new AggregateError([setupError, ...cleanupErrors],
        'Delegated cgroup setup failed and rollback was incomplete');
    }
    throw setupError;
  }
}
async function remove_delegated_parent(state) {
  const { root, parent, supervisor, added } = state;
  // The parent is unique to this invocation. If a provider cleanup regressed,
  // kill only its direct ORIX run cgroups and verify they are empty before rmdir.
  const remaining = (await child_directories(parent)).filter(name => name !== 'supervisor');
  for (const name of remaining) {
    assert.ok(name.startsWith('orix-provider-'), 'Refusing to clean an unknown delegated child cgroup: ' + name);
    const cgroup = path.join(parent, name);
    await write_control(path.join(cgroup, 'cgroup.kill'), '1');
    const deadline = performance.now() + 5_000;
    while (performance.now() < deadline) {
      if (/^populated 0$/m.test(await read_control(path.join(cgroup, 'cgroup.events')))) break;
      await delay(25);
    }
    assert.match(await read_control(path.join(cgroup, 'cgroup.events')), /^populated 0$/m,
      'Provider cgroup remained populated during integration cleanup: ' + name);
    await rmdir(cgroup);
  }
  await write_control(path.join(root, 'cgroup.procs'), String(process.pid));
  await rmdir(supervisor);
  await write_control(path.join(parent, 'cgroup.subtree_control'), '-' + REQUIRED.join(' -'));
  await rmdir(parent);
  if (added.length) await write_control(path.join(root, 'cgroup.subtree_control'), '-' + added.join(' -'));
}

async function main() {
  // This gate mutates root-level cgroup controller state on a disposable VM.
  // Require explicit workflow authorization before creating any cgroup.
  assert_linux_cgroup_integration_authorized();
  assert.equal(process.platform, 'linux', 'This integration gate must run on Linux');
  assert.equal(typeof process.geteuid, 'function');
  assert.equal(process.geteuid(), 0, 'The real cgroup integration gate must run as root');

  // Validate every non-mutating prerequisite before changing host cgroup state.
  // In particular, a /tmp workspace rejection must never strand a new cgroup.
  const hostWorkspace = path.resolve(process.cwd());
  const tempRoot = path.resolve(os.tmpdir());
  const workspaceFromTemp = path.relative(tempRoot, hostWorkspace);
  const workspaceInsideTemp = workspaceFromTemp === '' ||
    (!path.isAbsolute(workspaceFromTemp) && workspaceFromTemp !== '..' &&
     !workspaceFromTemp.startsWith('..' + path.sep));
  assert.equal(workspaceInsideTemp, false,
    'Host-root sentinel must be outside /tmp because the sandbox deliberately replaces /tmp with a tmpfs');

  const delegated = await create_delegated_parent();
  const previousParent = process.env.ORIX_CGROUP_PARENT;
  const hostSecret = path.join(hostWorkspace, '.orix-cgroup-host-secret-' + process.pid + '-' + randomUUID());
  const hostSecretValue = 'host-only-secret-' + process.pid + '-' + randomUUID();
  let base = null;
  let server;
  try {
    process.env.ORIX_CGROUP_PARENT = delegated.parent;
    // Allocate temporary state only after entering the cleanup-protected region.
    base = await mkdtemp(path.join(os.tmpdir(), 'orix-cgroup-integration-'));
    const root = path.join(base, 'rootfs');
    await mkdir(root);
    const nodePath = await make_minimal_rootfs(root);
    const rootfsMarkerValue = 'rootfs-only-' + process.pid + '-' + randomUUID();
    await writeFile(path.join(root, 'work', 'orix-rootfs-marker'), rootfsMarkerValue, { flag: 'wx', mode: 0o400 });
    await writeFile(hostSecret, hostSecretValue, { flag: 'wx', mode: 0o600 });

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
      import { spawn, spawnSync } from 'node:child_process';
      const marker = ${JSON.stringify(marker)};
      const result = { marker, namespace_pid: process.pid, namespace_parent_pid: process.ppid, host_pid: Number(process.env.ORIX_HOST_PID) };
      try { result.rootfs_marker = fs.readFileSync('/work/orix-rootfs-marker', 'utf8'); }
      catch (error) { result.rootfs_marker_error = error.code || 'rootfs-marker-read-failed'; }
      const nested = spawnSync('/usr/bin/unshare', ['--user', '--map-root-user', '/usr/bin/node', '-e', 'process.exit(0)'], { encoding: 'utf8', timeout: 1500 });
      result.nested_userns = nested.error?.code === 'ENOENT' ? 'probe-missing' : nested.status === 0 ? 'allowed' : 'blocked';
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
      const cpuStart = performance.now();
      let cpuIterations = 0;
      while (performance.now() - cpuStart < 1500) cpuIterations += 1;
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
      env: { ORIX_HOST_PID: String(process.pid) },
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
    assert.equal(execution.isolation, 'required', 'Execution result did not preserve the explicitly requested isolation policy');
    assert.equal(execution.isolation_enforced, true, 'Execution result claimed no enforced isolation after the required backend succeeded');
    const result = JSON.parse(execution.stdout);
    assert.equal(providerSeen, true, 'Provider process was not observed in its run cgroup before execution completed');
    assert.notEqual(result.namespace_pid, result.host_pid, 'Provider PID was not remapped into a private PID namespace');
    assert.equal(result.rootfs_marker, rootfsMarkerValue,
      'Provider did not read the positive marker from the intended minimal rootfs');
    assert.equal(result.memory_probe_ok, true, 'Provider could not complete the bounded memory allocation probe');
    assert.ok(peakMemory > 250 * 1024 * 1024, 'Kernel did not account the provider memory allocation in memory.current');
    assert.ok(throttledPeriods > 0, 'cpu.max did not throttle the busy provider');
    assert.ok(peakPids >= 32, 'pids.current did not reflect provider-created descendants');
    assert.ok(peakPids <= 64, 'Observed task count exceeded the configured pids.max ceiling');
    assert.equal(result.memory_probe_ok, true, 'Provider memory-allocation probe did not complete');
    assert.equal(result.cpu_probe, true, 'Provider CPU-load probe did not complete');
    assert.ok(result.pids_limit_hits > 0, 'pids.max did not reject excess process creation');
    assert.ok(sleepPids.length > 0, 'Provider descendants were not observed inside the run cgroup');
    assert.equal(result.namespace_parent_pid, 1, 'Provider is not contained under the private PID namespace init process');
    assert.equal(result.nested_userns, 'blocked', 'Provider can still create nested user namespaces');
    assert.notEqual(result.host_file, 'readable', 'Provider read a host-workspace file outside its rootfs');
    assert.notEqual(result.root_write, 'writable', 'Provider modified the read-only sandbox rootfs');
    assert.equal(result.tmp_write, 'allowed', 'Ephemeral /tmp should remain writable');
    assert.equal(result.host_network, 'blocked', 'Provider reached the host loopback network');
    assert.deepEqual(result.rlimits.cpu_seconds, ['60', '60']);
    assert.deepEqual(result.rlimits.core_bytes, ['0', '0']);
    assert.deepEqual(result.rlimits.file_size_bytes, ['67108864', '67108864']);
    assert.deepEqual(result.rlimits.open_files, ['256', '256']);
    assert.equal(execution.isolation_cleanup.complete, true);
    assert.equal(execution.isolation_cleanup.failed, false);
    assert.equal(execution.isolation_cleanup.error, null);
    assert.equal(execution.isolation_cleanup.report.removed, true);
    assert.ok(Number(execution.isolation_cleanup.report.cpu_stat.match(/^nr_throttled (\d+)$/m)?.[1] || 0) > 0,
      'Final cgroup cpu.stat did not record quota throttling');
    assert.ok(Number(execution.isolation_cleanup.report.pids_events.match(/^max (\d+)$/m)?.[1] || 0) > 0,
      'Final cgroup pids.events did not record pids.max enforcement');
    for (const pid of sleepPids) {
      const command = await readFile('/proc/' + pid + '/cmdline', 'utf8').catch(error => {
        if (error.code === 'ENOENT') return '';
        throw error;
      });
      assert.equal(command.includes('/usr/bin/sleep'), false, 'Provider descendant survived cgroup cleanup');
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
    let oomDone = false;
    let oomExecution;
    oomPromise.then(value => { oomExecution = value; oomDone = true; }, error => { oomExecution = error; oomDone = true; });
    if (!oomDone) oomExecution = await oomPromise;
    else if (oomExecution instanceof Error) throw oomExecution;
    assert.equal(oomExecution.ok, false, 'Provider unexpectedly survived an allocation above memory.max');
    assert.equal(oomExecution.isolation, 'required', 'OOM execution result lost the required isolation policy');
    assert.equal(oomExecution.isolation_enforced, true, 'OOM execution did not report the successfully prepared isolation backend');
    assert.equal(oomExecution.isolation_cleanup.complete, true);
    assert.equal(oomExecution.isolation_cleanup.failed, false);
    assert.equal(oomExecution.isolation_cleanup.error, null);
    assert.equal(oomExecution.isolation_cleanup.report.removed, true);
    assert.ok(Number(oomExecution.isolation_cleanup.report.memory_events.match(/^oom_kill (\d+)$/m)?.[1] || 0) > 0,
      'memory.max did not produce a kernel OOM kill event');

    // Verify asynchronous cancellation kills the whole provider cgroup,
    // including a descendant that outlives the Node provider process.
    const cancellationMarker = 'ORIX_CGROUP_CANCEL_PROBE_' + process.pid;
    const cancellationController = new AbortController();
    const cancellationProbe = `
      import { spawn } from 'node:child_process';
      const marker = ${JSON.stringify(cancellationMarker)};
      const child = spawn('/usr/bin/sleep', ['30'], { stdio: 'ignore' });
      child.unref();
      process.stdout.write(marker);
      setInterval(() => {}, 1000);
    `;
    const cancellationPromise = run_static_provider({
      manifest: manifest(),
      executable: nodePath,
      cwd: path.join(root, 'work'),
      sandbox_root: root,
      isolation: 'required',
      args: ['-e', cancellationProbe],
      signal: cancellationController.signal,
      timeout_ms: 8_000,
      max_output_bytes: 4_096,
    });
    let cancellationSample = null;
    for (let attempt = 0; attempt < 250; attempt += 1) {
      cancellationSample = await sample_cgroup(delegated.parent, cancellationMarker).catch(error => {
        if (error.code === 'ENOENT') return null;
        throw error;
      });
      if (cancellationSample?.provider_seen && cancellationSample.sleep_pids.length > 0) break;
      await delay(20);
    }
    assert.ok(cancellationSample?.provider_seen, 'Cancellation provider never became visible in its run cgroup');
    assert.ok(cancellationSample.sleep_pids.length > 0, 'Cancellation probe did not create a descendant');
    cancellationController.abort();
    const cancelledExecution = await cancellationPromise;
    assert.equal(cancelledExecution.cancelled, true, 'AbortSignal cancellation was not reported');
    assert.equal(cancelledExecution.termination_reason, 'cancelled');
    assert.equal(cancelledExecution.isolation_cleanup.complete, true);
    assert.equal(cancelledExecution.isolation_cleanup.failed, false);
    assert.equal(cancelledExecution.isolation_cleanup.error, null);
    assert.equal(cancelledExecution.isolation_cleanup.report.removed, true);
    for (const pid of cancellationSample.sleep_pids) {
      const command = await readFile('/proc/' + pid + '/cmdline', 'utf8').catch(error => {
        if (error.code === 'ENOENT') return '';
        throw error;
      });
      assert.equal(command.includes('/usr/bin/sleep'), false, 'Cancelled provider descendant survived cgroup.kill');
    }

    // Exercise the timeout path separately; its cleanup contract must be the
    // same as explicit cancellation and must not leave a detached descendant.
    const timeoutMarker = 'ORIX_CGROUP_TIMEOUT_PROBE_' + process.pid;
    const timeoutProbe = `
      import { spawn } from 'node:child_process';
      const marker = ${JSON.stringify(timeoutMarker)};
      const child = spawn('/usr/bin/sleep', ['30'], { stdio: 'ignore' });
      child.unref();
      process.stdout.write(marker);
      setInterval(() => {}, 1000);
    `;
    const timeoutPromise = run_static_provider({
      manifest: manifest(),
      executable: nodePath,
      cwd: path.join(root, 'work'),
      sandbox_root: root,
      isolation: 'required',
      args: ['-e', timeoutProbe],
      timeout_ms: 5_000,
      max_output_bytes: 4_096,
    });
    let timeoutSample = null;
    for (let attempt = 0; attempt < 200; attempt += 1) {
      timeoutSample = await sample_cgroup(delegated.parent, timeoutMarker).catch(error => {
        if (error.code === 'ENOENT') return null;
        throw error;
      });
      if (timeoutSample?.provider_seen && timeoutSample.sleep_pids.length > 0) break;
      await delay(20);
    }
    assert.ok(timeoutSample?.provider_seen, 'Timeout provider never became visible in its run cgroup');
    assert.ok(timeoutSample.sleep_pids.length > 0, 'Timeout probe did not create a descendant');
    const timedOutExecution = await timeoutPromise;
    assert.equal(timedOutExecution.timed_out, true, 'Provider timeout was not reported');
    assert.equal(timedOutExecution.termination_reason, 'timeout');
    assert.equal(timedOutExecution.isolation_cleanup.complete, true);
    assert.equal(timedOutExecution.isolation_cleanup.failed, false);
    assert.equal(timedOutExecution.isolation_cleanup.error, null);
    assert.equal(timedOutExecution.isolation_cleanup.report.removed, true);
    for (const pid of timeoutSample.sleep_pids) {
      const command = await readFile('/proc/' + pid + '/cmdline', 'utf8').catch(error => {
        if (error.code === 'ENOENT') return '';
        throw error;
      });
      assert.equal(command.includes('/usr/bin/sleep'), false, 'Timed-out provider descendant survived cgroup.kill');
    }

    // Verify captured-output overflow also tears down every task in the run cgroup.
    const outputLimitMarker = 'ORIX_CGROUP_OUTPUT_LIMIT_PROBE_' + process.pid;
    const outputLimitProbe = `
      import { spawn } from 'node:child_process';
      const marker = ${JSON.stringify(outputLimitMarker)};
      const child = spawn('/usr/bin/sleep', ['30'], { stdio: 'ignore' });
      child.unref();
      process.stdout.write(marker + 'x'.repeat(64 * 1024));
      setInterval(() => {}, 1000);
    `;
    const outputLimitPromise = run_static_provider({
      manifest: manifest(),
      executable: nodePath,
      cwd: path.join(root, 'work'),
      sandbox_root: root,
      isolation: 'required',
      args: ['--input-type=module', '-e', outputLimitProbe],
      timeout_ms: 8_000,
      max_output_bytes: 1_024,
    });
    let outputLimitSample = null;
    for (let attempt = 0; attempt < 250; attempt += 1) {
      outputLimitSample = await sample_cgroup(delegated.parent, outputLimitMarker).catch(error => {
        if (error.code === 'ENOENT') return null;
        throw error;
      });
      if (outputLimitSample?.provider_seen && outputLimitSample.sleep_pids.length > 0) break;
      await delay(20);
    }
    assert.ok(outputLimitSample?.provider_seen, 'Output-limit provider never became visible in its run cgroup');
    assert.ok(outputLimitSample.sleep_pids.length > 0, 'Output-limit probe did not create a descendant');
    const outputLimitedExecution = await outputLimitPromise;
    assert.equal(outputLimitedExecution.output_limited, true, 'Captured-output overflow was not reported');
    assert.equal(outputLimitedExecution.termination_reason, 'output-limit');
    assert.equal(outputLimitedExecution.isolation_cleanup.complete, true);
    assert.equal(outputLimitedExecution.isolation_cleanup.failed, false);
    assert.equal(outputLimitedExecution.isolation_cleanup.error, null);
    assert.equal(outputLimitedExecution.isolation_cleanup.report.removed, true);
    for (const pid of outputLimitSample.sleep_pids) {
      const command = await readFile('/proc/' + pid + '/cmdline', 'utf8').catch(error => {
        if (error.code === 'ENOENT') return '';
        throw error;
      });
      assert.equal(command.includes('/usr/bin/sleep'), false, 'Output-limited provider descendant survived cgroup.kill');
    }

    // Direct manager calls must make cleanup idempotent, including concurrent
    // callers racing to close the same leaf cgroup.
    const emptyRun = await prepare_linux_provider_cgroup();
    const [emptyCleanupA, emptyCleanupB] = await Promise.all([
      emptyRun.cleanup(),
      emptyRun.cleanup(),
    ]);
    assert.deepEqual(emptyCleanupA, emptyCleanupB,
      'Concurrent cleanup calls returned inconsistent results');
    assert.equal(emptyCleanupA.removed, true,
      'Idempotent cleanup did not remove the empty provider cgroup');
    assert.equal(emptyCleanupA.retry_count, 0,
      'A normal empty-cgroup cleanup should not need a retry');

    // Force one transient EBUSY by placing an empty nested cgroup under the
    // run leaf. Remove it during the bounded backoff; cleanup must retain the
    // delegated parent FD, reopen the leaf, and succeed on attempt two.
    const retryRun = await prepare_linux_provider_cgroup();
    const nestedCgroup = `${retryRun.path}/orix-transient-cleanup-probe`;
    await mkdir(nestedCgroup, { mode: 0o700 });
    const nestedRemoval = new Promise((resolve, reject) => {
      setTimeout(() => rmdir(nestedCgroup).then(resolve, reject), 25);
    });
    const retryReport = await retryRun.cleanup();
    await nestedRemoval;
    assert.equal(retryReport.retry_count, 1,
      'Transient cgroup removal failure was not retried exactly once');
    assert.equal(retryReport.removed, true,
      'Retry did not remove the provider cgroup after the nested child disappeared');

    // A signal already aborted before launch must still roll back the prepared
    // cgroup and must never reach provider spawn.
    const childrenBeforePreAbort = await child_directories(delegated.parent);
    const preAbortedController = new AbortController();
    preAbortedController.abort();
    await assert.rejects(
      run_static_provider({
        manifest: manifest(),
        executable: nodePath,
        cwd: path.join(root, 'work'),
        sandbox_root: root,
        isolation: 'required',
        args: ['-e', 'process.stdout.write("MUST_NOT_SPAWN")'],
        signal: preAbortedController.signal,
        timeout_ms: 2_000,
        max_output_bytes: 1_024,
      }),
      error => error.code === 'ORIX_PROVIDER_CANCELLED',
    );
    assert.deepEqual(await child_directories(delegated.parent), childrenBeforePreAbort,
      'A pre-aborted request left a provider cgroup behind');

    process.stdout.write('Linux cgroup v2 integration passed: FD attach-before-exec, rootfs/network isolation, RLIMITs, cpu.max throttling, memory.max OOM, pids.max rejection, normal/cancel/timeout/output-limit descendant teardown and empty-cgroup removal.\\n');
  } finally {
    const cleanupErrors = [];
    try {
      if (server) await new Promise((resolve, reject) => {
        server.close(error => error ? reject(error) : resolve());
      });
    } catch (error) { cleanupErrors.push(error); }
    try { await rm(hostSecret, { force: true }); }
    catch (error) { cleanupErrors.push(error); }
    try { if (base) await rm(base, { recursive: true, force: true }); }
    catch (error) { cleanupErrors.push(error); }
    try {
      if (previousParent === undefined) delete process.env.ORIX_CGROUP_PARENT;
      else process.env.ORIX_CGROUP_PARENT = previousParent;
    } catch (error) { cleanupErrors.push(error); }
    try { await remove_delegated_parent(delegated); }
    catch (error) { cleanupErrors.push(error); }
    if (cleanupErrors.length) {
      throw new AggregateError(cleanupErrors, 'Linux cgroup integration cleanup was incomplete');
    }
  }
}

await main();
