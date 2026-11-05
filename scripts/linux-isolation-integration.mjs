// Linux Bubblewrap hostile-process integration gate. Run only on Linux with Bubblewrap and util-linux.
import assert from 'node:assert/strict';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, rm, rmdir, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { run_static_provider } from '../src/providers/process-runner.mjs';

async function child_cgroup_directories(parent) {
  const entries = await readdir(parent);
  const directories = [];
  for (const name of entries) {
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
    id: 'test.linux-isolation',
    name: 'Linux isolation integration test',
    version: '1.0.0',
    description: 'Hostile-process verification for the Bubblewrap provider backend.',
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

async function make_minimal_rootfs(root) {
  for (const directory of ['proc', 'dev', 'tmp', 'work', 'usr/bin']) {
    await mkdir(path.join(root, directory), { recursive: true });
  }
  const executable = process.execPath;
  const dependencies = execFileSync('ldd', [executable], { encoding: 'utf8' });
  const paths = new Set([executable]);
  for (const line of dependencies.split('\n')) {
    const match = line.match(/(?:=>\s*)?(\/\S+)\s+\(/);
    if (match) paths.add(match[1]);
  }
  const nodePath = path.join(root, 'usr/bin/node');
  await copyFile(executable, nodePath);
  await chmod(nodePath, 0o755);
  for (const source of paths) {
    if (source === executable) continue;
    const destination = path.join(root, source.slice(1));
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(source, destination);
    await chmod(destination, 0o755);
  }
  return nodePath;
}

async function main() {
  assert.equal(process.platform, 'linux', 'This integration gate must run on Linux');
  assert.equal(process.getuid?.(), 0, 'The cgroup-v2 integration gate must run with permission to create a delegated test hierarchy');
  const base = await mkdtemp(path.join(os.tmpdir(), 'orix-bwrap-integration-'));
  const root = path.join(base, 'rootfs');
  const hostSecret = path.join(os.tmpdir(), 'orix-host-secret-' + process.pid);
  const hostSecretValue = 'host-only-secret-' + process.pid;
  const cgroupParent = path.join('/sys/fs/cgroup', 'orix-integration-' + process.pid);
  let server;
  let cgroupParentCreated = false;
  try {
    await mkdir(root);
    await make_minimal_rootfs(root);
    const cgroupRoot = '/sys/fs/cgroup';
    const available = (await readFile(path.join(cgroupRoot, 'cgroup.controllers'), 'utf8')).trim().split(/\s+/);
    for (const controller of ['cpu', 'memory', 'pids']) {
      assert.ok(available.includes(controller), 'Missing cgroup-v2 controller: ' + controller);
    }
    const rootEnabled = (await readFile(path.join(cgroupRoot, 'cgroup.subtree_control'), 'utf8')).trim().split(/\s+/);
    const rootMissing = ['cpu', 'memory', 'pids'].filter(controller => !rootEnabled.includes(controller));
    if (rootMissing.length) await writeFile(path.join(cgroupRoot, 'cgroup.subtree_control'), rootMissing.map(item => '+' + item).join(' '));
    await mkdir(cgroupParent);
    cgroupParentCreated = true;
    assert.equal((await readFile(path.join(cgroupParent, 'cgroup.type'), 'utf8')).trim(), 'domain');
    assert.match(await readFile(path.join(cgroupParent, 'cgroup.events'), 'utf8'), /populated 0/);
    assert.equal((await readFile(path.join(cgroupParent, 'cgroup.procs'), 'utf8')).trim(), '');
    await writeFile(path.join(cgroupParent, 'cgroup.subtree_control'), '+cpu +memory +pids');
    await writeFile(hostSecret, hostSecretValue, { mode: 0o600 });

    server = net.createServer();
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;

    const probe = `
      import fs from 'node:fs';
      import net from 'node:net';
      const result = { namespace_pid: process.pid, namespace_parent_pid: process.ppid, host_pid: Number(process.env.ORIX_HOST_PID) };
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
      result.host_network = await new Promise(resolve => {
        const socket = net.createConnection({ host: '127.0.0.1', port: ${port} }, () => {
          socket.destroy(); resolve('connected');
        });
        socket.setTimeout(700, () => { socket.destroy(); resolve('blocked'); });
        socket.once('error', () => resolve('blocked'));
      });
      await new Promise(resolve => setTimeout(resolve, 2500));
      process.stdout.write(JSON.stringify(result));
    `;

    const executionPromise = run_static_provider({
      manifest: manifest(),
      executable: path.join(root, 'usr/bin/node'),
      cwd: path.join(root, 'work'),
      sandbox_root: root,
      sandbox_cgroup_parent: cgroupParent,
      isolation: 'required',
      env: { ORIX_HOST_PID: String(process.pid) },
      args: ['--input-type=module', '-e', probe],
      timeout_ms: 8_000,
      max_output_bytes: 4_096,
    });
    let providerCgroup = null;
    let observed = null;
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const entries = await child_cgroup_directories(cgroupParent);
      if (entries.length) {
        const candidate = path.join(cgroupParent, entries[0]);
        try {
          const snapshot = {
            memory: (await readFile(path.join(candidate, 'memory.max'), 'utf8')).trim(),
            swap: (await readFile(path.join(candidate, 'memory.swap.max'), 'utf8')).trim(),
            oom_group: (await readFile(path.join(candidate, 'memory.oom.group'), 'utf8')).trim(),
            pids: (await readFile(path.join(candidate, 'pids.max'), 'utf8')).trim(),
            cpu: (await readFile(path.join(candidate, 'cpu.max'), 'utf8')).trim(),
            processes: (await readFile(path.join(candidate, 'cgroup.procs'), 'utf8')).trim(),
            events: (await readFile(path.join(candidate, 'cgroup.events'), 'utf8')).trim(),
          };
          if (snapshot.processes && /populated 1/.test(snapshot.events)) {
            providerCgroup = candidate;
            observed = snapshot;
            break;
          }
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
        }
      }
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    const execution = await executionPromise;
    assert.ok(providerCgroup, 'Provider cgroup was not created');
    assert.equal(observed.memory, '536870912');
    assert.equal(observed.swap, '0');
    assert.equal(observed.oom_group, '1');
    assert.equal(observed.pids, '64');
    assert.equal(observed.cpu, '50000 100000');
    assert.match(observed.processes, /[1-9][0-9]*/);
    assert.match(observed.events, /populated 1/);
    assert.deepEqual(await child_cgroup_directories(cgroupParent), [], 'Provider cgroup was not cleaned up after exit');
    assert.equal(execution.ok, true, execution.stderr || 'Sandboxed provider failed');
    const result = JSON.parse(execution.stdout);
    assert.notEqual(result.namespace_pid, result.host_pid, 'Provider PID was not remapped into a private PID namespace');
    assert.equal(result.namespace_parent_pid, 1, 'Provider is not contained under the private PID namespace init process');
    assert.notEqual(result.host_file, 'readable', 'Provider read a host file outside its rootfs');
    assert.notEqual(result.root_write, 'writable', 'Provider modified the read-only sandbox rootfs');
    assert.equal(result.tmp_write, 'allowed', 'Ephemeral /tmp should remain writable');
    assert.equal(result.host_network, 'blocked', 'Provider reached the host loopback network');
    assert.deepEqual(result.rlimits.cpu_seconds, ['60', '60'], 'CPU RLIMIT was not inherited');
    assert.deepEqual(result.rlimits.core_bytes, ['0', '0'], 'Core dump RLIMIT was not inherited');
    assert.deepEqual(result.rlimits.file_size_bytes, ['67108864', '67108864'], 'File-size RLIMIT was not inherited');
    assert.deepEqual(result.rlimits.open_files, ['256', '256'], 'Open-file RLIMIT was not inherited');
    assert.equal(await readFile(hostSecret, 'utf8'), hostSecretValue, 'Host secret changed unexpectedly');
    process.stdout.write('Linux Bubblewrap hostile-process checks passed: filesystem, PID/network namespaces, private tmp, inherited RLIMITs, and cgroup-v2 CPU/memory/swap/PID limits.\\n');
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await rm(hostSecret, { force: true });
    await rm(base, { recursive: true, force: true });
    if (cgroupParentCreated) {
      await writeFile(path.join(cgroupParent, 'cgroup.subtree_control'), '-cpu -memory -pids');
      const remainingChildren = await child_cgroup_directories(cgroupParent);
      const parentState = {
        child_cgroups: remainingChildren,
        processes: (await readFile(path.join(cgroupParent, 'cgroup.procs'), 'utf8')).trim(),
        events: (await readFile(path.join(cgroupParent, 'cgroup.events'), 'utf8')).trim(),
        controllers: (await readFile(path.join(cgroupParent, 'cgroup.subtree_control'), 'utf8')).trim(),
      };
      process.stdout.write('Delegated cgroup cleanup state: ' + JSON.stringify(parentState) + '\\n');
      assert.deepEqual(parentState.child_cgroups, [], 'Delegated cgroup parent still contains child cgroups');
      assert.equal(parentState.processes, '', 'Delegated cgroup parent still contains processes');
      assert.match(parentState.events, /populated 0/);
      assert.equal(parentState.controllers, '', 'Delegated cgroup controllers were not disabled');
      await rmdir(cgroupParent);
    }
  }
}

await main();
