// Linux Bubblewrap hostile-process integration gate. Run only on a Linux host with Bubblewrap installed.
import assert from 'node:assert/strict';
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { run_static_provider } from '../src/providers/process-runner.mjs';

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
  const executables = [
    { source: process.execPath, target: path.join(root, 'usr/bin/node') },
    { source: '/usr/bin/unshare', target: path.join(root, 'usr/bin/unshare') },
  ];
  const paths = new Set();
  for (const item of executables) {
    paths.add(item.source);
    const dependencies = execFileSync('ldd', [item.source], { encoding: 'utf8' });
    for (const line of dependencies.split('\n')) {
      const match = line.match(/(?:=>\s*)?(\/\S+)\s+\(/);
      if (match) paths.add(match[1]);
    }
    await copyFile(item.source, item.target);
    await chmod(item.target, 0o755);
  }
  const nodePath = executables[0].target;
  for (const source of paths) {
    if (executables.some(item => item.source === source)) continue;
    const destination = path.join(root, source.slice(1));
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(source, destination);
    await chmod(destination, 0o755);
  }
  return nodePath;
}

async function main() {
  assert.equal(process.platform, 'linux', 'This integration gate must run on Linux');
  const base = await mkdtemp(path.join(os.tmpdir(), 'orix-bwrap-integration-'));
  const root = path.join(base, 'rootfs');
  const hostSecret = path.join(os.tmpdir(), 'orix-host-secret-' + process.pid);
  const hostSecretValue = 'host-only-secret-' + process.pid;
  let server;
  try {
    await mkdir(root);
    await make_minimal_rootfs(root);
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
      import { spawnSync } from 'node:child_process';
      const result = { namespace_pid: process.pid, namespace_parent_pid: process.ppid, host_pid: Number(process.env.ORIX_HOST_PID) };
      const nested_userns = spawnSync('/usr/bin/unshare', ['--user', '--map-root-user', '/usr/bin/node', '-e', 'process.exit(0)'], { encoding: 'utf8', timeout: 1500 });
      const nested_userns_denied = /(?:operation not permitted|permission denied)/i.test(nested_userns.stderr || '');
      result.nested_userns = nested_userns.error || nested_userns.status === null
        ? 'probe-error'
        : nested_userns.status === 0 ? 'allowed'
        : nested_userns_denied ? 'blocked' : 'probe-unexpected-failure';
      result.nested_userns_diagnostic = {
        status: nested_userns.status,
        signal: nested_userns.signal,
        error: nested_userns.error?.code ?? null,
        stderr: (nested_userns.stderr || '').trim().slice(0, 500),
      };
      try { fs.readFileSync(${JSON.stringify(hostSecret)}, 'utf8'); result.host_file = 'readable'; }
      catch (error) { result.host_file = error.code || 'blocked'; }
      try { fs.writeFileSync('/work/host-write-probe', 'escape'); result.root_write = 'writable'; }
      catch (error) { result.root_write = error.code || 'blocked'; }
      try { fs.writeFileSync('/tmp/provider-write-probe', 'allowed'); result.tmp_write = 'allowed'; }
      catch (error) { result.tmp_write = error.code || 'blocked'; }
      result.host_network = await new Promise(resolve => {
        const socket = net.createConnection({ host: '127.0.0.1', port: ${port} }, () => {
          socket.destroy(); resolve('connected');
        });
        socket.setTimeout(700, () => { socket.destroy(); resolve('blocked'); });
        socket.once('error', () => resolve('blocked'));
      });
      process.stdout.write(JSON.stringify(result));
    `;

    const execution = await run_static_provider({
      manifest: manifest(),
      executable: path.join(root, 'usr/bin/node'),
      cwd: path.join(root, 'work'),
      sandbox_root: root,
      isolation: 'required',
      env: { ORIX_HOST_PID: String(process.pid) },
      args: ['--input-type=module', '-e', probe],
      timeout_ms: 8_000,
      max_output_bytes: 4_096,
    });
    assert.equal(execution.ok, true, execution.stderr || 'Sandboxed provider failed');
    const result = JSON.parse(execution.stdout);
    assert.notEqual(result.namespace_pid, result.host_pid, 'Provider PID was not remapped into a private PID namespace');
    assert.equal(
      result.nested_userns,
      'blocked',
      `Nested user-namespace probe must exit non-zero; provider may still create nested user namespaces (diagnostic: ${result.nested_userns_diagnostic ?? 'none'})`,
    );
    assert.equal(result.namespace_parent_pid, 1, 'Provider is not contained under the private PID namespace init process');
    assert.notEqual(result.host_file, 'readable', 'Provider read a host file outside its rootfs');
    assert.notEqual(result.root_write, 'writable', 'Provider modified the read-only sandbox rootfs');
    assert.equal(result.tmp_write, 'allowed', 'Ephemeral /tmp should remain writable');
    assert.equal(result.host_network, 'blocked', 'Provider reached the host loopback network');
    assert.equal(await readFile(hostSecret, 'utf8'), hostSecretValue, 'Host secret changed unexpectedly');
    process.stdout.write('Linux Bubblewrap hostile-process checks passed: host file denied, rootfs read-only, private /tmp writable, host loopback unreachable, nested user namespaces disabled.\n');
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await rm(hostSecret, { force: true });
    await rm(base, { recursive: true, force: true });
  }
}

await main();
