// Windows AppContainer + Job Object hostile-process integration gate.
import assert from 'node:assert/strict';
import { copyFile, mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { run_static_provider } from '../src/providers/process-runner.mjs';

function manifest() {
  return {
    contract_version: 'orix.provider.v1',
    id: 'test.windows-appcontainer',
    name: 'Windows AppContainer isolation integration test',
    version: '1.0.0',
    description: 'Hostile-process verification for AppContainer and Job Object enforcement.',
    capabilities: ['test.process'],
    supported_platforms: ['windows'],
    input_formats: ['test'],
    execution: {
      mode: 'static',
      requires_authorization: false,
      executes_target: false,
      writes_target: false,
      uses_network: false,
    },
    limits: { timeout_ms: 15_000, max_input_bytes: 1024, max_output_bytes: 16_384 },
    license: { spdx_id: 'MIT', redistribution: 'external-install' },
  };
}

async function main() {
  assert.equal(process.platform, 'win32', 'This integration gate must run on Windows');
  const base = await mkdtemp(path.join(process.cwd(), '.orix-appcontainer-integration-'));
  const root = path.join(base, 'rootfs');
  // GitHub-hosted Windows runners grant BUILTIN\\Users write access to the
  // workspace. The sandbox must not inherit that broad ACL: make the rootfs
  // private to the runner identity, SYSTEM and local Administrators before
  // creating any provider-controlled entries.
  await mkdir(root, { recursive: true });
  const runnerIdentity = execFileSync('whoami.exe', [], { encoding: 'utf8', windowsHide: true }).trim();
  const systemRoot = process.env.SystemRoot || process.env.WINDIR;
  assert.ok(systemRoot, 'Windows SystemRoot is required for the trusted ACL test helper');
  execFileSync(path.join(systemRoot, 'System32', 'icacls.exe'), [
    root, '/inheritance:r', '/grant:r',
    runnerIdentity + ':(OI)(CI)F',
    '*S-1-5-18:(OI)(CI)F',
    '*S-1-5-32-544:(OI)(CI)F',
  ], { encoding: 'utf8', windowsHide: true });
  const hostSecret = path.join(base, 'host-only-secret.txt');
  const hostSecretValue = 'host-only-secret-' + process.pid;
  let server;
  try {
    await mkdir(path.join(root, 'work'), { recursive: true });
    await mkdir(path.join(root, 'tmp'), { recursive: true });

    // An ACL that lets every local principal modify the provider rootfs must
    // be rejected by the native launcher before the AppContainer is created.
    const unsafeRoot = path.join(base, 'unsafe-rootfs');
    await mkdir(path.join(unsafeRoot, 'work'), { recursive: true });
    await mkdir(path.join(unsafeRoot, 'tmp'), { recursive: true });
    await copyFile(process.execPath, path.join(unsafeRoot, 'node.exe'));
    const systemRoot = process.env.SystemRoot || process.env.WINDIR;
    assert.ok(systemRoot, 'Windows SystemRoot is required for the trusted ACL test helper');
    execFileSync(path.join(systemRoot, 'System32', 'icacls.exe'), [
      unsafeRoot, '/grant', '*S-1-1-0:(OI)(CI)M',
    ], { encoding: 'utf8', windowsHide: true });
    const unsafeExecution = await run_static_provider({
      manifest: manifest(),
      executable: path.join(unsafeRoot, 'node.exe'),
      cwd: path.join(unsafeRoot, 'work'),
      sandbox_root: unsafeRoot,
      isolation: 'required',
      env: {},
      args: ['-e', 'process.stdout.write("must-not-run")'],
      timeout_ms: 12_000,
      max_output_bytes: 4_096,
    });
    assert.equal(unsafeExecution.ok, false, 'Windows isolation must reject an untrusted writable rootfs ACL');
    assert.match(unsafeExecution.stderr, /ORIX_WINDOWS_ROOTFS_UNTRUSTED/,
      'Native launcher did not report the rejected untrusted rootfs ACL');
    assert.equal(unsafeExecution.stdout, '', 'Provider executed despite the untrusted rootfs ACL');

    await copyFile(process.execPath, path.join(root, 'node.exe'));
    await writeFile(hostSecret, hostSecretValue, { encoding: 'utf8', mode: 0o600 });

    server = net.createServer();
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;

    const probe = `
      import fs from 'node:fs';
      import net from 'node:net';
      import os from 'node:os';
      import path from 'node:path';
      const result = {};
      result.system_root = process.env.SystemRoot || '';
      result.windir = process.env.WINDIR || '';
      try { fs.readFileSync(${JSON.stringify(hostSecret)}, 'utf8'); result.host_file = 'readable'; }
      catch (error) { result.host_file = error.code || 'blocked'; }
      try { fs.writeFileSync(path.join(process.cwd(), 'host-write-probe'), 'escape'); result.root_write = 'writable'; }
      catch (error) { result.root_write = error.code || 'blocked'; }
      result.temp_dir = os.tmpdir(); result.temp_env = process.env.TEMP; result.tmp_env = process.env.TMP; result.temp_exists = fs.existsSync(os.tmpdir());
      try { fs.writeFileSync(path.join(os.tmpdir(), 'provider-write-probe'), 'allowed'); result.tmp_write = 'allowed'; }
      catch (error) { result.tmp_write = error.code || 'blocked'; }
      const actualTemp = path.resolve(os.tmpdir()).replace(/[\\\\/]+$/, '').toLowerCase();
      const rootMarker = path.basename(path.dirname(${JSON.stringify(root)})).toLowerCase();
      const tempParts = actualTemp.split(/[\\\\/]+/);
      const markerIndex = tempParts.lastIndexOf(rootMarker);
      result.temp_path = actualTemp;
      result.tmp_inside_root = markerIndex >= 0 && tempParts[markerIndex + 1] === 'rootfs' && tempParts[markerIndex + 2] === 'tmp';
      result.host_network = await new Promise(resolve => {
        const socket = net.createConnection({ host: '127.0.0.1', port: ${port} });
        let settled = false;
        const finish = value => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          socket.destroy();
          resolve(value);
        };
        const timer = setTimeout(() => finish('blocked'), 1000);
        socket.once('connect', () => finish('connected'));
        socket.once('error', () => finish('blocked'));
      });
      process.stdout.write(JSON.stringify(result));
    `;

    const execution = await run_static_provider({
      manifest: manifest(),
      executable: path.join(root, 'node.exe'),
      cwd: path.join(root, 'work'),
      sandbox_root: root,
      isolation: 'required',
      env: { ORIX_HOST_PID: String(process.pid) },
      args: ['--input-type=module', '-e', probe],
      timeout_ms: 12_000,
      max_output_bytes: 4_096,
    });
    assert.equal(execution.ok, true, JSON.stringify({
      duration_ms: execution.duration_ms,
      exit_code: execution.exit_code,
      signal: execution.signal,
      termination_reason: execution.termination_reason,
      stdout: execution.stdout,
      stderr: execution.stderr,
    }));
    assert.match(execution.stderr, /ORIX_WINDOWS_APPCONTAINER=1;JOB_CPU_RATE=5000;JOB_MEMORY=536870912;JOB_ACTIVE_PROCESSES=64/,
      'AppContainer token and Job Object limits were not confirmed by the native launcher');
    const result = JSON.parse(execution.stdout);
    assert.ok(result.system_root, 'Provider did not receive the trusted SystemRoot required by the Windows runtime');
    assert.equal(result.windir.toLowerCase(), result.system_root.toLowerCase(), 'WINDIR and SystemRoot disagree');
    assert.notEqual(result.host_file, 'readable', 'Provider read a host file outside its rootfs');
    assert.notEqual(result.root_write, 'writable', 'Provider modified the read-only sandbox rootfs');
    assert.equal(result.temp_exists, true, JSON.stringify(result));
    assert.equal(result.tmp_inside_root, true, JSON.stringify(result));
    assert.equal(result.tmp_write, 'allowed', JSON.stringify(result));
    assert.equal(result.host_network, 'blocked', 'Provider reached host loopback network');
    const remainingPackageScratch = await readdir(path.join(root, 'tmp', 'Packages')).catch(error => {
      if (error.code === 'ENOENT') return [];
      throw error;
    });
    assert.deepEqual(remainingPackageScratch, [],
      'Per-profile AppContainer temp files must be removed after provider teardown');
    process.stdout.write('Windows AppContainer hostile-process checks passed: token, filesystem ACLs, private temp, network isolation and Job Object quotas.\\n');
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await rm(base, { recursive: true, force: true });
  }
}

await main();
