// Windows AppContainer + Job Object hostile-process integration gate.
import assert from 'node:assert/strict';
import { copyFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
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
  const base = await mkdtemp(path.join(os.tmpdir(), 'orix-appcontainer-integration-'));
  const root = path.join(base, 'rootfs');
  const hostSecret = path.join(base, 'host-only-secret.txt');
  const hostSecretValue = 'host-only-secret-' + process.pid;
  let server;
  try {
    await mkdir(path.join(root, 'work'), { recursive: true });
    await mkdir(path.join(root, 'tmp'), { recursive: true });
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
      try { fs.readFileSync(${JSON.stringify(hostSecret)}, 'utf8'); result.host_file = 'readable'; }
      catch (error) { result.host_file = error.code || 'blocked'; }
      try { fs.writeFileSync(path.join(process.cwd(), 'host-write-probe'), 'escape'); result.root_write = 'writable'; }
      catch (error) { result.root_write = error.code || 'blocked'; }
      result.temp_dir = os.tmpdir(); result.temp_env = process.env.TEMP; result.tmp_env = process.env.TMP; result.temp_exists = fs.existsSync(os.tmpdir());
      try { fs.writeFileSync(path.join(os.tmpdir(), 'provider-write-probe'), 'allowed'); result.tmp_write = 'allowed'; }
      catch (error) { result.tmp_write = error.code || 'blocked'; }
      const scratchRoot = path.resolve(${JSON.stringify(path.join(root, 'tmp'))}).replace(/[\\\\/]+$/, '').toLowerCase();
      const actualTemp = path.resolve(os.tmpdir()).replace(/[\\\\/]+$/, '').toLowerCase();
      const relativeTemp = path.relative(scratchRoot, actualTemp);
      result.scratch_root = scratchRoot;
      result.temp_path = actualTemp;
      result.tmp_inside_root = relativeTemp === '' || (relativeTemp !== '..' && !relativeTemp.startsWith('..' + path.sep) && !path.isAbsolute(relativeTemp));      result.host_network = await new Promise(resolve => {
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
    assert.notEqual(result.host_file, 'readable', 'Provider read a host file outside its rootfs');
    assert.notEqual(result.root_write, 'writable', 'Provider modified the read-only sandbox rootfs');
    assert.equal(result.temp_exists, true, JSON.stringify(result));
    assert.equal(result.tmp_inside_root, true, JSON.stringify(result));
    assert.equal(result.tmp_write, 'allowed', JSON.stringify(result));
    assert.equal(result.host_network, 'blocked', 'Provider reached host loopback network');
    process.stdout.write('Windows AppContainer hostile-process checks passed: token, filesystem ACLs, private temp, network isolation and Job Object quotas.\\n');
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await rm(base, { recursive: true, force: true });
  }
}

await main();
