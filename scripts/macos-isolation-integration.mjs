// macOS Seatbelt hostile-process integration gate.
import assert from 'node:assert/strict';
import { chmod, copyFile, mkdir, mkdtemp, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { run_static_provider } from '../src/providers/process-runner.mjs';
import { prepare_macos_provider_isolation } from '../src/providers/macos-isolation.mjs';

function manifest() {
  return {
    contract_version: 'orix.provider.v1',
    id: 'test.macos-seatbelt',
    name: 'macOS Seatbelt isolation integration test',
    version: '1.0.0',
    description: 'Hostile-process verification for Seatbelt filesystem and network restrictions.',
    capabilities: ['test.process'],
    supported_platforms: ['macos'],
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

async function copy_node_runtime(root) {
  const bin = path.join(root, 'bin');
  const lib = path.join(root, 'lib');
  await mkdir(bin, { recursive: true });
  await mkdir(lib, { recursive: true });
  const destination = path.join(bin, 'node');
  await copyFile(process.execPath, destination);
  await chmod(destination, 0o755);
  const sourceLib = path.resolve(path.dirname(process.execPath), '..', 'lib');
  try {
    for (const name of await readdir(sourceLib)) {
      if (name.endsWith('.dylib')) await copyFile(path.join(sourceLib, name), path.join(lib, name));
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const dependencies = execFileSync('/usr/bin/otool', ['-L', process.execPath], { encoding: 'utf8' });
  const bundledLibraries = new Set(await readdir(lib));
  for (const line of dependencies.split('\n').slice(1)) {
    const dependency = line.trim().split(/\s+/)[0];
    if (dependency.startsWith('@rpath/')) {
      const libraryName = path.basename(dependency);
      assert.equal(bundledLibraries.has(libraryName), true,
        'Missing Node runtime library in rootfs/lib: ' + libraryName + '\n' + dependencies);
    }
  }
  return destination;
}

async function main() {
  assert.equal(process.platform, 'darwin', 'This integration gate must run on macOS');
  const base = await mkdtemp(path.join(os.tmpdir(), 'orix-seatbelt-integration-'));
  const root = path.join(base, 'rootfs');
  const hostSecret = path.join(base, 'host-only-secret.txt');
  const hostSecretValue = 'host-only-secret-' + process.pid;
  let server;
  try {
    await mkdir(path.join(root, 'work'), { recursive: true });
    await mkdir(path.join(root, 'tmp'), { recursive: true });

    // The canonical rootfs and every ancestor must resist untrusted writers.
    const unsafeRoot = path.join(base, 'unsafe-rootfs');
    await mkdir(path.join(unsafeRoot, 'tmp'), { recursive: true });
    await mkdir(path.join(unsafeRoot, 'work'), { recursive: true });
    await chmod(unsafeRoot, 0o777);
    await assert.rejects(
      prepare_macos_provider_isolation({
        executable: process.execPath,
        cwd: path.join(unsafeRoot, 'work'),
        sandbox_root: unsafeRoot,
        args: [],
        env: {},
      }),
      error => error.code === 'ORIX_PROVIDER_SANDBOX_ROOT_UNTRUSTED',
      'macOS isolation must reject a group/other-writable rootfs',
    );
    await chmod(unsafeRoot, 0o700);
    await rm(unsafeRoot, { recursive: true, force: true });

    const unsafeParent = path.join(base, 'unsafe-parent');
    const unsafeParentRoot = path.join(unsafeParent, 'rootfs');
    await mkdir(path.join(unsafeParentRoot, 'tmp'), { recursive: true });
    await mkdir(path.join(unsafeParentRoot, 'work'), { recursive: true });
    await chmod(unsafeParent, 0o700);
    await chmod(base, 0o777);
    try {
      await assert.rejects(
        prepare_macos_provider_isolation({
          executable: process.execPath,
          cwd: path.join(unsafeParentRoot, 'work'),
          sandbox_root: unsafeParentRoot,
          args: [],
          env: {},
        }),
        error => error.code === 'ORIX_PROVIDER_SANDBOX_ROOT_UNTRUSTED',
        'macOS isolation must reject a group/other-writable rootfs ancestor',
      );
    } finally {
      await chmod(base, 0o700);
      await rm(unsafeParent, { recursive: true, force: true });
    }

    const executable = await copy_node_runtime(root);
    const canonicalScratch = await realpath(path.join(root, 'tmp'));
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
      try { fs.writeFileSync(path.join(os.tmpdir(), 'provider-write-probe'), 'allowed'); result.tmp_write = 'allowed'; }
      catch (error) { result.tmp_write = error.code || 'blocked'; }
      result.tmp_inside_root = path.resolve(os.tmpdir()) === ${JSON.stringify(canonicalScratch)};
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
      executable,
      cwd: path.join(root, 'work'),
      sandbox_root: root,
      isolation: 'required',
      // Host compiler must ignore caller-controlled SDK/toolchain/temp overrides.
      env: {
        ORIX_HOST_PID: String(process.pid),
        SDKROOT: path.join(base, 'attacker-controlled-sdk'),
        DEVELOPER_DIR: path.join(base, 'attacker-controlled-developer-dir'),
        TMPDIR: path.join(base, 'attacker-controlled-tmp'),
        TOOLCHAINS: path.join(base, 'attacker-controlled-toolchains'),
      },
      args: ['--input-type=module', '-e', probe],
      timeout_ms: 12_000,
      max_output_bytes: 4_096,
    });
    assert.equal(execution.ok, true, JSON.stringify({
      duration_ms: execution.duration_ms,
      exit_code: execution.exit_code,
      signal: execution.signal,
      stdout: execution.stdout,
      stderr: execution.stderr,
    }));
    assert.match(execution.stderr, /ORIX_MACOS_SEATBELT=1;RLIMIT_CPU=60;RLIMIT_FSIZE=67108864;RLIMIT_NOFILE=256;RLIMIT_CORE=0/,
      'Kernel Seatbelt and inherited RLIMIT controls were not confirmed');
    const result = JSON.parse(execution.stdout);
    assert.notEqual(result.host_file, 'readable', 'Provider read a host file outside its rootfs');
    assert.notEqual(result.root_write, 'writable', 'Provider modified the read-only sandbox rootfs');
    assert.equal(result.tmp_write, 'allowed', 'Private rootfs tmp should remain writable');
    assert.equal(result.tmp_inside_root, true, 'TMPDIR was not confined to sandbox_root/tmp');
    assert.equal(result.host_network, 'blocked', 'Provider reached host loopback network');
    assert.equal(await (await import('node:fs/promises')).readFile(hostSecret, 'utf8'), hostSecretValue);
    process.stdout.write('macOS Seatbelt hostile-process checks passed: kernel sandbox, filesystem, private tmp, network and RLIMITs.\\n');
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await rm(base, { recursive: true, force: true });
  }
}

await main();
