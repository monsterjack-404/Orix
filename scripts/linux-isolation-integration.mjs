// Linux Bubblewrap hostile-process and Rizin-adapter integration gate.
// Run only on a Linux host with Bubblewrap installed.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { access, chmod, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { analyze_rizin_functions, analyze_rizin_imports } from '../src/providers/rizin.mjs';
import { run_static_provider } from '../src/providers/process-runner.mjs';
import { create_delegated_parent, remove_delegated_parent } from './linux-cgroup-v2-fixture.mjs';

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
  for (const source of paths) {
    if (executables.some(item => item.source === source)) continue;
    const destination = path.join(root, source.slice(1));
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(source, destination);
    await chmod(destination, 0o755);
  }
  return executables[0].target;
}

const RIZIN_RELEASE_VERSION = '0.9.1';
const RIZIN_STATIC_ARCHIVE_URL = 'https://github.com/rizinorg/rizin/releases/download/v0.9.1/rizin-v0.9.1-static-x86_64.tar.xz';
const RIZIN_STATIC_ARCHIVE_SHA256 = '9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf';
const RIZIN_STATIC_ARCHIVE_SIZE = 137_626_404;

async function sha256_file(file_path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file_path)) hash.update(chunk);
  return hash.digest('hex');
}

async function install_verified_upstream_rizin(root, base) {
  const archive_path = path.join(base, 'rizin-v' + RIZIN_RELEASE_VERSION + '-static-x86_64.tar.xz');
  const install_root = path.join(root, 'opt', 'rizin-static');
  await mkdir(install_root, { recursive: true });

  execFileSync('curl', [
    '--fail', '--location', '--retry', '3', '--retry-delay', '1',
    '--proto', '=https', '--proto-redir', '=https',
    '--connect-timeout', '20', '--max-time', '300',
    '--max-filesize', String(RIZIN_STATIC_ARCHIVE_SIZE),
    '--output', archive_path, RIZIN_STATIC_ARCHIVE_URL,
  ], { stdio: 'pipe', timeout: 5 * 60 * 1000 });

  const archive_info = await stat(archive_path);
  assert.equal(archive_info.size, RIZIN_STATIC_ARCHIVE_SIZE, 'Official Rizin static archive size changed');
  assert.equal(
    await sha256_file(archive_path),
    RIZIN_STATIC_ARCHIVE_SHA256,
    'Official Rizin static archive SHA-256 mismatch',
  );

  const members = execFileSync('tar', ['-tJf', archive_path], {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  }).split(/\r?\n/).filter(Boolean);
  assert.ok(members.length > 0, 'Official Rizin archive must not be empty');
  for (const member of members) {
    const normalized = member.replace(/^\.\//, '');
    assert.equal(path.posix.isAbsolute(normalized), false, 'Rizin archive contains an absolute path');
    assert.equal(normalized.split('/').includes('..'), false, 'Rizin archive contains a parent traversal path');
    assert.equal(normalized.includes('\0'), false, 'Rizin archive contains a NUL path');
  }

  execFileSync('tar', [
    '-xJf', archive_path,
    '-C', install_root,
    '--no-same-owner',
    '--no-same-permissions',
  ], { stdio: 'pipe', timeout: 5 * 60 * 1000 });

  const executable = path.join(install_root, 'bin', 'rizin');
  const executable_info = await lstat(executable);
  assert.equal(executable_info.isSymbolicLink(), false, 'Rizin executable must not be a symlink');
  assert.equal(executable_info.isFile(), true, 'Rizin executable must be a regular file');
  await access(executable, 1);
  const canonical = await realpath(executable);
  const relative = path.relative(install_root, canonical);
  assert.equal(relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative), false,
    'Resolved Rizin executable escaped its installed prefix');
  process.stdout.write('Verified upstream Rizin ' + RIZIN_RELEASE_VERSION +
    ' static archive: official release SHA-256 matched and portable prefix installed in the sandbox rootfs.\n');
  return canonical;
}

async function verify_real_upstream_rizin_under_bubblewrap(root, base) {
  const executable = await install_verified_upstream_rizin(root, base);
  const source_path = path.join(base, 'orix-rizin-real-target.c');
  const input_path = path.join(base, 'orix-rizin-real-target.elf');
  await writeFile(source_path, [
    '#include <stdio.h>',
    '__attribute__((noinline)) int orix_rizin_probe_symbol(int value) { return value + 42; }',
    'int main(void) { puts("ORIX real Rizin + Bubblewrap integration"); return orix_rizin_probe_symbol(0) == 42 ? 0 : 1; }',
    '',
  ].join('\n'));
  execFileSync('cc', [
    '-O0', '-g', '-fno-pie', '-no-pie', '-fno-omit-frame-pointer',
    '-o', input_path, source_path,
  ], { stdio: 'pipe', timeout: 30_000 });

  const common = {
    executable,
    input_path,
    cwd: root,
    isolation: 'required',
    sandbox_root: root,
    timeout_ms: 60_000,
    max_output_bytes: 2 * 1024 * 1024,
  };

  const imports = await analyze_rizin_imports(common);
  assert.equal(imports.provider.engine_version, RIZIN_RELEASE_VERSION,
    'ORIX must execute the pinned real upstream Rizin release inside Bubblewrap');
  assert.equal(imports.artifact.stable_during_analysis, true);
  assert.ok(imports.summary.imports > 0, 'Real Rizin must return a non-empty ELF import table');
  assert.ok(imports.imports.some(item => item.name === 'puts'),
    'Real Rizin must identify the sample ELF puts import');

  const inventory = await analyze_rizin_functions(common);
  assert.equal(inventory.provider.engine_version, RIZIN_RELEASE_VERSION);
  assert.ok(inventory.functions.length > 0, 'Real Rizin must return a non-empty function inventory');
  // Rizin versions and analysis heuristics can give entry points different
  // names. Use a known sample symbol when present; otherwise use the first
  // real function entry returned by the upstream engine.
  const selected_function = inventory.functions.find(item =>
    item.name === 'main' || item.name === 'sym.main' ||
    item.name.endsWith('orix_rizin_probe_symbol')) ?? inventory.functions[0];
  assert.ok(selected_function, 'Real Rizin must return at least one selectable function entry');

  const disassembly = await analyze_rizin_functions({
    ...common,
    address: selected_function.offset,
    max_instructions: 8,
  });
  assert.equal(disassembly.provider.engine_version, RIZIN_RELEASE_VERSION);
  assert.equal(disassembly.disassembly.address, selected_function.offset);
  assert.ok(disassembly.disassembly.instructions.length > 0,
    'Real Rizin must return actual disassembly at a discovered function entry');
  assert.equal(disassembly.artifact.stable_during_analysis, true);

  const leftovers = (await readdir(root)).filter(name => name.startsWith('.orix-rizin-'));
  assert.deepEqual(leftovers, [], 'Real Rizin private snapshots must be removed after successful isolated analysis');
  process.stdout.write('Real upstream Rizin ' + RIZIN_RELEASE_VERSION +
    ' + Bubblewrap passed: version, ELF imports, function inventory, bounded disassembly, stable input digest and snapshot cleanup.\n');
}

async function verify_rizin_adapter_under_bubblewrap(root, node_path, base) {
  const fixture_source = new URL('../tests/fixtures/rizin-stub.mjs', import.meta.url);
  const fixture_path = path.join(root, 'work', 'rizin-stub.mjs');
  const config_path = path.join(root, 'work', 'rizin-stub-config.json');
  const input_path = path.join(base, 'rizin-bubblewrap-input.bin');
  await copyFile(fixture_source, fixture_path);
  await writeFile(config_path, '{}', { mode: 0o400 });
  await writeFile(input_path, Buffer.from('ORIX Rizin Bubblewrap integration fixture'));

  const common = {
    executable: node_path,
    executable_args: ['/work/rizin-stub.mjs', '/work/rizin-stub-config.json'],
    input_path,
    isolation: 'required',
    sandbox_root: root,
    timeout_ms: 8_000,
    max_output_bytes: 16_384,
  };

  const imports = await analyze_rizin_imports(common);
  assert.equal(imports.provider.engine_version, '0.8.2');
  assert.equal(imports.artifact.stable_during_analysis, true);
  assert.equal(imports.summary.imports, 2);
  assert.equal(imports.imports[0].name, 'puts');
  assert.equal(imports.imports[0].library, 'libc.so.6');

  const functions = await analyze_rizin_functions({
    ...common,
    address: '0x401000',
    max_instructions: 3,
    decompile: true,
  });
  assert.equal(functions.provider.engine_version, '0.8.2');
  assert.equal(functions.functions.length, 1);
  assert.equal(functions.disassembly.instructions.length, 3);
  assert.equal(functions.decompilation.backend, 'rizin-pdg');
  assert.match(functions.decompilation.source, /int main/);

  const leftovers = (await readdir(root)).filter(name => name.startsWith('.orix-rizin-'));
  assert.deepEqual(leftovers, [], 'Rizin private snapshots must be removed after successful isolated analysis');
  process.stdout.write('Rizin adapter + Bubblewrap integration passed: version, imports, function inventory, disassembly, decompilation fixture, and snapshot cleanup.\n');
}

async function main() {
  assert.equal(process.platform, 'linux', 'This integration gate must run on Linux');
  const base = await mkdtemp(path.join(os.tmpdir(), 'orix-bwrap-integration-'));
  const delegated = await create_delegated_parent();
  process.env.ORIX_CGROUP_PARENT = delegated.parent;
  const root = path.join(base, 'rootfs');
  const hostSecret = path.join(os.tmpdir(), 'orix-host-secret-' + process.pid);
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

    const probe = [
      "import fs from 'node:fs';",
      "import net from 'node:net';",
      "import { spawnSync } from 'node:child_process';",
      'const result = { namespace_pid: process.pid, namespace_parent_pid: process.ppid, host_pid: Number(process.env.ORIX_HOST_PID) };',
      "const nested_userns = spawnSync('/usr/bin/unshare', ['--user', '--map-root-user', '/usr/bin/node', '-e', 'process.exit(0)'], { encoding: 'utf8', timeout: 1500 });",
      "result.nested_userns = nested_userns.error?.code === 'ENOENT' ? 'probe-missing' : nested_userns.status === 0 ? 'allowed' : 'blocked';",
      'try { fs.readFileSync(' + JSON.stringify(hostSecret) + ", 'utf8'); result.host_file = 'readable'; }",
      "catch (error) { result.host_file = error.code || 'blocked'; }",
      "try { fs.writeFileSync('/work/host-write-probe', 'escape'); result.root_write = 'writable'; }",
      "catch (error) { result.root_write = error.code || 'blocked'; }",
      "try { fs.writeFileSync('/tmp/provider-write-probe', 'allowed'); result.tmp_write = 'allowed'; }",
      "catch (error) { result.tmp_write = error.code || 'blocked'; }",
      'result.host_network = await new Promise(resolve => {',
      "  const socket = net.createConnection({ host: '127.0.0.1', port: " + String(port) + " }, () => {",
      "    socket.destroy(); resolve('connected');",
      '  });',
      "  socket.setTimeout(700, () => { socket.destroy(); resolve('blocked'); });",
      "  socket.once('error', () => resolve('blocked'));",
      '});',
      'process.stdout.write(JSON.stringify(result));',
    ].join('\n');

    const execution = await run_static_provider({
      manifest: manifest(),
      executable: nodePath,
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
    assert.equal(result.nested_userns, 'blocked', 'Provider can still create nested user namespaces');
    assert.equal(result.namespace_parent_pid, 1, 'Provider is not contained under the private PID namespace init process');
    assert.notEqual(result.host_file, 'readable', 'Provider read a host file outside its rootfs');
    assert.notEqual(result.root_write, 'writable', 'Provider modified the read-only sandbox rootfs');
    assert.equal(result.tmp_write, 'allowed', 'Ephemeral /tmp should remain writable');
    assert.equal(result.host_network, 'blocked', 'Provider reached the host loopback network');
    assert.equal(await readFile(hostSecret, 'utf8'), hostSecretValue, 'Host secret changed unexpectedly');
    process.stdout.write('Linux Bubblewrap hostile-process checks passed: host file denied, rootfs read-only, private /tmp writable, host loopback unreachable, nested user namespaces disabled.\n');

    await verify_rizin_adapter_under_bubblewrap(root, nodePath, base);
    await verify_real_upstream_rizin_under_bubblewrap(root, base);
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    try {
      await rm(hostSecret, { force: true });
      await rm(base, { recursive: true, force: true });
    } finally {
      await remove_delegated_parent(delegated);
    }
  }
}

await main();
