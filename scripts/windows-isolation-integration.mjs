// Windows AppContainer + Job Object hostile-process integration gate.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { access, copyFile, link, lstat, mkdir, mkdtemp, readFile, readdir, rm, rmdir, symlink, writeFile } from 'node:fs/promises';
import { execFileSync, spawn } from 'node:child_process';
import net from 'node:net';
import os_host from 'node:os';
import path from 'node:path';
import { run_static_provider } from '../src/providers/process-runner.mjs';
import { prepare_windows_provider_isolation } from '../src/providers/windows-isolation.mjs';
import { decodeWindowsProviderLauncher, WINDOWS_PROVIDER_LAUNCHER_SHA256 } from '../src/providers/windows-launcher-integrity.mjs';

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
  const launcherSource = await readFile(new URL('../native/windows-provider-launcher.cs', import.meta.url), 'utf8');
  assert.match(launcherSource, /GetSystemDirectoryW/,
    'Native helper must resolve security-sensitive Windows utilities through the OS API');
  assert.match(launcherSource, /if \(!process\.WaitForExit\(10000\)\)[\s\S]*?process\.Kill\(\)[\s\S]*?process\.WaitForExit\(\)[\s\S]*?throw new TimeoutException/,
    'Timed-out icacls must be observed exited before helper cleanup can mutate its target');
  assert.match(launcherSource, /static void TerminateAndWaitForProvider[\s\S]*?WaitForSingleObject\(job, 5000\)/,
    'Provider teardown must wait for the assigned Job Object to become empty');
  assert.match(launcherSource, /static void TerminateAndWaitForProvider[\s\S]*?WaitForSingleObject\(processHandle, 5000\)/,
    'A provider process created before Job Object assignment must be terminated and observed exited');
  assert.ok(launcherSource.includes('RUN:TEARDOWN_INCOMPLETE') &&
    launcherSource.includes('ProviderTeardownIncompleteException'),
    'Unverified process teardown must be surfaced as a distinct fail-closed result');
  assert.match(launcherSource, /catch \(ProviderTeardownIncompleteException error\)[\s\S]*?return 125/,
    'Native Main must skip AppContainer cleanup when process-tree emptiness was not confirmed');

  assert.match(launcherSource,
    /FileSystemRights volumeRootDestructiveMask = FileSystemRights\.DeleteSubdirectoriesAndFiles \|[\s\S]*?FileSystemRights deniedRights = rootfsComponent[\s\S]*?volumeRootComponent \? volumeRootDestructiveMask : ancestorDestructiveMask;/,
    'Volume-root ACLs must ignore non-actionable DELETE on the volume object while rejecting DELETE_CHILD and ACL/ownership mutation');
  const purgeStart = launcherSource.indexOf('static void PurgeTree(');
  const deleteStart = launcherSource.indexOf('static void DeleteTreeNoReparse(', purgeStart);
  assert.ok(purgeStart >= 0 && deleteStart > purgeStart,
    'Native helper must retain an explicit AppContainer cleanup tree walker');
  const purgeSource = launcherSource.slice(purgeStart, deleteStart);
  assert.match(purgeSource, /File\.GetAttributes\(path\)/,
    'Cleanup must inspect each directory entry before descending');
  assert.doesNotMatch(purgeSource, /File\.Exists\(path\)|Directory\.Exists\(path\)/,
    'Cleanup must not use path existence helpers that can follow a reparse target');
  assert.match(purgeSource, /FileAttributes\.ReparsePoint[\s\S]*?throw new InvalidOperationException\("ORIX_WINDOWS_CLEANUP_REPARSE_POINT/,
    'Cleanup must abort on reparse points instead of skipping them and continuing with descendant paths');
  const cleanupStart = launcherSource.indexOf('public static void Cleanup(');
  assert.ok(cleanupStart >= 0, 'Native helper must expose the explicit profile cleanup path');
  const cleanupSource = launcherSource.slice(cleanupStart);
  assert.match(cleanupSource, /DeriveAppContainerSidFromAppContainerName\(profileName, out sid\)[\s\S]*?if \(hr != 0\) Marshal\.ThrowExceptionForHR\(hr\)/,
    'AppContainer SID lookup errors must fail cleanup instead of being treated as profile absence');
  assert.doesNotMatch(cleanupSource, /ORIX_CLEANUP:NO_PROFILE/,
    'Cleanup must not silently report success for an arbitrary SID lookup failure');


  assert.ok(launcherSource.includes('DuplicateHandle(') &&
    launcherSource.includes('DUPLICATE_SAME_ACCESS'),
    'Native helper must duplicate standard handles instead of changing the host handle table');
  assert.ok(
    launcherSource.includes('DuplicateStandardHandle(GetStdHandle(-10), "stdin", inheritedStandardHandles)') &&
    launcherSource.includes('DuplicateStandardHandle(GetStdHandle(-11), "stdout", inheritedStandardHandles)') &&
    launcherSource.includes('DuplicateStandardHandle(GetStdHandle(-12), "stderr", inheritedStandardHandles)'),
    'The child must receive dedicated duplicates of stdin, stdout and stderr');
  assert.ok(launcherSource.includes('PROC_THREAD_ATTRIBUTE_HANDLE_LIST'),
    'The child handle inheritance must remain restricted to the explicit standard-handle list');
  assert.equal(launcherSource.includes('SetHandleInformation('), false,
    'The helper must not alter inheritance flags on the host process standard handles');
  assert.ok(launcherSource.includes('foreach (IntPtr inheritedHandle in inheritedStandardHandles)') &&
    launcherSource.includes('CloseHandle(inheritedHandle)'),
    'The helper must close its temporary standard-handle duplicates during teardown');
  assert.doesNotMatch(launcherSource, /Environment\.GetEnvironmentVariable\("SystemRoot"\)/,
    'Native helper must not resolve icacls.exe from inherited SystemRoot');
  const isolationSource = await readFile(new URL('../src/providers/windows-isolation.mjs', import.meta.url), 'utf8');
  assert.match(isolationSource, /normalizedKey === 'systemroot' \|\| normalizedKey === 'windir'/,
    'Provider environment overrides must not replace reserved Windows runtime identity keys');
  assert.match(isolationSource, /const trustedSystemRoot = \[process\.env\.SystemRoot, process\.env\.WINDIR\]\.find\(value => typeof value === 'string' && value\.trim\(\)\.length > 0\);[\s\S]*?providerEnvironment\.SystemRoot = trustedSystemRoot;[\s\S]*?providerEnvironment\.WINDIR = trustedSystemRoot;/,
    'Windows runtime identity must be restored from the first non-empty trusted host value after provider overrides');
  assert.doesNotMatch(isolationSource, /resolve_csc|csc\.exe|windows-provider-launcher\.cs/,
    'Windows runtime must not discover a compiler or compile native helper source');
  assert.match(isolationSource, /decodeWindowsProviderLauncher/,
    'Windows runtime must load the prebuilt source-pinned launcher');
  assert.match(isolationSource, /RUN:TEARDOWN_INCOMPLETE[\s\S]*?ORIX_PROVIDER_WINDOWS_TEARDOWN_UNVERIFIED/,
    'Host cleanup must refuse to traverse AppContainer state after unverified provider teardown');
  const packagedPayload = await readFile(new URL('../native/bin/win32-anycpu/orix-windows-provider-launcher.exe.gz', import.meta.url));
  const packagedLauncher = decodeWindowsProviderLauncher(packagedPayload);
  assert.equal(createHash('sha256').update(packagedLauncher).digest('hex'), WINDOWS_PROVIDER_LAUNCHER_SHA256,
    'Packaged Windows launcher does not match its source-pinned digest');
  assert.match(isolationSource, /child\.once\('close'/,
    'Native helper timeout handling must wait until the helper process and stdio handles are closed');
  assert.doesNotMatch(isolationSource, /child\.once\('exit'/,
    'Native helper lifecycle must use close, not exit, before temporary-directory cleanup');
  assert.match(isolationSource, /timedOut = true;[\s\S]*?child\.kill\(\);[\s\S]*?child\.once\('close'/,
    'Native helper timeout must terminate the helper and defer rejection until close');
  const timeoutRequest = isolationSource.indexOf('timedOut = true;');
  const killRequest = isolationSource.indexOf('child.kill();', timeoutRequest);
  const closeHandler = isolationSource.indexOf("child.once('close', async (code, signal) => {", killRequest);
  const timeoutFailure = isolationSource.indexOf('ORIX_PROVIDER_WINDOWS_HELPER_TIMEOUT', closeHandler);
  assert.ok(timeoutRequest >= 0 && killRequest > timeoutRequest &&
    closeHandler > killRequest && timeoutFailure > closeHandler,
  'Windows helper timeout must wait for stdio close before caller cleanup and log collection');
  // Keep the rootfs outside the broadly writable GitHub Actions workspace; its
  // ancestors are part of the native trust check, not just the leaf ACL.
  // Use a protected system directory, not the GitHub workspace or user profile.
  // The native trust check intentionally examines every ancestor: a writable
  // parent would let another local principal replace the sandbox rootfs.
  const trustedParent = process.env.ProgramFiles;
  assert.ok(trustedParent && path.isAbsolute(trustedParent),
    'ProgramFiles must identify the protected Windows installation directory');
  const base = await mkdtemp(path.join(trustedParent, 'ORIX-AppContainer-'));
  const root = path.join(base, 'rootfs');
  // GitHub-hosted Windows runners grant BUILTIN\\Users write access to the
  // workspace. The sandbox must not inherit that broad ACL: make the rootfs
  // private to the runner identity, SYSTEM and local Administrators before
  // creating any provider-controlled entries.
  await mkdir(root, { recursive: true });
  const runnerIdentity = execFileSync('whoami.exe', [], { encoding: 'utf8', windowsHide: true }).trim();
  const systemRoot = process.env.SystemRoot || process.env.WINDIR;
  assert.ok(systemRoot, 'Windows SystemRoot is required for the trusted ACL test helper');
  // Protect the fixture parent as well as rootfs: the outside-rootfs
  // secret lives beside rootfs and must not inherit broad BUILTIN\\Users read
  // access from Program Files.
  for (const directory of [base, root]) {
    execFileSync(path.join(systemRoot, 'System32', 'icacls.exe'), [
      directory, '/inheritance:r', '/grant:r',
      runnerIdentity + ':(OI)(CI)F',
      '*S-1-5-18:(OI)(CI)F',
      '*S-1-5-32-544:(OI)(CI)F',
    ], { encoding: 'utf8', windowsHide: true });
  }
  // Store the sentinel in the runner user's private profile, not under
  // Program Files where broad read ACLs may be inherited by AppContainers.
  const hostSecret = path.join(os_host.homedir(), 'orix-host-only-secret-' + process.pid + '.txt');
  const hostSecretValue = 'host-only-secret-' + process.pid;
  let server;
  try {
    await mkdir(path.join(root, 'work'), { recursive: true });
    await mkdir(path.join(root, 'tmp'), { recursive: true });
    // The normal rootfs runtime must exist before both negative ACL probes.
    await copyFile(process.execPath, path.join(root, 'node.exe'));

    // A failed native process-tree wait must block the later host-driven
    // cleanup helper. Simulate the durable teardown marker before any profile
    // has been created; cleanup must not launch a second helper or erase it.
    const blockedTeardown = await prepare_windows_provider_isolation({
      executable: path.join(root, 'node.exe'),
      cwd: path.join(root, 'work'),
      sandbox_root: root,
      args: ['-e', 'process.exit(0)'],
      env: {},
    });
    const blockedTeardownLog = path.join(blockedTeardown.cwd, 'provider.log');
    const teardownMarker = 'RUN:TEARDOWN_INCOMPLETE:simulated wait failure\\n';
    await writeFile(blockedTeardownLog, teardownMarker, 'utf8');
    await assert.rejects(
      blockedTeardown.cleanup(),
      error => error.code === 'ORIX_PROVIDER_WINDOWS_TEARDOWN_UNVERIFIED',
      'Host cleanup must refuse when the native helper could not confirm the provider Job Object is empty',
    );
    assert.equal(await readFile(blockedTeardownLog, 'utf8'), teardownMarker,
      'The blocked cleanup path must not launch another helper or mutate the teardown log');
    assert.equal((await lstat(path.join(blockedTeardown.cwd, 'orix-windows-provider-launcher.exe'))).isFile(), true,
      'The cleanup guard must leave the helper workspace intact for recovery');
    await rm(blockedTeardown.cwd, { recursive: true, force: true });

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
    await access(path.join(root, 'node.exe'));

    // Keep the nested-ACL negative fixture independent from the positive rootfs:
    // failed native preflight/cleanup must not affect another provider's files.
    const unsafeNestedRoot = path.join(base, 'unsafe-nested-rootfs');
    const unsafeNested = path.join(unsafeNestedRoot, 'work');
    await mkdir(unsafeNested, { recursive: true });
    await mkdir(path.join(unsafeNestedRoot, 'tmp'), { recursive: true });
    await copyFile(process.execPath, path.join(unsafeNestedRoot, 'node.exe'));
    execFileSync(path.join(systemRoot, 'System32', 'icacls.exe'), [
      unsafeNested, '/grant', '*S-1-1-0:(OI)(CI)M',
    ], { encoding: 'utf8', windowsHide: true });
    try {
      const nestedUnsafeExecution = await run_static_provider({
        manifest: manifest(),
        executable: path.join(unsafeNestedRoot, 'node.exe'),
        cwd: unsafeNested,
        sandbox_root: unsafeNestedRoot,
        isolation: 'required',
        env: {},
        args: ['-e', 'process.stdout.write("must-not-run")'],
        timeout_ms: 12_000,
        max_output_bytes: 4_096,
      });
      assert.equal(nestedUnsafeExecution.ok, false,
        'Windows isolation must reject a writable nested rootfs directory');
      assert.match(nestedUnsafeExecution.stderr, /ORIX_WINDOWS_ROOTFS_UNTRUSTED/,
        'Native launcher did not report the rejected nested rootfs ACL');
      assert.equal(nestedUnsafeExecution.stdout, '',
        'Provider executed despite the untrusted nested rootfs ACL');
    } finally {
      execFileSync(path.join(systemRoot, 'System32', 'icacls.exe'), [
        unsafeNested, '/remove:g', '*S-1-1-0',
      ], { encoding: 'utf8', windowsHide: true });
    }

    // A hard link inside the rootfs can alias an otherwise external file.
    const hardLinkRoot = path.join(base, 'hardlink-rootfs');
    await mkdir(path.join(hardLinkRoot, 'work'), { recursive: true });
    await mkdir(path.join(hardLinkRoot, 'tmp'), { recursive: true });
    await copyFile(process.execPath, path.join(hardLinkRoot, 'node.exe'));
    const externalHardLinkTarget = path.join(base, 'external-hardlink-target.txt');
    const externalHardLinkValue = 'ORIX external hard-link sentinel';
    await writeFile(externalHardLinkTarget, externalHardLinkValue, 'utf8');
    await link(externalHardLinkTarget, path.join(hardLinkRoot, 'linked-secret.txt'));

    // The JavaScript preflight must reject the alias before staging a helper.
    let nodeHardLinkError = null;
    try {
      await run_static_provider({
        manifest: manifest(),
        executable: path.join(hardLinkRoot, 'node.exe'),
        cwd: path.join(hardLinkRoot, 'work'),
        sandbox_root: hardLinkRoot,
        isolation: 'required',
        env: {},
        args: ['-e', 'process.stdout.write("must-not-run")'],
        timeout_ms: 12_000,
        max_output_bytes: 4_096,
      });
    } catch (error) {
      nodeHardLinkError = error;
    }
    assert.ok(nodeHardLinkError, 'Windows JavaScript preflight must reject a rootfs hard link');
    assert.equal(nodeHardLinkError.code, 'ORIX_PROVIDER_SANDBOX_PATH_DENIED');
    assert.match(nodeHardLinkError.message, /must not contain hard-linked files/);
    assert.equal(await readFile(externalHardLinkTarget, 'utf8'), externalHardLinkValue,
      'JavaScript hard-link preflight must not modify the external target');

    // Invoke the package-owned native helper directly to exercise its independent
    // handle-based link-count check, bypassing the JavaScript preflight above.
    const hardLinkHelperWorkspace = path.join(base, 'hardlink-native-helper');
    await mkdir(hardLinkHelperWorkspace, { recursive: true });
    const launcherPayload = await readFile(new URL('../native/bin/win32-anycpu/orix-windows-provider-launcher.exe.gz', import.meta.url));
    const launcherBytes = decodeWindowsProviderLauncher(launcherPayload);
    const nativeLauncher = path.join(hardLinkHelperWorkspace, 'orix-windows-provider-launcher.exe');
    await writeFile(nativeLauncher, launcherBytes);
    const nativeConfigPath = path.join(hardLinkHelperWorkspace, 'hardlink-provider.json');
    const nativeLogPath = path.join(hardLinkHelperWorkspace, 'hardlink-provider.log');
    const trustedSystemRoot = process.env.SystemRoot || process.env.WINDIR;
    await writeFile(nativeConfigPath, JSON.stringify({
      executable: path.join(hardLinkRoot, 'node.exe'),
      args: ['-e', 'process.stdout.write("must-not-run")'],
      cwd: path.join(hardLinkRoot, 'work'),
      sandboxRoot: hardLinkRoot,
      profileName: 'ORIX-HL-PROBE-' + process.pid,
      logPath: nativeLogPath,
      environment: {
        SystemRoot: trustedSystemRoot,
        WINDIR: trustedSystemRoot,
        PATH: process.env.PATH || '',
        TEMP: path.join(hardLinkRoot, 'tmp'),
        TMP: path.join(hardLinkRoot, 'tmp'),
        HOME: hardLinkRoot,
        USERPROFILE: hardLinkRoot,
        LOCALAPPDATA: hardLinkRoot,
        APPDATA: hardLinkRoot,
      },
    }), 'utf8');
    let nativeHardLinkError = null;
    try {
      execFileSync(nativeLauncher, ['run', nativeConfigPath], {
        cwd: hardLinkHelperWorkspace,
        env: { ...process.env },
        encoding: 'utf8',
        windowsHide: true,
      });
    } catch (error) {
      nativeHardLinkError = error;
    }
    assert.ok(nativeHardLinkError, 'Native Windows launcher must independently reject a rootfs hard link');
    assert.equal(nativeHardLinkError.status, 125,
      'Native hard-link rejection must fail closed with exit code 125');
    assert.match(String(nativeHardLinkError.stderr),
      /ORIX_WINDOWS_ISOLATION_ERROR=.*ORIX_WINDOWS_ROOTFS_UNTRUSTED: hard-linked files are not allowed/,
      'Native launcher did not reject the hard link using the file handle link count');
    assert.equal(await readFile(externalHardLinkTarget, 'utf8'), externalHardLinkValue,
      'Native hard-link preflight must not modify the external target');
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
    assert.notEqual(result.host_file, 'readable', JSON.stringify(result) + ' — provider read a host file outside its rootfs');
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

    // Prove that a provider's descendants are actually terminated when the
    // provider leader exits. Configuration checks alone do not prove Job Object
    // containment or descendant cleanup.
    const descendantCounter = path.join(root, 'tmp', 'job-descendant-counter-' + process.pid);
    const descendantScript = [
      'const fs = require("node:fs");',
      'const counter = ' + JSON.stringify(descendantCounter) + ';',
      'let count = 0;',
      'fs.writeFileSync(counter, "0");',
      'setInterval(() => fs.writeFileSync(counter, String(++count)), 20);',
    ].join('\\n');
    const parentScript = [
      'const { spawn } = require("node:child_process");',
      'const fs = require("node:fs");',
      'const cell = new Int32Array(new SharedArrayBuffer(4));',
      'const child = spawn(process.execPath, ["-e", ' + JSON.stringify(descendantScript) + '], { detached: false, stdio: "ignore", windowsHide: true });',
      'const deadline = Date.now() + 10000;',
      'while (!fs.existsSync(' + JSON.stringify(descendantCounter) + ') && Date.now() < deadline) Atomics.wait(cell, 0, 0, 25);',
      'if (!fs.existsSync(' + JSON.stringify(descendantCounter) + ')) { console.error("provider descendant did not become ready"); process.exit(88); }',
      'process.stdout.write("provider-descendant-started");',
      'process.exit(0);',
    ].join('\\n');
    const descendantExecution = await run_static_provider({
      manifest: manifest(),
      executable: path.join(root, 'node.exe'),
      cwd: path.join(root, 'work'),
      sandbox_root: root,
      isolation: 'required',
      env: {},
      args: ['-e', parentScript],
      timeout_ms: 12_000,
      max_output_bytes: 4_096,
    });
    assert.equal(descendantExecution.ok, true, JSON.stringify({
      exit_code: descendantExecution.exit_code,
      stdout: descendantExecution.stdout,
      stderr: descendantExecution.stderr,
      termination_reason: descendantExecution.termination_reason,
    }));
    assert.match(descendantExecution.stdout, /provider-descendant-started/,
      'Provider leader must exit only after its child process has started');
    assert.match(descendantExecution.stderr, /ORIX_WINDOWS_APPCONTAINER=1;JOB_CPU_RATE=5000;JOB_MEMORY=536870912;JOB_ACTIVE_PROCESSES=64/,
      'Native launcher did not confirm AppContainer and Job Object limits for the descendant test');
    const descendantCountAfterExit = await readFile(descendantCounter, 'utf8');
    await new Promise(resolve => setTimeout(resolve, 250));
    const descendantCountLater = await readFile(descendantCounter, 'utf8');
    assert.equal(descendantCountLater, descendantCountAfterExit,
      'A provider-spawned descendant continued writing after its leader exited; the Job Object did not clean it up');

    // Exercise the cleanup traversal with a real directory junction. The
    // provider process waits while the host replaces its writable Packages
    // directory with a junction to an external sentinel tree. Cleanup must
    // stop at the reparse point and leave the external sentinel untouched.
    const cleanupReady = path.join(root, 'tmp', 'cleanup-reparse-ready-' + process.pid);
    const cleanupContinue = path.join(root, 'tmp', 'cleanup-reparse-continue-' + process.pid);
    const reparsePrepared = await prepare_windows_provider_isolation({
      executable: path.join(root, 'node.exe'),
      cwd: path.join(root, 'work'),
      sandbox_root: root,
      args: ['-e', [
        'const fs = require("node:fs");',
        'fs.writeFileSync(' + JSON.stringify(cleanupReady) + ', "ready");',
        'const go = ' + JSON.stringify(cleanupContinue) + ';',
        'const cell = new Int32Array(new SharedArrayBuffer(4));',
        'const deadline = Date.now() + 15000;',
        'while (!fs.existsSync(go) && Date.now() < deadline) Atomics.wait(cell, 0, 0, 25);',
        'if (!fs.existsSync(go)) { console.error("cleanup injection host timed out"); process.exitCode = 88; }',
      ].join('\n')],
      env: {},
    });
    let reparseChild = null;
    let reparseClosed = null;
    let junctionInstalled = false;
    let preparedCleanupComplete = false;
    const packagesRoot = path.join(root, 'tmp', 'Packages');
    try {
      reparseChild = spawn(reparsePrepared.executable, reparsePrepared.args, {
        cwd: reparsePrepared.cwd,
        env: reparsePrepared.env,
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let helperStdout = '';
      let helperStderr = '';
      reparseChild.stdout.on('data', chunk => { helperStdout += chunk.toString('utf8'); });
      reparseChild.stderr.on('data', chunk => { helperStderr += chunk.toString('utf8'); });
      reparseClosed = new Promise((resolve, reject) => {
        reparseChild.once('error', reject);
        reparseChild.once('close', (code, signal) => resolve({ code, signal, stdout: helperStdout, stderr: helperStderr }));
      });

      const readyDeadline = Date.now() + 15000;
      let providerReady = false;
      while (Date.now() < readyDeadline) {
        try { await access(cleanupReady); providerReady = true; break; }
        catch { await new Promise(resolve => setTimeout(resolve, 25)); }
      }
      assert.equal(providerReady, true, 'Provider did not enter the controlled cleanup-junction test');

      const [profileName] = await readdir(packagesRoot);
      assert.ok(profileName, 'AppContainer redirected Packages profile directory was not created');
      const externalRoot = path.join(base, 'external-cleanup-target');
      const externalProfile = path.join(externalRoot, profileName);
      const externalSentinel = path.join(externalProfile, 'must-survive-cleanup.txt');
      await mkdir(path.join(externalProfile, 'AC', 'Temp'), { recursive: true });
      await writeFile(externalSentinel, 'external-data-must-survive', 'utf8');

      await rm(packagesRoot, { recursive: true, force: true });
      await symlink(externalRoot, packagesRoot, 'junction');
      junctionInstalled = true;
      const junctionInfo = await lstat(packagesRoot);
      assert.equal(junctionInfo.isSymbolicLink(), true, 'Test fixture did not create a Windows junction/reparse point');

      await writeFile(cleanupContinue, 'continue', 'utf8');
      const reparseResult = await reparseClosed;
      reparseChild = null;
      assert.equal(reparseResult.code, 125,
        'Cleanup must fail closed when an AppContainer cleanup ancestor is a reparse point: ' +
        JSON.stringify({ stdout: reparseResult.stdout, stderr: reparseResult.stderr }));
      assert.match(reparseResult.stderr, /ORIX_WINDOWS_CLEANUP_REPARSE_POINT/,
        'Native cleanup did not report the rejected reparse-point path');
      assert.equal(await readFile(externalSentinel, 'utf8'), 'external-data-must-survive',
        'Cleanup traversed the junction and deleted data outside the sandbox root');

      await rmdir(packagesRoot);
      junctionInstalled = false;

      // A malformed profile name must not be mistaken for an absent profile.
      // DeriveAppContainerSidFromAppContainerName documents invalid arguments
      // as failures; the launcher must return non-zero instead of claiming that
      // cleanup succeeded and discarding its diagnostics.
      const invalidProfileConfig = path.join(base, 'invalid-appcontainer-profile.json');
      await writeFile(invalidProfileConfig, JSON.stringify({
        sandboxRoot: root,
        profileName: 'x'.repeat(65),
        logPath: path.join(base, 'invalid-appcontainer-profile.log'),
      }), 'utf8');
      let invalidCleanupError = null;
      try {
        execFileSync(reparsePrepared.executable, ['cleanup', invalidProfileConfig], {
          cwd: reparsePrepared.cwd,
          env: reparsePrepared.env,
          encoding: 'utf8',
          windowsHide: true,
        });
      } catch (error) { invalidCleanupError = error; }
      assert.ok(invalidCleanupError, 'Invalid AppContainer profile names must not be reported as successful cleanup');
      assert.equal(invalidCleanupError.status, 125,
        'Invalid AppContainer profile name should fail closed with exit code 125');
      assert.match(String(invalidCleanupError.stderr), /ORIX_WINDOWS_ISOLATION_ERROR=/,
        'Invalid AppContainer profile name did not surface a native cleanup diagnostic');
      assert.equal((String(invalidCleanupError.stderr).match(/ORIX_WINDOWS_ISOLATION_ERROR=/g) ?? []).length, 1,
        'Explicit cleanup failure must not trigger a duplicate cleanup attempt');

      await reparsePrepared.cleanup();
      preparedCleanupComplete = true;
      await access(externalSentinel);
    } finally {
      if (reparseChild) {
        try { reparseChild.kill(); } catch { /* process may already have exited */ }
        if (reparseClosed) await reparseClosed.catch(() => {});
      }
      if (junctionInstalled) await rmdir(packagesRoot).catch(() => {});
      if (!preparedCleanupComplete) await reparsePrepared.cleanup().catch(() => {});
    }

    process.stdout.write('Windows AppContainer hostile-process checks passed: token, filesystem ACLs, private temp, network isolation, Job Object quotas and reparse-safe cleanup.\\n');
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    await rm(base, { recursive: true, force: true });
    await rm(hostSecret, { force: true });
  }
}

await main();
