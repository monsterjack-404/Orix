// Move this trusted launcher into a delegated cgroup before starting the provider tree.
import { writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';

const [cgroupDirectory, executable, ...args] = process.argv.slice(2);
if (!cgroupDirectory || !path.isAbsolute(cgroupDirectory) ||
    !executable || !path.isAbsolute(executable) ||
    cgroupDirectory.includes('\0') || executable.includes('\0')) {
  process.stderr.write('Invalid provider cgroup launcher arguments.\n');
  process.exit(125);
}

try {
  // This process is the one started by ORIX. Moving it before spawning anything
  // makes every subsequently created descendant inherit the enforced cgroup.
  await writeFile(path.join(cgroupDirectory, 'cgroup.procs'), String(process.pid));
} catch (error) {
  process.stderr.write('Could not enter the required provider cgroup: ' + (error.code ?? 'write-failed') + '\n');
  process.exit(125);
}

const child = spawn(executable, args, {
  cwd: '/',
  env: process.env,
  shell: false,
  windowsHide: true,
  detached: false,
  stdio: 'inherit',
});
let spawnFailed = false;
child.once('error', error => {
  spawnFailed = true;
  process.stderr.write('Could not launch isolated provider: ' + (error.code ?? 'spawn-failed') + '\n');
  process.exitCode = 127;
});
child.once('close', (code, signal) => {
  if (!spawnFailed) process.exitCode = Number.isInteger(code) ? code : (signal === 'SIGTERM' ? 143 : 1);
});
