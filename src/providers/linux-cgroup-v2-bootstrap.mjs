// JavaScript, src/providers/linux-cgroup-v2-bootstrap.mjs, Node.js 20+, trusted Linux-only cgroup attach helper.
import { closeSync, writeSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { constants as OS_CONSTANTS } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ATTACH_FD = 3;
const MAX_ARGUMENTS = 256;
const MAX_ARGUMENT_BYTES = 64 * 1024;

function fail(code, message, cause) {
  const error = new Error(message, cause === undefined ? undefined : { cause });
  error.code = code;
  throw error;
}

/**
 * Consume the one-shot write capability passed by the trusted host.
 * The host must map the already-open leaf cgroup.procs descriptor to child fd 3.
 * This function deliberately cannot accept another descriptor number.
 */
export function attach_current_process_to_cgroup(fd) {
  if (process.platform !== 'linux') {
    fail('ORIX_CGROUP_BOOTSTRAP_PLATFORM_UNSUPPORTED', 'The cgroup bootstrap is Linux-only');
  }
  if (fd !== ATTACH_FD) {
    fail('ORIX_CGROUP_BOOTSTRAP_FD_INVALID', 'The cgroup attach capability must be descriptor 3');
  }

  const payload = Buffer.from(String(process.pid) + '\n', 'ascii');
  let failure = null;
  try {
    const written = writeSync(fd, payload, 0, payload.length);
    if (written !== payload.length) {
      fail('ORIX_CGROUP_BOOTSTRAP_SHORT_WRITE', 'The cgroup attach write was incomplete');
    }
  } catch (error) {
    failure = error;
  }

  try {
    closeSync(fd);
  } catch (error) {
    if (failure === null) failure = error;
  }

  if (failure !== null) {
    fail('ORIX_CGROUP_BOOTSTRAP_ATTACH_FAILED', 'The bootstrap could not attach itself to the provider cgroup', failure);
  }
}

function parse_launch_arguments(argv) {
  if (!Array.isArray(argv) || argv.length < 3 ||
      argv[0] !== '--attach-fd=3' || argv[1] !== '--') {
    fail('ORIX_CGROUP_BOOTSTRAP_ARGUMENTS_INVALID', 'Expected --attach-fd=3 -- ABSOLUTE_EXECUTABLE [ARG ...]');
  }

  const executable = argv[2];
  const args = argv.slice(3);
  if (typeof executable !== 'string' || !path.isAbsolute(executable) ||
      executable.includes('\0') || args.length > MAX_ARGUMENTS ||
      args.some(argument => typeof argument !== 'string' || argument.includes('\0'))) {
    fail('ORIX_CGROUP_BOOTSTRAP_ARGUMENTS_INVALID', 'Bootstrap command must use an absolute executable and bounded NUL-free arguments');
  }

  let total = Buffer.byteLength(executable, 'utf8');
  for (const argument of args) total += Buffer.byteLength(argument, 'utf8');
  if (total > MAX_ARGUMENT_BYTES) {
    fail('ORIX_CGROUP_BOOTSTRAP_ARGUMENTS_INVALID', 'Bootstrap command exceeds the argument byte limit');
  }
  return { executable, args };
}

function report_failure(code) {
  process.stderr.write(code + '\n');
  process.exitCode = 125;
}

function launch_provider_command(executable, args) {
  let child;
  try {
    child = spawn(executable, args, {
      cwd: process.cwd(),
      env: process.env,
      shell: false,
      windowsHide: true,
      stdio: 'inherit',
    });
  } catch (error) {
    process.stderr.write('ORIX_CGROUP_BOOTSTRAP_SPAWN_FAILED ' + (error.code ?? error.name ?? 'spawn-error') + '\n');
    process.exitCode = 127;
    return;
  }

  let spawn_failed = false;
  child.once('error', error => {
    spawn_failed = true;
    process.stderr.write('ORIX_CGROUP_BOOTSTRAP_SPAWN_FAILED ' + (error.code ?? error.name ?? 'spawn-error') + '\n');
    process.exitCode = 127;
  });
  child.once('close', (code, signal) => {
    if (spawn_failed) return;
    if (Number.isInteger(code)) {
      process.exitCode = code;
      return;
    }
    const signal_number = signal ? OS_CONSTANTS.signals[signal] : undefined;
    process.exitCode = Number.isInteger(signal_number) ? 128 + signal_number : 1;
  });
}

function main() {
  let command;
  try {
    // Parsing performs no filesystem or process operation. Attaching is the
    // first side effect, and it must succeed before the provider is spawned.
    command = parse_launch_arguments(process.argv.slice(2));
  } catch (error) {
    report_failure(error.code ?? 'ORIX_CGROUP_BOOTSTRAP_ARGUMENTS_INVALID');
    return;
  }

  try {
    attach_current_process_to_cgroup(ATTACH_FD);
  } catch (error) {
    report_failure(error.code ?? 'ORIX_CGROUP_BOOTSTRAP_ATTACH_FAILED');
    return;
  }

  // Descriptor 3 has been closed before any provider/Bubblewrap process starts.
  launch_provider_command(command.executable, command.args);
}

const invoked_path = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invoked_path === fileURLToPath(import.meta.url)) main();
