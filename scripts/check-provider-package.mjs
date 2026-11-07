// Verify the runtime files used by Linux required isolation are admitted to npm's package tarball.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const npmExecPath = process.env.npm_execpath;
assert.equal(typeof npmExecPath, 'string',
  'Package admission check must run from npm so npm_execpath identifies the active npm CLI');

const result = spawnSync(process.execPath, [path.resolve(npmExecPath), 'pack', '--dry-run', '--json'], {
  cwd: projectRoot,
  encoding: 'utf8',
  timeout: 30_000,
  maxBuffer: 4 * 1024 * 1024,
  windowsHide: true,
});
if (result.error) throw result.error;
assert.equal(result.status, 0,
  'npm pack --dry-run failed: ' + String(result.stderr || result.stdout).slice(0, 4000));

let packages;
try {
  packages = JSON.parse(result.stdout);
} catch (error) {
  throw new Error('npm pack --dry-run did not return valid JSON', { cause: error });
}
assert.ok(Array.isArray(packages) && packages.length === 1,
  'Expected npm pack --dry-run to describe exactly one package');

const included = new Set(packages[0].files.map(file => file.path));
const requiredFiles = [
  'src/providers/linux-cgroup-v2-bootstrap.mjs',
  'src/providers/linux-cgroup-v2-manager.mjs',
  'src/providers/linux-cgroup-v2-preflight.mjs',
  'src/providers/linux-isolation.mjs',
  'src/providers/process-runner.mjs',
];
const missing = requiredFiles.filter(file => !included.has(file));
assert.deepEqual(missing, [],
  'The runtime package is missing required provider-isolation files');

process.stdout.write('Provider package admission passed: all Linux isolation runtime files are included.\\n');
