// JavaScript, scripts/check-syntax.mjs, Node.js 20+, cross-platform syntax gate for project modules.

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const project_root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const roots = ['src', 'tests', 'scripts', 'web'];
const failures = [];
let checked = 0;

async function collect_modules(directory) {
  let entries;
  try {
    entries = await fs.readdir(directory, { withFileTypes: true });
  } catch (error) {
    failures.push({ path: path.relative(project_root, directory), message: error.message });
    return [];
  }
  entries.sort((left, right) => left.name.localeCompare(right.name, 'en'));
  const modules = [];
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) modules.push(...await collect_modules(absolute));
    else if (entry.isFile() && entry.name.endsWith('.mjs')) modules.push(absolute);
  }
  return modules;
}

for (const root of roots) {
  const absolute = path.join(project_root, root);
  try {
    const stats = await fs.lstat(absolute);
    if (!stats.isDirectory() || stats.isSymbolicLink()) throw new Error('expected a real directory');
  } catch (error) {
    failures.push({ path: root, message: error.message });
    continue;
  }
  const modules = await collect_modules(absolute);
  for (const module_path of modules) {
    const result = spawnSync(process.execPath, ['--check', module_path], { encoding: 'utf8', cwd: project_root });
    checked += 1;
    if (result.error || result.status !== 0) {
      failures.push({
        path: path.relative(project_root, module_path),
        message: result.error?.message ?? (result.stderr || result.stdout || `node --check exited ${result.status}`).trim(),
      });
    }
  }
}

if (failures.length) {
  for (const failure of failures) process.stderr.write(`FAIL ${failure.path}: ${failure.message}\n`);
  process.stderr.write(`Syntax validation failed: ${failures.length} failure(s) across ${checked} module(s).\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`Syntax validation passed for ${checked} ECMAScript modules.\n`);
}
