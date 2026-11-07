// JavaScript, scripts/check-test-skips.mjs, Node.js 20+, reject undeclared skipped-test debt.
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const project_root = fileURLToPath(new URL('../', import.meta.url));
const test_roots = ['test', 'tests', '__tests__'].map(name => path.join(project_root, name));
const skip_pattern = /\b(?:context|t|test|it|describe)\.skip\s*\(|\bskip\s*:\s*true\b/g;
const violations = [];
let scanned_modules = 0;

async function visit(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const full_path = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      await visit(full_path);
      continue;
    }
    if (!entry.isFile() || !entry.name.endsWith('.mjs')) continue;
    scanned_modules++;
    const source = await readFile(full_path, 'utf8');
    for (const match of source.matchAll(skip_pattern)) {
      const line = source.slice(0, match.index).split('\n').length;
      violations.push({ path: path.relative(project_root, full_path), line });
    }
  }
}

for (const directory of test_roots) {
  try {
    await visit(directory);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

if (violations.length > 0) {
  for (const violation of violations) {
    process.stderr.write('Skipped test declaration: ' + violation.path + ':' + violation.line + '\n');
  }
  process.stderr.write('Test skip guard failed: ' + violations.length + ' skipped-test declaration(s) found.\n');
  process.exitCode = 1;
} else {
  process.stdout.write(
    'Test skip guard passed: scanned ' + scanned_modules +
    ' test modules across test/, tests/ and __tests__/.\n',
  );
}
