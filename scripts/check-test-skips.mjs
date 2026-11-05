// JavaScript, scripts/check-test-skips.mjs, reject platform-conditional skipped tests.
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../tests/', import.meta.url));
const skip_pattern = /\b(?:context|t|test|it|describe)\.skip\s*\(|\bskip\s*:\s*true\b/g;
const violations = [];

async function visit(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const full_path = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      await visit(full_path);
      continue;
    }
    if (!entry.isFile() || !entry.name.endsWith('.mjs')) continue;
    const source = await readFile(full_path, 'utf8');
    for (const match of source.matchAll(skip_pattern)) {
      const line = source.slice(0, match.index).split('\n').length;
      violations.push({ path: path.relative(root, full_path), line });
    }
  }
}

await visit(root);
if (violations.length > 0) {
  for (const violation of violations) {
    process.stderr.write('Skipped test declaration: ' + violation.path + ':' + violation.line + '\n');
  }
  process.exitCode = 1;
} else {
  process.stdout.write('Test skip guard passed: no skipped test declarations found.\n');
}
