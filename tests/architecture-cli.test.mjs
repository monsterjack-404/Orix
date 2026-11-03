// JavaScript, tests/architecture-cli.test.mjs, Node.js 20+, CLI integration tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile, mkdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repository_root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli_path = path.join(repository_root, 'src', 'cli.mjs');

async function with_project(callback) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'orix-architecture-cli-'));
  try {
    await mkdir(path.join(root, 'src'), { recursive: true });
    await writeFile(path.join(root, 'src', 'index.js'), \"import './service.js';\\n\");
    await writeFile(path.join(root, 'src', 'service.js'), \"import './index.js';\\n\");
    await writeFile(path.join(root, 'src', 'unused.js'), 'export const unused = true;\\n');
    await callback(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('architecture CLI emits versioned JSON and identifies a local import cycle', async () => with_project(async root => {
  const result = spawnSync(process.execPath, [cli_path, 'architecture', root, '--json'], {
    cwd: repository_root, encoding: 'utf8', timeout: 15000,
  });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.schema_version, 'orix.architecture.v1');
  assert.equal(report.summary.cycle_count, 1);
  assert.equal(report.summary.isolated_files, 1);
}));

test('architecture CLI emits a Mermaid diagram and refuses unknown formats', async () => with_project(async root => {
  const result = spawnSync(process.execPath, [cli_path, 'architecture', root, '--format', 'mermaid'], {
    cwd: repository_root, encoding: 'utf8', timeout: 15000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^flowchart LR/m);

  const invalid = spawnSync(process.execPath, [cli_path, 'architecture', root, '--format', 'sarif'], {
    cwd: repository_root, encoding: 'utf8', timeout: 15000,
  });
  assert.equal(invalid.status, 1);
  assert.match(invalid.stderr, /architecture output supports JSON, Markdown or Mermaid/);
}));

test('architecture CLI writes a new report and refuses to overwrite an existing file', async () => with_project(async root => {
  const output = path.join(root, 'architecture.json');
  const result = spawnSync(process.execPath, [cli_path, 'architecture', root, '--json', '--out', output], {
    cwd: repository_root, encoding: 'utf8', timeout: 15000,
  });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(await readFile(output, 'utf8'));
  assert.equal(report.schema_version, 'orix.architecture.v1');

  const second = spawnSync(process.execPath, [cli_path, 'architecture', root, '--json', '--out', output], {
    cwd: repository_root, encoding: 'utf8', timeout: 15000,
  });
  assert.equal(second.status, 1);
  assert.match(second.stderr, /Refusing to overwrite existing report/);
}));
