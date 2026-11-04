// JavaScript, tests/javascript-analysis.test.mjs, Node.js 20+, bounded JS/TS tokenizer contracts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { analyze_javascript_source } from '../src/project/javascript.mjs';
import { scan_project } from '../src/project/intelligence.mjs';

test('extracts static imports, re-exports, require and dynamic import without comment/string false positives', () => {
  const source = [
    "// import fake from 'comment-only';",
    "const example = \"require('not-a-module')\";",
    "import './side-effect.js';",
    "import type { Thing } from './types.js';",
    "export { value } from './value.js';",
    "const a = require('./common.cjs');",
    "const b = import('./lazy.js');",
    "const template = 'import(\\\'not-real.js\\\')';",
  ].join('\\n');
  const report = analyze_javascript_source(source);
  assert.deepEqual(report.imports.map(item => [item.specifier, item.kind]), [
    ['./side-effect.js', 'side-effect-import'],
    ['./types.js', 'import'],
    ['./value.js', 're-export'],
    ['./common.cjs', 'require'],
    ['./lazy.js', 'dynamic-import'],
  ]);
  assert.equal(report.imports.some(item => item.specifier.includes('not-real')), false);
  assert.equal(report.imports.some(item => item.specifier.includes('not-a-module')), false);
});

test('collects function, class, interface, type, enum and exported variable declarations', () => {
  const report = analyze_javascript_source([
    'export function start() {}',
    'class Engine {}',
    'interface Options {}',
    'type Identifier = string;',
    'enum State { Ready }',
    'export const enabled = true;',
    'const internal = 1;',
  ].join('\\n'));
  assert.deepEqual(report.symbols.map(item => [item.name, item.kind]), [
    ['start', 'function'],
    ['Engine', 'class'],
    ['Options', 'interface'],
    ['Identifier', 'type'],
    ['State', 'enum'],
    ['enabled', 'variable'],
  ]);
});

test('enforces token and result bounds and rejects invalid limits', () => {
  const report = analyze_javascript_source('const a = 1; const b = 2;', { max_tokens: 3, max_imports: 1, max_symbols: 1 });
  assert.equal(report.coverage.token_limit_reached, true);
  assert.throws(() => analyze_javascript_source('x', { max_tokens: 0 }), /max_tokens/);
});

test('project scanner uses structural JS/TS imports and records token coverage', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'orix-js-'));
  try {
    await writeFile(path.join(root, 'index.ts'), "import { run } from './runner.js';\\nexport function main() { return run(); }\\n");
    await writeFile(path.join(root, 'runner.js'), 'export function run() { return true; }\\n');
    const report = await scan_project(root);
    const entry = report.files.find(item => item.path === 'index.ts');
    assert.equal(entry.imports[0].specifier, './runner.js');
    assert.equal(entry.imports[0].resolved_path, 'runner.js');
    assert.equal(entry.imports[0].kind, 'import');
    assert.ok(entry.javascript_analysis.tokens > 0);
    assert.ok(report.symbols.some(item => item.name === 'main' && item.file === 'index.ts'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
