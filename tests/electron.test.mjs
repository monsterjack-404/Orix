// JavaScript, tests/electron.test.mjs, Node.js 20+, Electron static triage contracts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { analyze_electron_project } from '../src/project/electron.mjs';
import { scan_project } from '../src/project/intelligence.mjs';

test('detects Electron from package metadata and reports literal unsafe webPreferences', () => {
  const report = analyze_electron_project([
    { path: 'package.json', text: JSON.stringify({ devDependencies: { electron: '^30.0.0' }, main: 'src/main.js' }) },
    { path: 'src/main.js', text: "const win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false, sandbox: false } });" },
    { path: 'src/preload.js', text: "const { contextBridge } = require('electron');" },
  ]);
  assert.equal(report.detected, true);
  assert.equal(report.confidence, 'strong-project-metadata');
  assert.ok(report.process_roles.includes('main-candidate'));
  assert.ok(report.process_roles.includes('preload-candidate'));
  assert.deepEqual(report.findings.map(item => item.rule_id).sort(), [
    'ORIX-ELECTRON-CONTEXT-ISOLATION',
    'ORIX-ELECTRON-NODE-INTEGRATION',
    'ORIX-ELECTRON-SANDBOX-DISABLED',
  ]);
  assert.ok(report.findings.every(item => item.confidence === 'heuristic' && item.line === 1));
});

test('does not flag secure literal settings or infer computed values', () => {
  const report = analyze_electron_project([
    { path: 'package.json', text: JSON.stringify({ dependencies: { electron: '^30.0.0' } }) },
    { path: 'main.js', text: [
      'new BrowserWindow({',
      ' webPreferences: {',
      '  nodeIntegration: false,',
      '  contextIsolation: true,',
      '  sandbox: true,',
      '  webSecurity: true,',
      '  nodeIntegration: process.env.NODE_INTEGRATION',
      ' }',
      '});',
    ].join('\n') },
  ]);
  assert.equal(report.detected, true);
  assert.equal(report.findings.length, 0);
});

test('only inspects direct webPreferences literals and ignores comments, strings, regex and unrelated objects', () => {
  const report = analyze_electron_project([
    { path: 'package.json', text: JSON.stringify({ dependencies: { electron: '^30.0.0' } }) },
    { path: 'main.js', text: [
      'const text = "webPreferences: { nodeIntegration: true }";',
      '// webPreferences: { contextIsolation: false }',
      'const pattern = /webPreferences: \\{ sandbox: false \\}/;',
      'const unrelated = { nodeIntegration: true, contextIsolation: false };',
      'new BrowserWindow({',
      '  webPreferences: {',
      '    nodeIntegration: true,',
      '    nested: { contextIsolation: false },',
      "    'webSecurity': false",
      '  }',
      '});',
    ].join('\n') },
  ]);
  assert.deepEqual(report.findings.map(item => item.rule_id).sort(), [
    'ORIX-ELECTRON-NODE-INTEGRATION',
    'ORIX-ELECTRON-WEB-SECURITY-DISABLED',
  ]);
  assert.deepEqual(report.findings.map(item => item.line), [7, 9]);
});

test('project scan includes Electron triage without executing package scripts', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'orix-electron-'));
  try {
    await writeFile(path.join(root, 'package.json'), JSON.stringify({
      devDependencies: { electron: '^30.0.0' },
      scripts: { postinstall: 'throw new Error("must never run")' },
    }));
    await writeFile(path.join(root, 'main.js'), "const options = { webPreferences: { webSecurity: false } };\n");
    const report = await scan_project(root);
    assert.equal(report.electron.detected, true);
    assert.equal(report.electron.findings.length, 1);
    assert.equal(report.summary.electron_findings, 1);
    assert.equal(report.summary.secret_pattern_matches, 0);
    assert.equal(report.findings[0].rule_id, 'ORIX-ELECTRON-WEB-SECURITY-DISABLED');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('does not mistake unrelated object methods for Electron module loading', () => {
  const report = analyze_electron_project([
    { path: 'src/main.js', text: [
      "service.require('electron');",
      "service.import('electron');",
      "service?.require('electron');",
    ].join('\n') },
  ]);
  assert.equal(report.detected, false);
  assert.equal(report.electron_source_files.length, 0);
});

test('recognizes side-effect imports and direct module.require Electron loading', () => {
  const side_effect = analyze_electron_project([
    { path: 'src/renderer.js', text: "import 'electron';" },
  ]);
  assert.equal(side_effect.detected, true);
  assert.equal(side_effect.electron_source_files.length, 1);

  const commonjs = analyze_electron_project([
    { path: 'src/preload.cjs', text: "const electron = module.require('electron');" },
  ]);
  assert.equal(commonjs.detected, true);
  assert.equal(commonjs.electron_source_files.length, 1);
});

test('does not classify an ordinary Node.js package main entry as Electron', () => {
  const report = analyze_electron_project([
    { path: 'package.json', text: JSON.stringify({ name: 'ordinary-node-app', main: 'main.js', scripts: { start: 'node main.js' } }) },
    { path: 'main.js', text: 'console.log("hello");' },
  ]);
  assert.equal(report.detected, false);
  assert.equal(report.confidence, 'not-detected');
});

test('detects source-only Electron signals without requiring package metadata', () => {
  const report = analyze_electron_project([
    { path: 'desktop/preload.ts', text: "import { contextBridge } from 'electron';" },
    { path: 'desktop/renderer.tsx', text: 'export const ready = true;' },
  ]);
  assert.equal(report.detected, true);
  assert.equal(report.confidence, 'heuristic-source-signal');
  assert.deepEqual(report.process_roles, ['preload-candidate', 'renderer-candidate']);
  assert.equal(report.electron_source_files.length, 1);
});

test('ignores Electron words in comments and ordinary strings', () => {
  const report = analyze_electron_project([
    { path: 'main.js', text: [
      'const name = "electron";',
      '// require("electron")',
      'const label = "webPreferences: { nodeIntegration: true }";',
    ].join('\n') },
  ]);
  assert.equal(report.detected, false);
  assert.equal(report.electron_source_files.length, 0);
  assert.equal(report.findings.length, 0);
});

test('handles long whitespace before literal values without backtracking regexes', () => {
  const spaces = ' '.repeat(10000);
  const report = analyze_electron_project([
    { path: 'package.json', text: JSON.stringify({ dependencies: { electron: '^30.0.0' } }) },
    { path: 'main.js', text: 'webPreferences: { nodeIntegration:' + spaces + 'true }' },
  ]);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].rule_id, 'ORIX-ELECTRON-NODE-INTEGRATION');
});

test('bounds direct Electron analyzer input size and entry shape', () => {
  assert.throws(() => analyze_electron_project(null), TypeError);
  assert.throws(() => analyze_electron_project([{}]), error => error.code === 'ORIX_ELECTRON_FILE_ENTRY');
  assert.throws(() => analyze_electron_project([{ path: 'large.js', text: 'x'.repeat(1_048_577) }]), error => error.code === 'ORIX_ELECTRON_FILE_SIZE_LIMIT');
  assert.throws(() => analyze_electron_project(Array.from({ length: 50_001 }, () => ({ path: 'a.js', text: '' }))), error => error.code === 'ORIX_ELECTRON_FILE_LIMIT');
});


test('reports source files that reach the bounded token ceiling', () => {
  const source = 'const value = 1;\n'.repeat(25_000);
  const report = analyze_electron_project([{ path: 'large.js', text: source }]);
  assert.equal(report.analysis_truncated_files, 1);
  assert.equal(report.detected, false);
});
