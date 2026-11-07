#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

const output = execFileSync('npm', ['pack', '--dry-run', '--json'], {
  encoding: 'utf8',
  shell: process.platform === 'win32',
  stdio: ['ignore', 'pipe', 'pipe'],
});
const results = JSON.parse(output);
assert.ok(Array.isArray(results) && results.length === 1, 'npm pack did not return exactly one package manifest');
const files = new Set((results[0].files ?? []).map(file => file.path));
for (const required of [
  'src/providers/windows-launcher-integrity.mjs',
  'native/bin/win32-anycpu/launcher-payload-01.b64',
  'native/bin/win32-anycpu/launcher-payload-02.b64',
  'native/bin/win32-anycpu/launcher-payload-03.b64',
  'native/bin/win32-anycpu/launcher-payload-04.b64',
]) {
  assert.ok(files.has(required), 'npm package is missing required Windows launcher trust material: ' + required);
}
process.stdout.write('Windows launcher integrity module and all payload segments are included in npm pack.\n');
