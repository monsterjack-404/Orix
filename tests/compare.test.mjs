// JavaScript, tests/compare.test.mjs, Node.js 20+, deterministic scan comparison contracts.

import test from 'node:test';
import assert from 'node:assert/strict';
import { compare_reports } from '../src/analyzer/compare.mjs';
import { render_comparison_markdown } from '../src/reports/comparison.mjs';

function artifact(root, relative, digest, indicators = [], format = 'Unknown') {
  return {
    schema_version: 'orix.artifact.v1',
    artifact: { path: root + '/' + relative, name: relative.split('/').at(-1), size_bytes: 10 },
    integrity: { algorithm: 'sha256', digest: digest.repeat(64).slice(0, 64) },
    detection: { format },
    indicators,
  };
}

function scan(root, artifacts) {
  return { schema_version: 'orix.scan.v1', scan: { root }, artifacts };
}

test('comparison classifies added, removed, modified and unchanged artifacts by relative path and hash', () => {
  const baseline = scan('/work/old', [
    artifact('/work/old', 'src/keep.js', 'a'),
    artifact('/work/old', 'src/change.js', 'b'),
    artifact('/work/old', 'src/remove.js', 'c'),
  ]);
  const current = scan('/work/new', [
    artifact('/work/new', 'src/keep.js', 'a'),
    artifact('/work/new', 'src/change.js', 'd'),
    artifact('/work/new', 'src/add.js', 'e'),
  ]);
  const result = compare_reports(baseline, current);
  assert.deepEqual(result.artifacts.added.map(item => item.path), ['src/add.js']);
  assert.deepEqual(result.artifacts.removed.map(item => item.path), ['src/remove.js']);
  assert.deepEqual(result.artifacts.modified.map(item => item.path), ['src/change.js']);
  assert.deepEqual(result.artifacts.unchanged.map(item => item.path), ['src/keep.js']);
  assert.equal(result.comparison.added, 1);
  assert.equal(result.comparison.removed, 1);
  assert.equal(result.comparison.modified, 1);
  assert.equal(result.comparison.unchanged, 1);
});

test('comparison reports introduced and resolved indicators across artifact revisions', () => {
  const old_indicator = { rule_id: 'ORIX-TEST-OLD', severity: 'medium', summary: 'Old finding' };
  const same_indicator = { rule_id: 'ORIX-TEST-SAME', severity: 'low', summary: 'Persistent finding' };
  const new_indicator = { rule_id: 'ORIX-TEST-NEW', severity: 'high', summary: 'New finding' };
  const baseline = scan('/work', [artifact('/work', 'app.bin', 'a', [old_indicator, same_indicator])]);
  const current = scan('/work', [artifact('/work', 'app.bin', 'b', [same_indicator, new_indicator])]);
  const result = compare_reports(baseline, current);
  assert.deepEqual(result.indicators.introduced.map(item => item.rule_id), ['ORIX-TEST-NEW']);
  assert.deepEqual(result.indicators.resolved.map(item => item.rule_id), ['ORIX-TEST-OLD']);
  const markdown = render_comparison_markdown(result);
  assert.match(markdown, /ORIX Report Comparison/);
  assert.match(markdown, /New finding/);
  assert.match(markdown, /Old finding/);
});

test('comparison accepts single artifact reports and rejects duplicate or escaping paths', () => {
  const before = artifact('/work', 'one.bin', 'a');
  const after = artifact('/work', 'one.bin', 'b');
  before.schema_version = 'orix.artifact.v1';
  after.schema_version = 'orix.artifact.v1';
  assert.equal(compare_reports(before, after).comparison.modified, 1);
  const duplicate = scan('/work', [artifact('/work', 'dup.bin', 'a'), artifact('/work', 'dup.bin', 'b')]);
  assert.throws(() => compare_reports(duplicate, scan('/work', [])), error => error.code === 'ORIX_COMPARE_DUPLICATE_PATH');
  const escaping = scan('/work', [artifact('/outside', 'escape.bin', 'a')]);
  assert.throws(() => compare_reports(escaping, scan('/work', [])), error => error.code === 'ORIX_COMPARE_PATH_ESCAPE');
});

test('comparison rejects unsupported report schemas and invalid artifact hashes', () => {
  assert.throws(() => compare_reports({ schema_version: 'orix.project.v1' }, { schema_version: 'orix.scan.v1', scan: { root: '/x' }, artifacts: [] }), error => error.code === 'ORIX_COMPARE_REPORT_UNSUPPORTED');
  const malformed = scan('/work', [{ artifact: { path: '/work/a' }, integrity: { digest: 'not-a-hash' } }]);
  assert.throws(() => compare_reports(malformed, scan('/work', [])), error => error.code === 'ORIX_COMPARE_ARTIFACT_INVALID');
});


test('comparison rejects scan reports without a usable root path', () => {
  const malformed = { schema_version: 'orix.scan.v1', artifacts: [] };
  assert.throws(
    () => compare_reports(malformed, scan('/work', [])),
    error => error.code === 'ORIX_COMPARE_REPORT_INVALID' && /root path/.test(error.message),
  );
});


test('comparison Markdown safely delimits paths containing backticks', () => {
  const tick = String.fromCharCode(96);
  const baseline = scan('/work', [artifact('/work', 'evil' + tick + 'name.bin', 'a')]);
  const current = scan('/work', [artifact('/work', 'evil' + tick + 'name.bin', 'b')]);
  const markdown = render_comparison_markdown(compare_reports(baseline, current));
  assert.ok(markdown.includes(tick.repeat(2) + 'evil' + tick + 'name.bin' + tick.repeat(2)));
});
