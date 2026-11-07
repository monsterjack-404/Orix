// JavaScript, tests/reports.test.mjs, Node.js 20+, Markdown report rendering contracts.

import test from 'node:test';
import assert from 'node:assert/strict';
import { render_inspection_markdown, render_scan_markdown } from '../src/reports/markdown.mjs';

function inspection_report(status = 'parsed') {
  return {
    schema_version: 'orix.artifact.v1',
    artifact: { name: 'sample.bin', path: '/tmp/sample.bin', size_bytes: 2048 },
    detection: { format: 'Unknown', confidence: 'none' },
    integrity: { digest: 'a'.repeat(64), stable_during_read: true },
    parser: { status, result: status === 'parsed' ? { header: { value: 1 } } : null, error: status === 'rejected' ? { code: 'ORIX_BAD_HEADER', message: 'invalid | header' } : null },
    metrics: {
      entropy: { bits_per_byte: 3.2, scope: 'complete-file' },
      strings: { count: 1, values: [{ offset: 4, encoding: 'ascii', length: 5, value: 'A|B\nC' }] },
      hex_preview: '41 42',
    },
    evidence: [{ id: 'ev-000001', kind: 'format', confidence: 'observed', offset: 0, summary: 'MZ | header' }],
    indicators: [{ rule_id: 'ORIX-PE-WX-001', severity: 'high', confidence: 'derived', summary: 'Writable and executable section' }],
    warnings: ['Sample warning'],
  };
}

test('inspection Markdown includes parsed structure, indicators, escaped cells and warnings', () => {
  const markdown = render_inspection_markdown(inspection_report());
  assert.match(markdown, /ORIX Artifact Report/);
  assert.match(markdown, /~~~json/);
  assert.match(markdown, /ORIX-PE-WX-001/);
  assert.match(markdown, /A\\\|B C/);
  assert.match(markdown, /MZ \\\| header/);
  assert.match(markdown, /Sample warning/);
});

test('inspection Markdown reports rejected parser details and no-match rule state', () => {
  const report = inspection_report('rejected');
  report.indicators = [];
  const markdown = render_inspection_markdown(report);
  assert.match(markdown, /Parser status: \*\*rejected\*\*/);
  assert.match(markdown, /ORIX_BAD_HEADER/);
  assert.match(markdown, /No built-in static indicator rules matched/);
});

test('scan Markdown summarizes indicators, artifacts, failures and inventory skips', () => {
  const markdown = render_scan_markdown({
    scan: {
      root: '/tmp/root', files_analyzed: 1, files_skipped: 2, total_bytes_analyzed: 1_048_576,
      duration_ms: 12, files_with_indicators: 1, indicator_counts: { high: 1, low: 2 },
      formats: { PE: 1 },
      coverage: { directories_examined: 2, truncated: true },
    },
    artifacts: [{
      artifact: { path: '/tmp/root/a|b.exe', size_bytes: 1024 },
      detection: { format: 'PE' }, integrity: { digest: 'b'.repeat(64) }, parser: { status: 'parsed' },
      indicators: [{ rule_id: 'ORIX-PE-WX-001', severity: 'high', summary: 'Writable | executable section' }],
    }],
    errors: [{ path: '/tmp/root/bad.bin', error: { code: 'ORIX_FILE_UNAVAILABLE', message: 'cannot read' } }],
    inventory_skips: [{ path: '/tmp/root/link', reason: 'symbolic-link' }],
    limitations: ['Static analysis only.'],
  });
  assert.match(markdown, /Files with indicators:\*\* 1/);
  assert.match(markdown, /high=1, low=2/);
  assert.match(markdown, /ORIX-PE-WX-001/);
  assert.match(markdown, /bad.bin/);
  assert.match(markdown, /symbolic-link/);
  assert.match(markdown, /Inventory truncated: yes/);
  assert.match(markdown, /Static analysis only/);
});


test('SARIF 2.1 export maps findings, severity, evidence byte ranges and artifact hashes', async () => {
  const { render_sarif } = await import('../src/reports/sarif.mjs');
  const report = inspection_report();
  report.artifact.path = '/tmp/orix sample.exe';
  report.integrity.digest = 'c'.repeat(64);
  report.indicators = [{
    rule_id: 'ORIX-PE-WX-001',
    title: 'Writable executable section',
    severity: 'high',
    confidence: 'derived',
    summary: 'Section has write and execute flags.',
    evidence: [{ source: 'pe-section', offset: 128, length: 40 }],
  }];
  const sarif = JSON.parse(render_sarif(report));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].tool.driver.name, 'ORIX');
  assert.equal(sarif.runs[0].tool.driver.semanticVersion, '0.5.0');
  assert.equal(sarif.runs[0].tool.driver.rules[0].id, 'ORIX-PE-WX-001');
  assert.equal(sarif.runs[0].results[0].level, 'error');
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.byteOffset, 128);
  assert.equal(sarif.runs[0].results[0].properties.artifact_sha256, 'c'.repeat(64));
  assert.match(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, /^file:/);
});

test('SARIF export aggregates scan findings and rejects unsupported report kinds', async () => {
  const { render_sarif } = await import('../src/reports/sarif.mjs');
  const artifact = inspection_report();
  const scan = { schema_version: 'orix.scan.v1', artifacts: [artifact, artifact] };
  const sarif = JSON.parse(render_sarif(scan));
  assert.equal(sarif.runs[0].results.length, 2);
  assert.throws(() => render_sarif({ schema_version: 'orix.unknown.v1' }), /supports artifact, directory-scan and project reports only/);
});


test('Markdown reports contain untrusted backticks and multiline error text safely', () => {
  const report = inspection_report();
  const tick = String.fromCharCode(96);
  report.artifact.name = 'evil' + tick + 'name.bin';
  report.artifact.path = '/tmp/evil' + tick + 'path.bin';
  report.metrics.strings.values[0].value = 'token' + tick + 'value|tail';
  report.parser.result = { value: 'untrusted ' + tick.repeat(3) + ' marker' };
  const markdown = render_inspection_markdown(report);
  assert.ok(markdown.includes(tick.repeat(2) + 'evil' + tick + 'name.bin' + tick.repeat(2)));
  assert.ok(markdown.includes('untrusted ' + tick.repeat(3) + ' marker'));
});


test('project SARIF exports redacted source findings with file, line and stable fingerprints', async () => {
  const { render_sarif } = await import('../src/reports/sarif.mjs');
  const secret = 'super-secret-value-that-must-never-escape';
  const report = {
    schema_version: 'orix.project.v1',
    project: { root: '/tmp/orix-project' },
    files: [{ path: 'src/config.js', sha256: 'd'.repeat(64) }],
    findings: [{
      rule_id: 'ORIX-PROJECT-SECRET-GENERIC-001',
      severity: 'high',
      confidence: 'heuristic',
      file: 'src/config.js',
      line: 17,
      label: 'Credential-like assignment',
      evidence: 'Credential-shaped match; value redacted.',
      matched_value: secret,
    }],
  };
  const document = JSON.parse(render_sarif(report));
  const run = document.runs[0];
  assert.equal(document.version, '2.1.0');
  assert.equal(run.results.length, 1);
  assert.equal(run.results[0].ruleId, 'ORIX-PROJECT-SECRET-GENERIC-001');
  assert.equal(run.results[0].level, 'error');
  assert.equal(run.results[0].locations[0].physicalLocation.region.startLine, 17);
  assert.match(run.results[0].locations[0].physicalLocation.artifactLocation.uri, /src\/config\.js$/);
  assert.equal(run.results[0].properties.artifact_sha256, 'd'.repeat(64));
  assert.equal(run.artifacts.length, 1);
  assert.ok(run.results[0].partialFingerprints.primaryLocationLineHash.length === 64);
  assert.equal(JSON.stringify(document).includes(secret), false);
  assert.equal(run.properties.project_findings_redacted, true);
});

test('project SARIF rejects absolute and escaping finding paths', async () => {
  const { render_sarif } = await import('../src/reports/sarif.mjs');
  const base = {
    schema_version: 'orix.project.v1',
    project: { root: '/tmp/orix-project' },
    files: [],
    findings: [{
      rule_id: 'ORIX-TEST-001',
      severity: 'low',
      confidence: 'heuristic',
      file: '../outside.js',
      line: 1,
      label: 'Test finding',
    }],
  };
  assert.throws(() => render_sarif(base), /escapes the project root/);
  assert.throws(() => render_sarif({
    ...base,
    findings: [{ ...base.findings[0], file: '/etc/passwd' }],
  }), /must be relative/);
});
