// JavaScript, tests/reports.test.mjs, Node.js 20+, Markdown report rendering contracts.

import test from 'node:test';
import assert from 'node:assert/strict';
import { render_inspection_markdown, render_scan_markdown } from '../src/reports/markdown.mjs';

function inspection_report(status = 'parsed') {
  return {
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
  assert.match(markdown, /```json/);
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
