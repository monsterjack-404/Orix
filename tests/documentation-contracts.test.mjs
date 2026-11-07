// JavaScript, tests/documentation-contracts.test.mjs, Node.js 20+.
// Prevent public support documentation from silently drifting behind runtime capabilities.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { list_format_capabilities } from '../src/formats/index.mjs';
import { evaluate_indicators } from '../src/analyzer/indicators.mjs';

const root = new URL('../', import.meta.url);

test('format support documentation names every registered signature and parser status', async () => {
  const documentation = await readFile(new URL('docs/FORMATS.md', root), 'utf8');
  const capabilities = list_format_capabilities();

  assert.ok(capabilities.length > 0, 'at least one format capability must be registered');
  for (const capability of capabilities) {
    const labels = {
      PE: 'PE / COFF (PE)',
      'Mach-O': 'Thin Mach-O',
      'Mach-O Universal': 'Universal Mach-O',
    };
    const label = labels[capability.format] ?? capability.format;
    assert.ok(
      documentation.includes(label),
      `docs/FORMATS.md must document registered format: ${capability.format}`,
    );
    const row = documentation.split('\n').find(line =>
      line.startsWith('| ' + label + ' |')
    );
    assert.ok(row, `docs/FORMATS.md must include a matrix row for ${capability.format}`);
    const columns = row.split('|').map(column => column.trim());
    assert.equal(
      columns[3],
      capability.parser_status === 'available' ? 'Yes' : 'No',
      `docs/FORMATS.md parser status must match runtime for ${capability.format}`,
    );
  }
});

test('indicator catalogue documents every currently emitted built-in rule ID', async () => {
  const documentation = await readFile(new URL('docs/INDICATORS.md', root), 'utf8');
  const base = {
    format: 'Unknown',
    parser_status: 'not-supported',
    parsed: null,
    parser_error: null,
    entropy: { bits_per_byte: 0, sample_size: 0 },
    strings: [],
    stable_during_read: true,
  };
  const observations = [
    evaluate_indicators({ ...base, parser_status: 'rejected', parser_error: { code: 'TEST_REJECTED' } }),
    evaluate_indicators({ ...base, stable_during_read: false }),
    evaluate_indicators({ ...base, entropy: { bits_per_byte: 7.8, sample_size: 2048 } }),
    evaluate_indicators({
      ...base,
      format: 'PE',
      parser_status: 'parsed',
      parsed: { sections: [
        { index: 0, name: '.wx', raw_range_valid: false, characteristics: ['write', 'execute'] },
      ] },
    }),
    evaluate_indicators({
      ...base,
      format: 'ZIP',
      parser_status: 'parsed',
      parsed: { entries: [
        { index: 0, name: '../escape', unsafe_path: true, is_symlink: false, encrypted: true },
      ] },
    }),
    evaluate_indicators({
      ...base,
      format: 'PDF',
      parser_status: 'parsed',
      parsed: {
        encrypted: true,
        active_content: { javascript: true, embedded_files: true },
      },
    }),
    evaluate_indicators({
      ...base,
      strings: [
        { value: 'CreateRemoteThread', encoding: 'ascii', offset: 0, length: 18 },
        { value: 'CredReadW', encoding: 'ascii', offset: 32, length: 9 },
      ],
    }),
  ];

  const emittedRuleIds = new Set(observations.flat().map(item => item.rule_id));
  assert.ok(emittedRuleIds.size > 0, 'indicator fixtures must exercise built-in rules');
  for (const ruleId of emittedRuleIds) {
    assert.ok(
      documentation.includes(ruleId),
      `docs/INDICATORS.md must document emitted rule: ${ruleId}`,
    );
  }
});
