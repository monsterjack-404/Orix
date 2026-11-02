// JavaScript, tests/indicators.test.mjs, Node.js 20+, indicator rule specificity and ordering.

import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluate_indicators } from '../src/analyzer/indicators.mjs';

const base = {
  format: 'Unknown', parser_status: 'not-supported', parsed: null,
  parser_error: null, entropy: { bits_per_byte: 2, sample_size: 64 },
  strings: [], stable_during_read: true,
};

test('indicator engine remains quiet when no built-in rule matches', () => {
  assert.deepEqual(evaluate_indicators(base), []);
});

test('high entropy is a low-severity heuristic, not a verdict', () => {
  const [indicator] = evaluate_indicators({ ...base, entropy: { bits_per_byte: 7.8, sample_size: 4096 } });
  assert.equal(indicator.rule_id, 'ORIX-ENTROPY-HIGH-001');
  assert.equal(indicator.severity, 'low');
  assert.equal(indicator.confidence, 'heuristic');
  assert.match(indicator.summary, /Compression, encryption/);
});

test('PE writable-executable and invalid raw ranges generate distinct findings', () => {
  const indicators = evaluate_indicators({
    ...base,
    format: 'PE',
    parser_status: 'parsed',
    parsed: { sections: [
      { index: 0, name: '.text', raw_offset: 512, raw_size: 128, raw_range_valid: true, characteristics: ['code','execute','write'] },
      { index: 1, name: '.bad', raw_offset: 4096, raw_size: 1024, raw_range_valid: false, characteristics: ['read'] },
    ] },
  });
  assert.deepEqual(indicators.map(item => item.rule_id), ['ORIX-PE-SECTION-RANGE-001','ORIX-PE-WRITABLE-EXECUTABLE-001']);
  assert.equal(indicators[1].evidence[0].section_name, '.text');
});

test('ZIP path traversal, symlink markers and encryption are reported without extraction', () => {
  const indicators = evaluate_indicators({
    ...base,
    format: 'ZIP', parser_status: 'parsed',
    parsed: { entries: [
      { index: 0, name: '../outside.txt', unsafe_path: true, is_symlink: false, encrypted: false },
      { index: 1, name: 'link', unsafe_path: false, is_symlink: true, encrypted: true },
    ] },
  });
  assert.deepEqual(indicators.map(item => item.rule_id), ['ORIX-ZIP-UNSAFE-ENTRY-001','ORIX-ZIP-ENCRYPTED-ENTRY-001']);
  assert.equal(indicators[0].evidence.length, 2);
});

test('string heuristics are exact and preserve extracted offsets', () => {
  const indicators = evaluate_indicators({
    ...base,
    strings: [
      { value: 'CreateRemoteThread', encoding: 'ascii', offset: 128, length: 18 },
      { value: 'WriteProcessMemory', encoding: 'ascii', offset: 160, length: 18 },
      { value: 'not-CreateRemoteThread-suffix', encoding: 'ascii', offset: 200, length: 30 },
    ],
  });
  assert.equal(indicators.length, 1);
  assert.equal(indicators[0].evidence.length, 2);
  assert.equal(indicators[0].confidence, 'heuristic');
});


test('PDF active content, embedded files and encryption produce separate triage findings', () => {
  const indicators = evaluate_indicators({
    ...base,
    format: 'PDF',
    parser_status: 'parsed',
    parsed: {
      encrypted: true,
      active_content: {
        javascript: true,
        embedded_files: true,
        file_specifications: true,
        open_actions: true,
        additional_actions: false,
        launch_actions: false,
      },
    },
  });
  assert.deepEqual(indicators.map(item => item.rule_id), [
    'ORIX-PDF-ACTIVE-CONTENT-001',
    'ORIX-PDF-EMBEDDED-CONTENT-001',
    'ORIX-PDF-ENCRYPTED-001',
  ]);
  assert.equal(indicators[0].severity, 'medium');
  assert.equal(indicators[1].severity, 'info');
  assert.equal(indicators[2].severity, 'info');
  assert.match(indicators[0].summary, /do not prove/);
});

test('parser rejection and changing file metadata produce observable findings', () => {
  const indicators = evaluate_indicators({
    ...base,
    format: 'PE', parser_status: 'rejected',
    parser_error: { code: 'ORIX_PE_BAD_SIGNATURE', details: { offset: 64 } },
    stable_during_read: false,
  });
  assert.deepEqual(indicators.map(item => item.rule_id), ['ORIX-FILE-STABILITY-001','ORIX-PARSER-STRUCTURE-001']);
  assert.equal(indicators[1].evidence[0].code, 'ORIX_PE_BAD_SIGNATURE');
});
