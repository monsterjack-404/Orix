// JavaScript, tests/pdf.test.mjs, Node.js 20+, PDF structural parser fixtures and bounds tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_pdf } from '../src/formats/pdf.mjs';
import { analyze_known_format } from '../src/formats/index.mjs';

function make_pdf(body, version = '1.7') {
  return Buffer.concat([Buffer.from(\`%PDF-\${version}\\n% fixture\\n\`, 'ascii'), Buffer.from(body, 'latin1'), Buffer.from('\\n%%EOF\\n', 'ascii')]);
}

test('PDF parser indexes classic xref, trailer, catalog, pages and startxref', () => {
  const pdf = make_pdf(['1 0 obj','<< /Type /Catalog /Pages 2 0 R >>','endobj','2 0 obj','<< /Type /Pages /Count 0 >>','endobj','xref','0 3','0000000000 65535 f','0000000015 00000 n','0000000064 00000 n','trailer','<< /Size 3 /Root 1 0 R >>','startxref','128'].join('\\n'));
  const parsed = parse_pdf(pdf);
  assert.equal(parsed.header.version, '1.7');
  assert.equal(parsed.objects.count, 2);
  assert.equal(parsed.cross_references.classic_table_markers, 1);
  assert.equal(parsed.trailer.entries.find(entry => entry.key === 'Root').value, '1');
  assert.equal(parsed.summary.has_catalog, true);
  assert.equal(parsed.summary.has_pages_tree, true);
  assert.equal(parsed.summary.has_startxref, true);
});

test('PDF parser indexes stream framing without decompressing payloads', () => {
  const pdf = make_pdf(['5 0 obj','<< /Length 11 /Filter /FlateDecode >>','stream','hello world','endstream','endobj','startxref','0'].join('\\n'));
  const parsed = parse_pdf(pdf);
  assert.equal(parsed.objects.stream_count, 1);
  assert.equal(parsed.objects.entries[0].stream.encoded_length, 11);
  assert.equal(parsed.objects.entries[0].dictionary.entries.find(entry => entry.key === 'Filter').value, '/FlateDecode');
});

test('PDF parser reports encryption and active-content names as indicators only', () => {
  const pdf = make_pdf(['1 0 obj','<< /Type /Catalog /OpenAction 2 0 R /Names << /JavaScript 3 0 R >> >>','endobj','2 0 obj','<< /S /JavaScript /JS (app.alert\\\\(1\\\\)) >>','endobj','trailer','<< /Size 4 /Root 1 0 R /Encrypt 4 0 R >>','startxref','0'].join('\\n'));
  const parsed = parse_pdf(pdf);
  assert.equal(parsed.security.encrypted, true);
  assert.ok(parsed.active_content_indicators.some(item => item.name === 'OpenAction'));
  assert.ok(parsed.active_content_indicators.some(item => item.name === 'JavaScript'));
  assert.ok(parsed.active_content_indicators.some(item => item.name === 'JS'));
});

test('PDF parser counts incremental revision markers and xref streams', () => {
  const pdf = make_pdf(['1 0 obj','<< /Type /XRef /Size 2 /W [1 2 1] /Length 4 >>','stream','abcd','endstream','endobj','startxref','10','%%EOF','startxref','20'].join('\\n'));
  const parsed = parse_pdf(pdf);
  assert.equal(parsed.cross_references.xref_stream_objects, 1);
  assert.equal(parsed.revision.incremental_update_count, 1);
  assert.equal(parsed.summary.has_xref, true);
});

test('PDF parser ignores fake object tokens inside literal and hex strings', () => {
  const pdf = make_pdf(['1 0 obj','<< /Note (fake 9 0 obj endobj and nested (text)) /Hex <312030206f626a> >>','endobj'].join('\\n'));
  const parsed = parse_pdf(pdf);
  assert.equal(parsed.objects.count, 1);
});

test('PDF parser enforces object, token and stream scan limits', () => {
  const pdf = make_pdf('1 0 obj << /Type /Catalog >> endobj');
  assert.throws(() => parse_pdf(pdf, { max_objects: 1, max_tokens: 2 }), error => error.code === 'ORIX_PDF_TOKEN_LIMIT');
  assert.throws(() => parse_pdf(pdf, { max_objects: 0 }), TypeError);
  const stream = make_pdf('1 0 obj << /Length 50 >> stream\\n' + 'a'.repeat(100) + '\\nendstream endobj');
  assert.throws(() => parse_pdf(stream, { max_stream_scan_bytes: 8 }), error => error.code === 'ORIX_PDF_STREAM_END_MISSING');
});

test('PDF dispatcher routes PDF signatures to the structural parser', () => {
  const pdf = make_pdf('trailer << /Size 0 >>');
  const result = analyze_known_format(pdf);
  assert.equal(result.detection.format, 'PDF');
  assert.equal(result.parser_status, 'parsed');
  assert.equal(result.parsed.format, 'PDF');
});

test('PDF parser rejects invalid headers and unterminated strings with typed errors', () => {
  assert.throws(() => parse_pdf(Buffer.from('not a pdf')), error => error.code === 'ORIX_PDF_BAD_HEADER');
  const malformed = make_pdf('1 0 obj << /Title (never closed >> endobj');
  assert.throws(() => parse_pdf(malformed), error => error.code === 'ORIX_PDF_UNTERMINATED_STRING');
});
