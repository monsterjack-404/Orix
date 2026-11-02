// JavaScript, tests/pdf.test.mjs, Node.js 20+, PDF structural parser regression coverage.

import test from 'node:test';
import assert from 'node:assert/strict';
import { parse_pdf } from '../src/formats/pdf.mjs';
import { analyze_known_format } from '../src/formats/index.mjs';

function make_pdf(objects, trailer = '<< /Size 3 /Root 1 0 R >>') {
  const chunks = [Buffer.from('%PDF-1.7\n', 'ascii')];
  const offsets = [];
  for (const object of objects) {
    offsets.push(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
    chunks.push(Buffer.from(object + '\n', 'latin1'));
  }
  const xref_offset = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const rows = ['xref', '0 ' + (objects.length + 1), '0000000000 65535 f '];
  for (const offset of offsets) rows.push(String(offset).padStart(10, '0') + ' 00000 n ');
  rows.push('trailer', trailer, 'startxref', String(xref_offset), '%%EOF');
  chunks.push(Buffer.from(rows.join('\n') + '\n', 'ascii'));
  return { buffer: Buffer.concat(chunks), xref_offset, offsets };
}

test('PDF parser indexes classic xref entries, trailer and indirect objects', () => {
  const fixture = make_pdf([
    `1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj`,
    `2 0 obj
<< /Type /Pages /Count 0 >>
endobj`,
  ]);
  const parsed = parse_pdf(fixture.buffer);
  assert.equal(parsed.version, '1.7');
  assert.equal(parsed.object_count, 2);
  assert.equal(parsed.revisions[0].kind, 'table');
  assert.equal(parsed.revisions[0].entry_count, 3);
  assert.equal(parsed.revisions[0].in_use_entries, 2);
  assert.equal(parsed.revisions[0].root.object_number, 1);
  assert.equal(parsed.startxref_offset, fixture.xref_offset);
});

test('PDF parser reports encryption and active-content markers without executing them', () => {
  const fixture = make_pdf([
    `1 0 obj
<< /Type /Catalog /OpenAction 2 0 R /Names << /JavaScript 3 0 R >> >>
endobj`,
    `2 0 obj
<< /S /JavaScript /JS (app.alert) >>
endobj`,
  ], '<< /Size 4 /Root 1 0 R /Encrypt 4 0 R >>');
  const parsed = parse_pdf(fixture.buffer);
  assert.equal(parsed.encrypted, true);
  assert.equal(parsed.active_content.javascript, true);
  assert.equal(parsed.active_content.open_actions, true);
  assert.equal(parsed.objects[0].markers.open_action, true);
});

test('PDF parser follows incremental /Prev links in descending offset order', () => {
  const base = make_pdf([`1 0 obj
<< /Type /Catalog >>
endobj`], '<< /Size 2 /Root 1 0 R >>');
  const footer = Buffer.from('startxref\n' + base.xref_offset + '\n%%EOF\n', 'ascii');
  const prefix = base.buffer.subarray(0, base.buffer.length - footer.length);
  const updated_xref_offset = prefix.length;
  const update = Buffer.from([
    'xref', '0 2', '0000000000 65535 f ', String(base.offsets[0]).padStart(10, '0') + ' 00000 n ',
    'trailer', '<< /Size 2 /Root 1 0 R /Prev ' + base.xref_offset + ' >>',
    'startxref', String(updated_xref_offset), '%%EOF', '',
  ].join('\n'), 'ascii');
  const parsed = parse_pdf(Buffer.concat([prefix, update]));
  assert.equal(parsed.revisions.length, 2);
  assert.equal(parsed.revisions[0].offset, updated_xref_offset);
  assert.equal(parsed.revisions[1].offset, base.xref_offset);
});

test('PDF parser recognizes xref-stream framing without decoding its entries', () => {
  const prefix = Buffer.from(`%PDF-1.7
7 0 obj
<< /Type /XRef /Size 1 /W [1 2 1] /Length 4 >>
stream
abcd
endstream
endobj
`, 'ascii');
  const xref_offset = prefix.indexOf('7 0 obj');
  const pdf = Buffer.concat([prefix, Buffer.from('startxref\n' + xref_offset + '\n%%EOF\n', 'ascii')]);
  const parsed = parse_pdf(pdf);
  assert.equal(parsed.revisions[0].kind, 'stream');
  assert.equal(parsed.revisions[0].object_number, 7);
  assert.equal(parsed.revisions[0].entries_decoded, false);
});

test('PDF parser enforces count limits and rejects invalid limit configuration', () => {
  const fixture = make_pdf([`1 0 obj
<< /Type /Catalog >>
endobj`]);
  assert.throws(() => parse_pdf(fixture.buffer, { max_objects: 0 }), TypeError);
  assert.throws(() => parse_pdf(fixture.buffer, { max_xref_entries: 1 }), error => error.code === 'ORIX_PDF_XREF_LIMIT');
  assert.throws(() => parse_pdf(fixture.buffer, { max_revisions: 0 }), TypeError);
});

test('PDF parser rejects invalid headers, missing EOF and invalid xref offsets', () => {
  assert.throws(() => parse_pdf(Buffer.from('not a pdf')), error => error.code === 'ORIX_PDF_BAD_HEADER');
  const fixture = make_pdf([`1 0 obj
<< /Type /Catalog >>
endobj`]);
  const no_eof = Buffer.from(fixture.buffer.toString('latin1').replace(/%%EOF\n$/, ''), 'latin1');
  assert.throws(() => parse_pdf(no_eof), error => error.code === 'ORIX_PDF_EOF_MISSING');
  const invalid_offset = Buffer.from(fixture.buffer.toString('latin1').replace(/(startxref\n)\d+(\n%%EOF\n)$/, (match, prefix, suffix) => prefix + '9999999999' + suffix), 'latin1');
  assert.throws(() => parse_pdf(invalid_offset), error => error.code === 'ORIX_PDF_XREF_RANGE');
});

test('PDF format dispatcher returns structural parser output', () => {
  const fixture = make_pdf([`1 0 obj
<< /Type /Catalog >>
endobj`]);
  const result = analyze_known_format(fixture.buffer);
  assert.equal(result.detection.format, 'PDF');
  assert.equal(result.parser_status, 'parsed');
  assert.equal(result.parsed.format, 'PDF');
});
