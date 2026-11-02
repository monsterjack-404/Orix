// JavaScript, src/formats/pdf.mjs, Node.js 20+, bounded read-only PDF structure indexer.

import { OrixError } from '../core/errors.mjs';

const MAX_TAIL_BYTES = 1024 * 1024;
const MAX_REVISIONS = 64;
const MAX_XREF_ENTRIES = 1_000_000;
const MAX_OBJECTS = 250_000;
const MAX_OBJECT_SCAN_BYTES = 64 * 1024 * 1024;

function fail(code, message, details = null) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function safe_integer(value, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) fail('ORIX_PDF_UNSAFE_INTEGER', label + ' is not a safe non-negative integer', { value });
  return parsed;
}

function read_line(text, offset, limit) {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= limit) fail('ORIX_PDF_XREF_RANGE', 'Cross-reference offset is outside the file', { offset, limit });
  let end = offset;
  while (end < limit && text.charCodeAt(end) !== 10 && text.charCodeAt(end) !== 13) end += 1;
  let next = end;
  if (text.charCodeAt(next) === 13) next += 1;
  if (text.charCodeAt(next) === 10) next += 1;
  return { line: text.slice(offset, end), next };
}

function parse_classic_xref(text, offset, file_size, limits) {
  const first = read_line(text, offset, file_size);
  if (!/^xref(?:\s|$)/.test(first.line)) {
    const object_match = /^(\d+)\s+(\d+)\s+obj\b/.exec(first.line.trim());
    if (!object_match) fail('ORIX_PDF_XREF_UNSUPPORTED', 'startxref does not point to a classic xref table or an indirect xref-stream object', { offset, line: first.line.slice(0, 80) });
    const dictionary_start = text.indexOf('<<', offset);
    const stream_marker = text.indexOf('stream', dictionary_start);
    const dictionary = dictionary_start >= 0 && stream_marker >= 0 ? text.slice(dictionary_start, stream_marker) : '';
    if (!/\/Type\s*\/XRef\b/.test(dictionary)) fail('ORIX_PDF_XREF_UNSUPPORTED', 'Indirect object at startxref is not a recognized xref stream', { offset });
    const length_match = /\/Length\s+(\d+)\b/.exec(dictionary);
    const length = length_match ? safe_integer(length_match[1], 'xref stream length') : null;
    return { kind: 'stream', offset, object_number: Number(object_match[1]), generation: Number(object_match[2]), stream_length: length, decoded: false, entries_decoded: false };
  }

  let cursor = first.next;
  const entries = [];
  let subsections = 0;
  let trailer_start = -1;
  while (cursor < file_size) {
    const row = read_line(text, cursor, file_size);
    cursor = row.next;
    if (row.line.trim() === 'trailer') { trailer_start = cursor; break; }
    const subsection = /^(\d+)\s+(\d+)\s*$/.exec(row.line.trim());
    if (!subsection) fail('ORIX_PDF_XREF_SUBSECTION', 'Malformed xref subsection header', { offset: cursor, line: row.line.slice(0, 100) });
    const start = safe_integer(subsection[1], 'xref subsection start');
    const count = safe_integer(subsection[2], 'xref subsection count');
    if (count > limits.max_xref_entries - entries.length) fail('ORIX_PDF_XREF_LIMIT', 'Xref entry count exceeds configured limit', { maximum: limits.max_xref_entries });
    subsections += 1;
    for (let index = 0; index < count; index += 1) {
      const entry = read_line(text, cursor, file_size);
      cursor = entry.next;
      const match = /^\s*(\d{10})\s+(\d{5})\s+([nf])(?:\s|$)/.exec(entry.line);
      if (!match) fail('ORIX_PDF_XREF_ENTRY', 'Malformed classic xref entry', { entry_index: index, line: entry.line.slice(0, 80) });
      const object_offset = Number(match[1]);
      const generation = Number(match[2]);
      const in_use = match[3] === 'n';
      if (in_use && object_offset >= file_size) fail('ORIX_PDF_XREF_OBJECT_RANGE', 'In-use xref entry points outside the file', { object_number: start + index, object_offset, file_size });
      entries.push({ object_number: start + index, offset: object_offset, generation, in_use });
    }
  }
  if (trailer_start < 0) fail('ORIX_PDF_TRAILER_MISSING', 'Classic xref table is not followed by a trailer dictionary', { offset: cursor });
  const dictionary_start = text.indexOf('<<', trailer_start);
  const dictionary_end = dictionary_start >= 0 ? text.indexOf('>>', dictionary_start + 2) : -1;
  if (dictionary_start < 0 || dictionary_end < 0 || dictionary_start - trailer_start > 64) fail('ORIX_PDF_TRAILER_MISSING', 'Trailer dictionary is missing or malformed', { offset: trailer_start });
  const trailer = text.slice(dictionary_start, dictionary_end + 2);
  const prev_match = /\/Prev\s+(\d+)\b/.exec(trailer);
  const size_match = /\/Size\s+(\d+)\b/.exec(trailer);
  const root_match = /\/Root\s+(\d+)\s+(\d+)\s+R/.exec(trailer);
  const encrypt_match = /\/Encrypt\s+(\d+)\s+(\d+)\s+R/.exec(trailer);
  return {
    kind: 'table', offset, end_offset: cursor, subsection_count: subsections, entry_count: entries.length,
    in_use_entries: entries.filter(entry => entry.in_use).length,
    free_entries: entries.filter(entry => !entry.in_use).length,
    size: size_match ? safe_integer(size_match[1], 'trailer size') : null,
    root: root_match ? { object_number: Number(root_match[1]), generation: Number(root_match[2]) } : null,
    encrypted: Boolean(encrypt_match),
    prev_offset: prev_match ? safe_integer(prev_match[1], 'previous xref offset') : null,
    entries,
  };
}

function scan_objects(text, limits) {
  const object_pattern = /(?:^|[\r\n])([0-9]{1,10})\s+([0-9]{1,5})\s+obj\b/g;
  const objects = [];
  let match;
  while ((match = object_pattern.exec(text)) !== null) {
    if (objects.length >= limits.max_objects) fail('ORIX_PDF_OBJECT_LIMIT', 'Indirect object count exceeds configured limit', { maximum: limits.max_objects });
    const object_offset = match.index + (match[0].length - match[0].trimStart().length);
    const body_start = object_pattern.lastIndex;
    const end_object = text.indexOf('endobj', body_start);
    if (end_object < 0) {
      objects.push({ object_number: Number(match[1]), generation: Number(match[2]), offset: object_offset, end_offset: null, complete: false });
      continue;
    }
    const body = text.slice(body_start, Math.min(end_object, body_start + limits.max_object_scan_bytes));
    objects.push({
      object_number: Number(match[1]), generation: Number(match[2]), offset: object_offset,
      end_offset: end_object + 6, complete: true,
      has_stream: /stream(?:\r\n|\n|\r)/.test(body),
      markers: {
        javascript: /\/(?:JavaScript|JS)\b/.test(body),
        embedded_file: /\/EmbeddedFile\b/.test(body),
        file_specification: /\/Filespec\b/.test(body),
        open_action: /\/OpenAction\b/.test(body),
        additional_actions: /\/AA\b/.test(body),
        launch_action: /\/Launch\b/.test(body),
      },
    });
    object_pattern.lastIndex = end_object + 6;
  }
  return objects;
}

export function parse_pdf(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('parse_pdf requires a Buffer');
  const limits = {
    max_xref_entries: options.max_xref_entries ?? MAX_XREF_ENTRIES,
    max_revisions: options.max_revisions ?? MAX_REVISIONS,
    max_objects: options.max_objects ?? MAX_OBJECTS,
    max_object_scan_bytes: options.max_object_scan_bytes ?? MAX_OBJECT_SCAN_BYTES,
    max_marker_scan_bytes: options.max_marker_scan_bytes ?? MAX_OBJECT_SCAN_BYTES,
  };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(name + ' must be a positive safe integer');
  }
  if (buffer.length < 8) fail('ORIX_PDF_TRUNCATED_HEADER', 'PDF input is too short to contain a header');
  const text = buffer.toString('latin1');
  const header = /^%PDF-(\d)\.(\d)/.exec(text);
  if (!header) fail('ORIX_PDF_BAD_HEADER', 'PDF header must begin with %PDF-<major>.<minor>');
  const tail_start = Math.max(0, buffer.length - MAX_TAIL_BYTES);
  const tail = text.slice(tail_start);
  const eof_matches = [...tail.matchAll(/%%EOF/g)];
  if (eof_matches.length === 0) fail('ORIX_PDF_EOF_MISSING', 'PDF end-of-file marker was not found in the bounded trailing window');
  const startxref_matches = [...tail.matchAll(/startxref\s+(\d+)\s+%%EOF/g)];
  if (startxref_matches.length === 0) fail('ORIX_PDF_STARTXREF_MISSING', 'PDF startxref pointer was not found before the final EOF marker');
  const last = startxref_matches[startxref_matches.length - 1];
  let xref_offset = safe_integer(last[1], 'startxref');
  const revisions = [];
  const seen_offsets = new Set();
  while (xref_offset !== null) {
    if (revisions.length >= limits.max_revisions) fail('ORIX_PDF_REVISION_LIMIT', 'Incremental update chain exceeds configured limit', { maximum: limits.max_revisions });
    if (seen_offsets.has(xref_offset)) fail('ORIX_PDF_PREV_CYCLE', 'PDF xref /Prev chain contains a cycle', { offset: xref_offset });
    seen_offsets.add(xref_offset);
    const revision = parse_classic_xref(text, xref_offset, buffer.length, limits);
    revisions.push(revision);
    xref_offset = revision.kind === 'table' ? revision.prev_offset : null;
    if (xref_offset !== null && xref_offset >= revisions[revisions.length - 1].offset) fail('ORIX_PDF_PREV_ORDER', 'Incremental xref /Prev pointer must refer to an earlier byte offset', { previous: xref_offset, current: revisions[revisions.length - 1].offset });
  }
  const objects = scan_objects(text, limits);
  const marker_text = text.slice(0, Math.min(text.length, limits.max_marker_scan_bytes));
  const active_content = {
    javascript: /\/(?:JavaScript|JS)\b/.test(marker_text),
    embedded_files: /\/EmbeddedFile\b/.test(marker_text),
    file_specifications: /\/Filespec\b/.test(marker_text),
    open_actions: /\/OpenAction\b/.test(marker_text),
    additional_actions: /\/AA\b/.test(marker_text),
    launch_actions: /\/Launch\b/.test(marker_text),
  };
  const encrypted = revisions.some(revision => revision.encrypted) || /\/Encrypt\s+\d+\s+\d+\s+R/.test(marker_text);
  return {
    format: 'PDF', version: header[1] + '.' + header[2], file_size: buffer.length,
    header_offset: 0, eof_marker_count: eof_matches.length,
    startxref_offset: Number(last[1]), revisions: revisions.map(({ entries, ...revision }) => revision),
    xref_entry_count: revisions.reduce((total, revision) => total + (revision.entry_count ?? 0), 0),
    objects, object_count: objects.length, encrypted, active_content,
    notes: [
      'Classic xref tables, trailer metadata, incremental /Prev links and indirect-object framing are indexed without executing document content.',
      'Xref streams are recognized by their object dictionary but their compressed entry stream is not decoded; object streams, filters, page-tree semantics and cryptographic signatures are not validated.',
      'Marker matches are lexical triage hints, not proof that an action is reachable or will execute. Stream payloads are not decompressed.',
    ],
  };
}
