// JavaScript, tests/playwright-trace.test.mjs, Node.js 20+, offline Playwright trace archive tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { parse_playwright_trace, analyze_playwright_trace_file, render_playwright_trace_markdown } from '../src/network/playwright-trace.mjs';
import { create_zip_entries } from './helpers.mjs';
import { parse_arguments } from '../src/cli/arguments.mjs';


function make_events(overrides = {}) {
  const events = [
    {
      type: 'context-options', version: 9, origin: 'library',
      browserName: 'chromium', playwrightVersion: '1.63.0', platform: 'linux',
      wallTime: 1793880000000, monotonicTime: 10,
      options: { userAgent: 'private-agent', baseURL: 'https://private.example.test/' },
    },
    {
      type: 'before', callId: 'call-1', startTime: 10,
      class: 'Locator', method: 'click', title: 'private title',
      params: { selector: '#secret-selector', value: 'typed-private-value' },
    },
    {
      type: 'console', time: 12, messageType: 'error',
      text: 'private console message must not escape',
      location: { url: 'https://example.test/app.js?token=console-secret', lineNumber: 4, columnNumber: 2 },
    },
    {
      type: 'resource-snapshot',
      snapshot: {
        startedDateTime: '2026-11-05T10:00:00.000Z',
        time: 31,
        request: {
          method: 'GET', url: 'https://example.test/users/12345678901234567890?token=request-secret',
          headers: [{ name: 'Cookie', value: 'private-cookie' }],
          cookies: [{ name: 'sid', value: 'private-cookie' }],
          queryString: [{ name: 'token', value: 'request-secret' }],
          bodySize: 0,
        },
        response: {
          status: 500, statusText: 'Internal Server Error',
          headers: [{ name: 'Set-Cookie', value: 'private-response-cookie' }],
          cookies: [{ name: 'sid', value: 'private-response-cookie' }],
          content: { size: 321, mimeType: 'text/html', text: 'private response body' },
          _failureText: '',
        },
        timings: { dns: 1, connect: 2, wait: 20, receive: 8 },
        _resourceType: 'document',
      },
    },
    {
      type: 'frame-snapshot',
      snapshot: {
        callId: 'call-1', pageId: 'page-1', frameId: 'frame-1',
        frameUrl: 'https://example.test/private?token=dom-secret',
        timestamp: 15, collectionTime: 15, isMainFrame: true,
        viewport: { width: 1280, height: 720 },
        html: ['html', { secret: 'private-dom-attribute' }, 'private DOM text'],
        resourceOverrides: [],
      },
    },
    { type: 'screenshot', callId: 'call-1', phase: 'after', pageId: 'page-1', timestamp: 20, file: 'screenshots/private.png' },
    { type: 'aria-snapshot', callId: 'call-1', phase: 'after', pageId: 'page-1', timestamp: 20, file: 'resources/private.aria' },
    {
      type: 'after', callId: 'call-1', endTime: 22,
      error: { name: 'Error', message: 'private action failure' },
      result: { value: 'private-result' },
      attachments: [{ name: 'private-attachment', contentType: 'text/plain', base64: 'c2VjcmV0' }],
    },
    { type: 'error', message: 'private trace error text' },
  ];
  return events.map(event => ({ ...event, ...(overrides[event.type] ?? {}) }));
}
function make_archive(events = make_events(), method = 8) {
  const trace = Buffer.from(events.map(event => JSON.stringify(event)).join('\n') + '\n', 'utf8');
  return create_zip_entries([
    { name: 'trace.trace', contents: trace, method },
    { name: 'resources/private.bin', contents: Buffer.from('never extract this') },
  ]);
}
function make_data_descriptor_archive({ signature = true, corrupt = false, zip64 = false } = {}) {
  const archive = make_archive();
  const eocd = archive.length - 22;
  const central_offset = archive.readUInt32LE(eocd + 16);
  const local = 0;
  const name_length = archive.readUInt16LE(local + 26);
  const original_extra_length = archive.readUInt16LE(local + 28);
  const compressed_size = archive.readUInt32LE(local + 18);
  const uncompressed_size = archive.readUInt32LE(local + 22);
  const original_data_offset = local + 30 + name_length + original_extra_length;
  const data_end = original_data_offset + compressed_size;
  const extra = zip64 ? Buffer.alloc(20) : Buffer.alloc(0);
  if (zip64) {
    extra.writeUInt16LE(0x0001, 0);
    extra.writeUInt16LE(16, 2);
    extra.writeBigUInt64LE(BigInt(uncompressed_size), 4);
    extra.writeBigUInt64LE(BigInt(compressed_size), 12);
  }
  const descriptor = Buffer.alloc((signature ? 4 : 0) + (zip64 ? 20 : 12));
  let descriptor_offset = 0;
  if (signature) {
    descriptor.writeUInt32LE(0x08074b50, descriptor_offset);
    descriptor_offset += 4;
  }
  const crc = archive.readUInt32LE(local + 14);
  descriptor.writeUInt32LE(corrupt ? (crc ^ 1) >>> 0 : crc, descriptor_offset);
  if (zip64) {
    descriptor.writeBigUInt64LE(BigInt(compressed_size), descriptor_offset + 4);
    descriptor.writeBigUInt64LE(BigInt(uncompressed_size), descriptor_offset + 12);
  } else {
    descriptor.writeUInt32LE(compressed_size, descriptor_offset + 4);
    descriptor.writeUInt32LE(uncompressed_size, descriptor_offset + 8);
  }
  const result = Buffer.concat([
    archive.subarray(0, original_data_offset),
    extra,
    archive.subarray(original_data_offset, data_end),
    descriptor,
    archive.subarray(data_end),
  ]);
  result.writeUInt16LE(result.readUInt16LE(local + 6) | 0x0008, local + 6);
  result.writeUInt32LE(0, local + 14);
  result.writeUInt32LE(zip64 ? 0xffffffff : 0, local + 18);
  result.writeUInt32LE(zip64 ? 0xffffffff : 0, local + 22);
  result.writeUInt16LE(original_extra_length + extra.length, local + 28);
  const shift = extra.length + descriptor.length;
  const shifted_central_offset = central_offset + shift;
  const shifted_eocd = result.length - 22;
  const central_entries = result.readUInt16LE(shifted_eocd + 10);
  let central_cursor = shifted_central_offset;
  for (let index = 0; index < central_entries; index += 1) {
    if (index === 0) {
      result.writeUInt16LE(result.readUInt16LE(central_cursor + 8) | 0x0008, central_cursor + 8);
    }
    const local_offset = result.readUInt32LE(central_cursor + 42);
    if (local_offset >= data_end) result.writeUInt32LE(local_offset + shift, central_cursor + 42);
    const entry_name_length = result.readUInt16LE(central_cursor + 28);
    const entry_extra_length = result.readUInt16LE(central_cursor + 30);
    const comment_length = result.readUInt16LE(central_cursor + 32);
    central_cursor += 46 + entry_name_length + entry_extra_length + comment_length;
  }
  result.writeUInt32LE(shifted_central_offset, shifted_eocd + 16);
  return result;
}

test('trace CLI command parses bounded event, action and request ceilings', () => {
  const parsed = parse_arguments([
    'trace', './recording.zip', '--json',
    '--max-trace-events', '500',
    '--max-trace-actions', '100',
    '--max-trace-requests', '250',
  ]);
  assert.equal(parsed.command, 'trace');
  assert.equal(parsed.target, './recording.zip');
  assert.equal(parsed.flags.format, 'json');
  assert.equal(parsed.flags.max_trace_events, 500);
  assert.equal(parsed.flags.max_trace_actions, 100);
  assert.equal(parsed.flags.max_trace_requests, 250);
  assert.throws(() => parse_arguments(['trace', './recording.zip', '--max-trace-events', '0']), /between 1 and 50000/);
});

test('Playwright trace importer produces a bounded action and network timeline without raw secret values', () => {
  const archive = make_archive();
  const report = parse_playwright_trace(archive);
  assert.equal(report.schema_version, 'orix.playwright-trace.v1');
  assert.equal(report.trace.version, 9);
  assert.equal(report.trace.browser, 'chromium');
  assert.equal(report.summary.events_total, 9);
  assert.equal(report.summary.action_count, 1);
  assert.equal(report.summary.failed_actions, 1);
  assert.equal(report.summary.request_count, 1);
  assert.equal(report.summary.failed_requests, 1);
  assert.equal(report.summary.console_errors, 1);
  assert.equal(report.media.frame_snapshots, 1);
  assert.equal(report.media.screenshots, 1);
  assert.equal(report.media.aria_snapshots, 1);
  assert.equal(report.coverage.complete, true);
  assert.equal(report.integrity.digest.length, 64);
  const serialized = JSON.stringify(report);
  for (const secret of [
    'private-agent', 'private.example.test', 'private title',
    '#secret-selector', 'typed-private-value', 'private console message',
    'console-secret', 'private-cookie', 'request-secret',
    'private response body', 'private-dom-attribute', 'private DOM text',
    'dom-secret', 'private action failure', 'private-result',
    'private-attachment', 'screenshots/private.png', 'resources/private.bin',
  ]) assert.equal(serialized.includes(secret), false, secret);
  assert.ok(report.requests[0].path.includes('[redacted]'));
  assert.equal(report.actions[0].outcome, 'failed');
  assert.deepEqual(report.privacy, {
    action_parameters_included: false,
    action_titles_included: false,
    input_values_included: false,
    console_text_included: false,
    request_headers_included: false,
    cookie_values_included: false,
    query_values_included: false,
    request_bodies_included: false,
    response_bodies_included: false,
    dom_snapshots_included: false,
    screenshot_bytes_included: false,
    resource_files_extracted: false,
    note: report.privacy.note,
  });
});

test('Playwright trace importer validates signed and unsigned ZIP data descriptors', () => {
  for (const signature of [false, true]) {
    const report = parse_playwright_trace(make_data_descriptor_archive({ signature }));
    assert.equal(report.trace.version, 9);
    assert.equal(report.summary.events_analyzed, 9);
  }
});

test('Playwright trace importer validates ZIP64 data descriptors with 64-bit sizes', () => {
  for (const signature of [false, true]) {
    const report = parse_playwright_trace(make_data_descriptor_archive({ signature, zip64: true }));
    assert.equal(report.summary.events_analyzed, 9);
  }
});

test('Playwright trace importer rejects a mismatched ZIP data descriptor', () => {
  assert.throws(
    () => parse_playwright_trace(make_data_descriptor_archive({ signature: true, corrupt: true })),
    error => error.code === 'ORIX_TRACE_DATA_DESCRIPTOR_MISMATCH',
  );
});

test('Playwright trace importer rejects duplicate local-header offsets across ZIP members', () => {
  const archive = make_archive();
  const eocd = archive.length - 22;
  const central = archive.readUInt32LE(eocd + 16);
  const first_name_length = archive.readUInt16LE(central + 28);
  const second_entry = central + 46 + first_name_length;
  archive.writeUInt32LE(0, second_entry + 42);
  assert.throws(
    () => parse_playwright_trace(archive),
    error => error.code === 'ORIX_TRACE_LOCAL_HEADER_SHARED',
  );
});

test('Playwright trace importer rejects payload ranges overlapping the next ZIP local header', () => {
  const archive = make_archive();
  const eocd = archive.length - 22;
  const central = archive.readUInt32LE(eocd + 16);
  const local_name_length = archive.readUInt16LE(0x1a);
  const local_extra_length = archive.readUInt16LE(0x1c);
  const trace_data_offset = 30 + local_name_length + local_extra_length;
  const first_name_length = archive.readUInt16LE(central + 28);
  const second_entry = central + 46 + first_name_length;
  archive.writeUInt32LE(trace_data_offset + 1, second_entry + 42);
  assert.throws(
    () => parse_playwright_trace(archive),
    error => error.code === 'ORIX_TRACE_MEMBER_RANGE',
  );
});

test('Playwright trace importer accepts stored and raw-DEFLATE trace members', () => {
  for (const method of [0, 8]) {
    const report = parse_playwright_trace(make_archive(make_events(), method));
    assert.equal(report.summary.events_analyzed, 9);
  }
});

test('Playwright trace importer rejects missing, unsupported and malformed traces', () => {
  assert.throws(
    () => parse_playwright_trace(create_zip_entries([{ name: 'other.txt', contents: 'no trace' }])),
    error => error.code === 'ORIX_TRACE_MEMBER_MISSING',
  );
  assert.throws(
    () => parse_playwright_trace(make_archive([{ type: 'context-options', version: 10 }])),
    error => error.code === 'ORIX_TRACE_VERSION_UNSUPPORTED',
  );
  assert.throws(
    () => parse_playwright_trace(create_zip_entries([{ name: 'trace.trace', contents: '{bad json}\n' }])),
    error => error.code === 'ORIX_TRACE_CONTEXT_MISSING' || error.code === 'ORIX_TRACE_INVALID_EVENT_JSON',
  );
  assert.throws(
    () => parse_playwright_trace(make_archive(make_events(), 12)),
    error => error.code === 'ORIX_TRACE_COMPRESSION_UNSUPPORTED',
  );
});

test('Playwright trace importer marks event/action/request ceilings as incomplete coverage', () => {
  const events = make_events();
  const report = parse_playwright_trace(make_archive(events), {
    max_events: 4,
    max_actions: 1,
    max_requests: 1,
  });
  assert.equal(report.coverage.complete, false);
  assert.equal(report.coverage.omitted_events, 5);
  assert.equal(report.summary.events_analyzed, 4);
  assert.ok(report.warnings.some(item => item.includes('truncated')));
  assert.throws(() => parse_playwright_trace(make_archive(), { max_line_bytes: 10 }), error => error.code === 'ORIX_TRACE_LINE_TOO_LARGE');
});

test('Playwright trace action ceilings count unique action IDs and mark omissions', () => {
  const events = make_events();
  events.splice(2, 0,
    { type: 'before', callId: 'call-2', startTime: 11, class: 'Page', method: 'goto', params: {} },
    { type: 'after', callId: 'call-2', endTime: 13 },
  );
  const report = parse_playwright_trace(make_archive(events), { max_actions: 1 });
  assert.equal(report.summary.action_count, 1);
  assert.equal(report.coverage.omitted_actions, 1);
  assert.equal(report.coverage.complete, false);
  assert.ok(report.warnings.some(item => item.includes('max_actions')));
});

test('Playwright JSONL scanning bounds retained lines when traces contain many blank records', () => {
  const context = JSON.stringify({ type: 'context-options', version: 9, browserName: 'chromium' });
  const trace = Buffer.from(context + '\n' + '\n'.repeat(300_000), 'utf8');
  const report = parse_playwright_trace(create_zip_entries([{ name: 'trace.trace', contents: trace }]), { max_events: 1 });
  assert.equal(report.summary.events_total, 1);
  assert.equal(report.summary.events_analyzed, 1);
  assert.equal(report.coverage.complete, true);
});

test('Playwright action IDs are sequential and duplicate action updates cannot create negative durations', () => {
  const events = make_events();
  events.splice(2, 0,
    { type: 'before', callId: 'call-2', startTime: 11, class: 'Page', method: 'goto', params: {} },
    { type: 'after', callId: 'call-2', endTime: 13 },
  );
  const report = parse_playwright_trace(make_archive(events));
  assert.deepEqual(report.actions.map(item => item.id), ['action-00001', 'action-00002']);

  const invalid = make_events();
  invalid.splice(7, 0, {
    type: 'action', callId: 'call-1', startTime: 1, endTime: 2, class: 'Locator', method: 'click',
  });
  assert.throws(
    () => parse_playwright_trace(make_archive(invalid)),
    error => error.code === 'ORIX_TRACE_ACTION_TIMING',
  );
});

test('Playwright trace importer rejects archive CRC corruption and non-UTF-8 trace data', () => {
  const corrupt = make_archive();
  corrupt[31] ^= 0x01;
  assert.throws(() => parse_playwright_trace(corrupt), error => String(error.code).startsWith('ORIX_TRACE_'));
  const invalid_utf8 = create_zip_entries([{ name: 'trace.trace', contents: Buffer.from([0xff, 0xfe]) }]);
  assert.throws(() => parse_playwright_trace(invalid_utf8), error => error.code === 'ORIX_TRACE_INVALID_UTF8');
});

test('Playwright trace importer skips unknown event labels without echoing attacker-controlled names', () => {
  const events = make_events();
  events.push({ type: 'private-secret-event-label', secret: 'private-event-value' });
  const report = parse_playwright_trace(make_archive(events));
  const serialized = JSON.stringify(report);
  assert.equal(report.summary.unknown_event_types, 1);
  assert.equal(report.coverage.complete, false);
  assert.equal(serialized.includes('private-secret-event-label'), false);
  assert.equal(serialized.includes('private-event-value'), false);
  assert.ok(report.warnings.some(item => item.includes('Unknown event types')));
});

test('Playwright trace Markdown renderer exposes safe timeline fields only', () => {
  const report = parse_playwright_trace(make_archive());
  const markdown = render_playwright_trace_markdown(report);
  assert.match(markdown, /ORIX Playwright Trace Investigation/);
  assert.match(markdown, /Action timeline/);
  assert.match(markdown, /Privacy and limits/);
  assert.equal(markdown.includes('typed-private-value'), false);
  assert.equal(markdown.includes('private console message'), false);
});

test('Playwright trace file reader records provenance and rejects symlinks and shared temp paths', async () => {
  const fixture_dir = path.dirname(fileURLToPath(import.meta.url));
  const file = path.join(fixture_dir, '.trace-' + process.pid + '-' + Date.now() + '.zip');
  const link = file + '.link';
  try {
    await writeFile(file, make_archive());
    const report = await analyze_playwright_trace_file(file);
    assert.equal(report.source.name, path.basename(file));
    assert.equal(report.integrity.stable_during_read, true);
    assert.equal(report.integrity.bytes > 0, true);
    await symlink(file, link);
    await assert.rejects(analyze_playwright_trace_file(link), error => error.code === 'ORIX_TRACE_SYMLINK_REJECTED');
    await assert.rejects(analyze_playwright_trace_file(tmpdir()), error => error.code === 'ORIX_TRACE_TEMP_PATH_REJECTED');
  } finally {
    await rm(link, { force: true });
    await rm(file, { force: true });
  }
});
