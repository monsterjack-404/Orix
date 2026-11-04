// JavaScript, tests/har.test.mjs, Node.js 20+, HAR network-analysis regression suite.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parse_har, analyze_har_file, render_har_markdown } from '../src/network/har.mjs';

function make_har(entries = []) {
  return Buffer.from(JSON.stringify({
    log: {
      version: '1.2',
      creator: { name: 'ORIX test', version: '1.0' },
      browser: { name: 'Test Browser', version: '1' },
      pages: [],
      entries,
    },
  }));
}

function entry(overrides = {}) {
  return {
    startedDateTime: '2026-11-04T10:00:00.000Z',
    time: 45,
    request: {
      method: 'GET',
      url: 'https://example.test/private/path?token=secret-value',
      headers: [{ name: 'Cookie', value: 'session=private-cookie-value' }],
      bodySize: 0,
    },
    response: {
      status: 200,
      statusText: 'OK',
      headers: [
        { name: 'Content-Type', value: 'text/html; charset=utf-8' },
        { name: 'Set-Cookie', value: 'session=secret; Path=/; Secure' },
      ],
      content: { size: 128, mimeType: 'text/html', text: '<html>private response body</html>' },
    },
    timings: { send: 1, wait: 30, receive: 14, dns: 0, connect: 0, ssl: 0 },
    serverIPAddress: '203.0.113.10',
    ...overrides,
  };
}

test('HAR parser creates a bounded request inventory and redacts query, cookie, header and body values', () => {
  const report = parse_har(make_har([entry()]));
  assert.equal(report.schema_version, 'orix.har.v1');
  assert.equal(report.source.version, '1.2');
  assert.equal(report.summary.entries_total, 1);
  assert.equal(report.summary.entries_analyzed, 1);
  assert.equal(report.summary.encrypted_requests, 1);
  assert.equal(report.entries[0].url.url, 'https://example.test/private/path');
  assert.deepEqual(report.entries[0].url.query_keys, ['token']);
  assert.deepEqual(report.entries[0].sensitive_request_header_types, ['cookie']);
  const serialized = JSON.stringify(report);
  for (const secret of ['secret-value', 'private-cookie-value', 'response body', 'session=secret']) {
    assert.equal(serialized.includes(secret), false);
  }
  assert.equal(report.privacy.request_bodies_included, false);
  assert.equal(report.privacy.response_bodies_included, false);
  assert.equal(report.integrity.digest.length, 64);
});

test('HAR review findings flag cleartext transport, sensitive credentials and weak cookie attributes', () => {
  const cleartext = entry({
    request: {
      method: 'POST',
      url: 'http://example.test/login',
      headers: [{ name: 'Authorization', value: 'Bearer do-not-print-me' }],
      bodySize: 8,
    },
    response: {
      status: 500,
      statusText: 'Server Error',
      headers: [{ name: 'Set-Cookie', value: 'sid=value; Path=/' }],
      content: { size: 0, mimeType: 'application/json' },
    },
    timings: { send: 2, wait: 20, receive: 3 },
  });
  const report = parse_har(make_har([cleartext]));
  const rules = report.findings.map(item => item.rule_id);
  assert.ok(rules.includes('ORIX-HAR-CLEARTEXT-001'));
  assert.ok(rules.includes('ORIX-HAR-SENSITIVE-OVER-HTTP-001'));
  assert.ok(rules.includes('ORIX-HAR-SERVER-ERROR-001'));
  assert.ok(rules.includes('ORIX-HAR-COOKIE-FLAGS-001'));
  assert.equal(JSON.stringify(report).includes('do-not-print-me'), false);
});

test('HAR parser reports entry truncation explicitly instead of implying complete coverage', () => {
  const report = parse_har(make_har([entry(), entry(), entry()]), { max_entries: 2 });
  assert.equal(report.coverage.complete, false);
  assert.equal(report.coverage.truncated, true);
  assert.equal(report.coverage.omitted_entries, 1);
  assert.equal(report.entries.length, 2);
});

test('HAR parser reports host inventory truncation independently from entry truncation', () => {
  const report = parse_har(make_har([
    entry({ request: { method: 'GET', url: 'https://one.test/' }, response: { status: 200, statusText: 'OK', headers: [], content: { size: 0, mimeType: 'application/json' } } }),
    entry({ request: { method: 'GET', url: 'https://two.test/' }, response: { status: 200, statusText: 'OK', headers: [], content: { size: 0, mimeType: 'application/json' } } }),
  ]), { max_hosts: 1 });
  assert.equal(report.coverage.truncated, false);
  assert.equal(report.coverage.complete, false);
  assert.equal(report.coverage.hosts_complete, false);
  assert.equal(report.coverage.omitted_hosts, 1);
  assert.equal(report.coverage.max_hosts, 1);
  assert.equal(report.summary.unique_hosts, 2);
  assert.equal(report.hosts.length, 1);
});

test('HAR parser rejects malformed roots, unsupported versions, invalid UTF-8 and malformed entries', () => {
  assert.throws(() => parse_har(Buffer.from('{}')), error => error.code === 'ORIX_HAR_INVALID_ROOT');
  assert.throws(() => parse_har(Buffer.from(JSON.stringify({ log: { version: '1.3', entries: [] } }))), error => error.code === 'ORIX_HAR_UNSUPPORTED_VERSION');
  assert.throws(() => parse_har(Buffer.from([0xff, 0xfe])), error => error.code === 'ORIX_HAR_INVALID_UTF8');
  assert.throws(() => parse_har(make_har([{ request: {}, response: {}, timings: {} }])), error => error.code === 'ORIX_HAR_INVALID_METHOD');
});

test('HAR parser rejects non-ISO timestamps and unsafe aggregate byte totals', () => {
  const invalid_time = entry();
  invalid_time.startedDateTime = 'November 4, 2026 10:00:00';
  assert.throws(() => parse_har(make_har([invalid_time])), error => error.code === 'ORIX_HAR_INVALID_TIMESTAMP');

  const first = entry({ request: { method: 'POST', url: 'https://example.test/', bodySize: Number.MAX_SAFE_INTEGER } });
  const second = entry({ request: { method: 'POST', url: 'https://example.test/', bodySize: 1 } });
  assert.throws(() => parse_har(make_har([first, second])), error => error.code === 'ORIX_HAR_TOTAL_OVERFLOW');
});

test('HAR parser enforces byte and entry budgets', () => {
  assert.throws(() => parse_har(make_har([]), { max_bytes: 10 }), error => error.code === 'ORIX_HAR_FILE_TOO_LARGE');
  assert.throws(() => parse_har(make_har([]), { max_entries: 0 }), /max_entries must be/);
  assert.throws(() => parse_har(make_har([]), { max_hosts: 0 }), /max_hosts must be/);
});

test('HAR Markdown renderer escapes hostile creator metadata', () => {
  const document = JSON.parse(make_har([entry()]).toString('utf8'));
  document.log.creator.name = '<img src=x>|[capture]*_' + String.fromCharCode(10) + '## injected';
  document.log.creator.version = '`javascript:alert(1)`';
  const report = parse_har(Buffer.from(JSON.stringify(document)));
  const markdown = render_har_markdown(report);
  assert.equal(markdown.includes('<img src=x>'), false);
  assert.ok(markdown.includes('&lt;img src=x&gt;'));
  assert.equal(markdown.includes(String.fromCharCode(10) + '## injected'), false);
  assert.ok(markdown.includes('\\|'));
  assert.ok(markdown.includes('\\['));
  assert.ok(markdown.includes('\\*'));
  assert.ok(markdown.includes('\\_'));
});

test('HAR file analyzer rejects shared OS temporary paths', async () => {
  await assert.rejects(analyze_har_file(tmpdir()), error => error.code === 'ORIX_HAR_TEMP_PATH_REJECTED');
});

test('HAR file analyzer rejects symlinks and returns a hashed source receipt', async () => {
  const directory = await mkdtemp(path.join(process.cwd(), '.orix-har-'));
  const file = path.join(directory, 'capture.har');
  const link = path.join(directory, 'capture-link.har');
  try {
    await writeFile(file, make_har([entry()]));
    const report = await analyze_har_file(file);
    assert.equal(report.source.name, 'capture.har');
    assert.equal(report.integrity.stable_during_read, true);
    assert.equal(report.integrity.bytes > 0, true);
    await symlink(file, link);
    await assert.rejects(analyze_har_file(link), error => error.code === 'ORIX_HAR_SYMLINK_REJECTED');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('HAR Markdown renderer presents summary and evidence findings without raw payloads', () => {
  const report = parse_har(make_har([entry()]));
  const markdown = render_har_markdown(report);
  assert.match(markdown, /ORIX HAR Investigation/);
  assert.match(markdown, /example\.test/);
  assert.match(markdown, /Privacy and limits/);
  assert.equal(markdown.includes('private-cookie-value'), false);
});
