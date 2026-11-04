// JavaScript, src/network/har.mjs, Node.js 20+, bounded read-only HAR 1.2 analysis.
import { constants as FS_CONSTANTS, promises as fs } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';
import { OrixError } from '../core/errors.mjs';

const DEFAULT_MAX_BYTES = 32 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES = 20_000;
const HARD_MAX_ENTRIES = 100_000;
const DEFAULT_MAX_HOSTS = 5_000;
const HARD_MAX_HOSTS = 10_000;
const MAX_HEADER_NAME = 256;

function fail(code, message, details = null) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function safe_limit(value, fallback, name, maximum) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum) {
    throw new TypeError(name + ' must be a safe integer between 1 and ' + maximum);
  }
  return selected;
}

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function bounded_text(value, maximum = 256) {
  return typeof value === 'string' ? value.slice(0, maximum) : null;
}

function markdown_escape(value) {
  const slash = String.fromCharCode(92);
  return String(value ?? '')
    .replaceAll('\\r', ' ')
    .replaceAll('\\n', ' ')
    .replaceAll('\\t', ' ')
    .replaceAll(slash, slash + slash)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('|', slash + '|')
    .replaceAll('`', slash + '`')
    .replaceAll('[', slash + '[')
    .replaceAll(']', slash + ']')
    .replaceAll('*', slash + '*')
    .replaceAll('_', slash + '_');
}

function header_index(headers, label) {
  if (headers === undefined) return new Map();
  if (!Array.isArray(headers)) fail('ORIX_HAR_INVALID_HEADERS', label + ' headers must be an array');
  const result = new Map();
  for (let index = 0; index < headers.length; index += 1) {
    const header = headers[index];
    if (!object(header) || typeof header.name !== 'string' || header.name.length === 0 || header.name.length > MAX_HEADER_NAME) {
      fail('ORIX_HAR_INVALID_HEADER', label + ' contains an invalid header name', { index });
    }
    const name = header.name.toLowerCase();
    const values = result.get(name) ?? [];
    // Values are held only in memory long enough to classify flags. They are never copied to the report.
    values.push(typeof header.value === 'string' ? header.value.slice(0, 8192) : '');
    result.set(name, values);
  }
  return result;
}

function safe_url(raw, entry_index) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 16_384) {
    fail('ORIX_HAR_INVALID_URL', 'HAR request URL must be a non-empty bounded string', { entry_index });
  }
  let parsed;
  try { parsed = new URL(raw); }
  catch { fail('ORIX_HAR_INVALID_URL', 'HAR request URL is not a valid absolute URL', { entry_index }); }
  const query_keys = [...new Set([...parsed.searchParams.keys()])].sort().slice(0, 100);
  const safe_path = parsed.pathname.slice(0, 2048) || '/';
  return {
    url: parsed.protocol + '//' + parsed.host + safe_path,
    scheme: parsed.protocol.replace(/:$/, '').toLowerCase(),
    host: parsed.hostname.toLowerCase(),
    port: parsed.port || null,
    path: safe_path,
    query_keys,
    has_credentials: Boolean(parsed.username || parsed.password),
  };
}

function add_safe_total(current, value, label, entry_index) {
  if (value > Number.MAX_SAFE_INTEGER - current) {
    fail('ORIX_HAR_TOTAL_OVERFLOW', label + ' exceeds safe integer precision', { entry_index, current, value });
  }
  return current + value;
}

function valid_time(value, label, entry_index, allow_unknown = false) {
  if (allow_unknown && value === -1) return -1;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 86_400_000) {
    fail('ORIX_HAR_INVALID_TIMING', label + ' must be a finite non-negative number' + (allow_unknown ? ' or -1' : ''), { entry_index, value });
  }
  return value;
}

function cookie_flags(set_cookie_values) {
  return set_cookie_values.map(value => ({
    secure: /(?:^|;)\s*secure(?:\s*;|$)/i.test(value),
    http_only: /(?:^|;)\s*httponly(?:\s*;|$)/i.test(value),
    same_site: /(?:^|;)\s*samesite\s*=/i.test(value),
  }));
}

function push_finding(findings, evidence, entry, rule_id, severity, confidence, summary, details = {}) {
  const evidence_id = 'har-ev-' + String(entry.index + 1).padStart(6, '0');
  findings.push({
    rule_id, severity, confidence, summary,
    location: { entry_index: entry.index, url: entry.url.url, method: entry.method, status: entry.status },
    evidence_ids: [evidence_id],
    details,
  });
  return evidence_id;
}

/**
 * Parse HAR 1.2 metadata without retaining request/response bodies, cookie values,
 * authorization values, query values, or arbitrary header values in the report.
 */
export function parse_har(input, options = {}) {
  if (!Buffer.isBuffer(input)) throw new TypeError('parse_har requires a Buffer');
  const max_bytes = safe_limit(options.max_bytes, DEFAULT_MAX_BYTES, 'max_bytes', DEFAULT_MAX_BYTES);
  const max_entries = safe_limit(options.max_entries, DEFAULT_MAX_ENTRIES, 'max_entries', HARD_MAX_ENTRIES);
  const max_hosts = safe_limit(options.max_hosts, DEFAULT_MAX_HOSTS, 'max_hosts', HARD_MAX_HOSTS);
  if (input.length > max_bytes) fail('ORIX_HAR_FILE_TOO_LARGE', 'HAR input exceeds the configured byte ceiling', { size_bytes: input.length, max_bytes });

  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(input); }
  catch { fail('ORIX_HAR_INVALID_UTF8', 'HAR input must be valid UTF-8'); }
  let document;
  try { document = JSON.parse(text); }
  catch (error) { fail('ORIX_HAR_INVALID_JSON', 'HAR input is not valid JSON', { message: String(error.message).slice(0, 200) }); }
  if (!object(document) || !object(document.log)) fail('ORIX_HAR_INVALID_ROOT', 'HAR document must contain a log object');
  const log = document.log;
  if (log.version !== '1.2') fail('ORIX_HAR_UNSUPPORTED_VERSION', 'Only HAR 1.2 is currently supported', { version: bounded_text(log.version, 40) });
  if (!object(log.creator) || typeof log.creator.name !== 'string' || typeof log.creator.version !== 'string') {
    fail('ORIX_HAR_INVALID_CREATOR', 'HAR log.creator must include name and version strings');
  }
  if (!Array.isArray(log.entries)) fail('ORIX_HAR_INVALID_ENTRIES', 'HAR log.entries must be an array');
  if (log.pages !== undefined && !Array.isArray(log.pages)) fail('ORIX_HAR_INVALID_PAGES', 'HAR log.pages must be an array when present');

  const findings = [];
  const evidence = [];
  const hosts = new Map();
  const methods = Object.create(null);
  const statuses = Object.create(null);
  const timings = { blocked: 0, dns: 0, connect: 0, send: 0, wait: 0, receive: 0, ssl: 0 };
  const analyzed_entries = Math.min(log.entries.length, max_entries);
  let request_bytes = 0;
  let response_bytes = 0;
  let encrypted_requests = 0;
  let cleartext_requests = 0;
  let redirect_count = 0;
  let error_count = 0;
  const entries = [];

  for (let index = 0; index < analyzed_entries; index += 1) {
    const raw = log.entries[index];
    if (!object(raw) || !object(raw.request) || !object(raw.response) || !object(raw.timings)) {
      fail('ORIX_HAR_INVALID_ENTRY', 'HAR entry must contain request, response and timings objects', { entry_index: index });
    }
    const request = raw.request;
    const response = raw.response;
    if (typeof request.method !== 'string' || request.method.length === 0 || request.method.length > 32) {
      fail('ORIX_HAR_INVALID_METHOD', 'HAR request method must be a bounded non-empty string', { entry_index: index });
    }
    if (!Number.isSafeInteger(response.status) || response.status < 0 || response.status > 999) {
      fail('ORIX_HAR_INVALID_STATUS', 'HAR response status must be an integer from 0 to 999', { entry_index: index, status: response.status });
    }
    if (typeof raw.startedDateTime !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(raw.startedDateTime) || !Number.isFinite(Date.parse(raw.startedDateTime))) {
      fail('ORIX_HAR_INVALID_TIMESTAMP', 'HAR entry startedDateTime must be a parseable date-time', { entry_index: index });
    }
    const total_time = valid_time(raw.time, 'entry.time', index);
    const url = safe_url(request.url, index);
    const request_headers = header_index(request.headers, 'request');
    const response_headers = header_index(response.headers, 'response');
    const phases = {};
    for (const phase of Object.keys(timings)) {
      const value = raw.timings[phase];
      if (value === undefined) { phases[phase] = null; continue; }
      phases[phase] = valid_time(value, 'timings.' + phase, index, true);
      if (phases[phase] > 0) timings[phase] = add_safe_total(timings[phase], phases[phase], 'timings.' + phase, index);
    }
    for (const required of ['send', 'wait', 'receive']) {
      if (phases[required] === null) fail('ORIX_HAR_REQUIRED_TIMING', 'HAR timings.' + required + ' is required', { entry_index: index });
    }

    const method = request.method.toUpperCase();
    const status = response.status;
    const content = object(response.content) ? response.content : {};
    const response_size = Number.isSafeInteger(content.size) && content.size >= 0 ? content.size : null;
    const request_size = Number.isSafeInteger(request.bodySize) && request.bodySize >= 0 ? request.bodySize : null;
    const mime_type = bounded_text(content.mimeType, 160);
    const set_cookie = response_headers.get('set-cookie') ?? [];
    const cookie_analysis = cookie_flags(set_cookie);
    const sensitive_request_headers = ['authorization', 'proxy-authorization', 'cookie'].filter(name => request_headers.has(name));
    const entry = {
      index,
      started_at: raw.startedDateTime,
      method,
      url,
      status,
      status_text: bounded_text(response.statusText, 120),
      total_time_ms: total_time,
      request_size_bytes: request_size,
      response_size_bytes: response_size,
      mime_type,
      request_header_names: [...request_headers.keys()].sort(),
      response_header_names: [...response_headers.keys()].sort(),
      sensitive_request_header_types: sensitive_request_headers,
      response_cookie_count: set_cookie.length,
      response_cookie_flags: cookie_analysis,
      redirect: status >= 300 && status < 400,
      timings: phases,
      server_ip_address: typeof raw.serverIPAddress === 'string' && raw.serverIPAddress.length <= 64 ? raw.serverIPAddress : null,
      url_has_credentials: url.has_credentials,
    };
    entries.push(entry);
    evidence.push({
      id: 'har-ev-' + String(index + 1).padStart(6, '0'),
      kind: 'http-transaction',
      source_index: index,
      summary: method + ' ' + url.host + url.path + ' returned HTTP ' + status,
      confidence: 'observed',
      fields: ['started_at', 'method', 'url', 'status', 'total_time_ms', 'request_header_names', 'response_header_names', 'timings'],
    });

    methods[method] = (methods[method] ?? 0) + 1;
    statuses[String(status)] = (statuses[String(status)] ?? 0) + 1;
    if (request_size !== null) request_bytes = add_safe_total(request_bytes, request_size, 'request bytes', index);
    if (response_size !== null) response_bytes = add_safe_total(response_bytes, response_size, 'response bytes', index);
    if (status >= 300 && status < 400) redirect_count += 1;
    if (status >= 400 || status === 0) error_count += 1;
    if (url.scheme === 'https') encrypted_requests += 1;
    else if (url.scheme === 'http') cleartext_requests += 1;
    const host_record = hosts.get(url.host) ?? { host: url.host, requests: 0, bytes_received: 0, error_responses: 0, schemes: new Set() };
    host_record.requests += 1;
    host_record.bytes_received = add_safe_total(host_record.bytes_received, response_size ?? 0, 'host response bytes', index);
    if (status >= 400 || status === 0) host_record.error_responses += 1;
    host_record.schemes.add(url.scheme);
    hosts.set(url.host, host_record);

    if (url.scheme === 'http') {
      push_finding(findings, evidence, entry, 'ORIX-HAR-CLEARTEXT-001', 'medium', 'observed',
        'Request used unencrypted HTTP transport', { sensitive_headers_present: sensitive_request_headers.length > 0 });
      if (sensitive_request_headers.length > 0) {
        push_finding(findings, evidence, entry, 'ORIX-HAR-SENSITIVE-OVER-HTTP-001', 'high', 'observed',
          'Authentication or cookie header was sent over unencrypted HTTP', { header_types: sensitive_request_headers });
      }
    }
    if (url.has_credentials) {
      push_finding(findings, evidence, entry, 'ORIX-HAR-URL-CREDENTIALS-001', 'medium', 'observed',
        'Request URL contains embedded user information; the values were redacted');
    }
    if (status >= 500) {
      push_finding(findings, evidence, entry, 'ORIX-HAR-SERVER-ERROR-001', 'low', 'observed',
        'Server returned an HTTP 5xx response', { status });
    }
    if (url.scheme === 'https' && !response_headers.has('strict-transport-security')) {
      push_finding(findings, evidence, entry, 'ORIX-HAR-MISSING-HSTS-001', 'info', 'heuristic',
        'HTTPS response did not include Strict-Transport-Security', { review_scope: 'origin policy; inspect representative responses before drawing a conclusion' });
    }
    if (mime_type && /(?:text\/html|application\/xhtml\+xml)/i.test(mime_type) && !response_headers.has('content-security-policy')) {
      push_finding(findings, evidence, entry, 'ORIX-HAR-MISSING-CSP-001', 'low', 'heuristic',
        'HTML response did not include Content-Security-Policy', { review_scope: 'policy may be delivered by a different response or deployment layer' });
    }
    const missing_cookie_flags = cookie_analysis.filter(item => !item.secure || !item.http_only || !item.same_site);
    if (missing_cookie_flags.length > 0) {
      push_finding(findings, evidence, entry, 'ORIX-HAR-COOKIE-FLAGS-001', 'low', 'observed',
        'One or more response cookies omit Secure, HttpOnly or SameSite attributes', {
          cookie_count: missing_cookie_flags.length,
          missing_secure: missing_cookie_flags.filter(item => !item.secure).length,
          missing_http_only: missing_cookie_flags.filter(item => !item.http_only).length,
          missing_same_site: missing_cookie_flags.filter(item => !item.same_site).length,
        });
    }
  }

  const host_list = [...hosts.values()].map(item => ({
    ...item,
    schemes: [...item.schemes].sort(),
  })).sort((a, b) => b.requests - a.requests || a.host.localeCompare(b.host)).slice(0, max_hosts);
  const hosts_truncated = hosts.size > host_list.length;
  const totals = Object.values(timings).reduce((sum, value) => sum + value, 0);
  const truncated = analyzed_entries < log.entries.length;
  return {
    schema_version: 'orix.har.v1',
    source: {
      format: 'HAR',
      version: log.version,
      creator: { name: bounded_text(log.creator.name, 160), version: bounded_text(log.creator.version, 80) },
      browser: object(log.browser) ? { name: bounded_text(log.browser.name, 160), version: bounded_text(log.browser.version, 80) } : null,
      page_count: Array.isArray(log.pages) ? log.pages.length : 0,
    },
    integrity: { algorithm: 'sha256', digest: createHash('sha256').update(input).digest('hex'), bytes: input.length },
    summary: {
      entries_total: log.entries.length,
      entries_analyzed: analyzed_entries,
      unique_hosts: hosts.size,
      methods,
      statuses,
      request_bytes: request_bytes,
      response_bytes: response_bytes,
      encrypted_requests,
      cleartext_requests,
      redirect_count,
      error_count,
      timing_totals_ms: timings,
      summed_phase_time_ms: totals,
    },
    coverage: {
      complete: !truncated && !hosts_truncated,
      truncated,
      omitted_entries: Math.max(0, log.entries.length - analyzed_entries),
      max_entries,
      hosts_complete: !hosts_truncated,
      omitted_hosts: Math.max(0, hosts.size - host_list.length),
      max_hosts,
    },
    hosts: host_list,
    entries,
    findings,
    evidence,
    privacy: {
      request_bodies_included: false,
      response_bodies_included: false,
      header_values_included: false,
      cookie_values_included: false,
      query_values_included: false,
      note: 'Bodies, header values, cookie values and query parameter values are excluded from this report. URL paths and server IP addresses may still contain sensitive information; review before sharing.',
    },
    warnings: [
      ...(truncated ? ['Entry analysis was truncated by max_entries; findings cover only analyzed entries.'] : []),
      ...(hosts_truncated ? ['Host inventory was truncated at max_hosts; the unique-host summary still counts all analyzed entries.'] : []),
      'HAR data is a browser/proxy capture supplied by the user, not independently verified live network traffic.',
      'Missing-header and cookie findings are review leads, not proof of exploitability or a complete web security assessment.',
    ],
  };
}

export async function analyze_har_file(file_path, options = {}) {
  if (typeof file_path !== 'string' || file_path.length === 0) throw new TypeError('file_path must be a non-empty string');
  const max_bytes = safe_limit(options.max_bytes, DEFAULT_MAX_BYTES, 'max_bytes', DEFAULT_MAX_BYTES);
  const absolute = path.resolve(file_path);
  let before;
  try { before = await fs.lstat(absolute); }
  catch (error) { throw new OrixError('ORIX_HAR_FILE_UNAVAILABLE', 'Cannot access HAR file', { cause: error, details: { system_code: error.code ?? null }, recoverable: true }); }
  if (before.isSymbolicLink()) fail('ORIX_HAR_SYMLINK_REJECTED', 'HAR analyzer does not follow symbolic links', { path: absolute });
  if (!before.isFile()) fail('ORIX_HAR_NOT_REGULAR_FILE', 'HAR analyzer accepts regular files only', { path: absolute });
  if (!Number.isSafeInteger(before.size) || before.size < 1 || before.size > max_bytes) {
    fail('ORIX_HAR_FILE_TOO_LARGE', 'HAR file size is empty, unsafe or above the configured byte ceiling', { size_bytes: before.size, max_bytes });
  }
  let handle;
  try {
    const no_follow = FS_CONSTANTS.O_NOFOLLOW ?? 0;
    handle = await fs.open(absolute, FS_CONSTANTS.O_RDONLY | no_follow);
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== before.size || String(opened.ino) !== String(before.ino) || String(opened.dev) !== String(before.dev)) {
      fail('ORIX_HAR_FILE_REPLACED', 'HAR file identity changed between metadata lookup and open');
    }
    if (!Number.isSafeInteger(opened.size) || opened.size < 1 || opened.size > max_bytes) {
      fail('ORIX_HAR_FILE_TOO_LARGE', 'Opened HAR file exceeds the configured byte ceiling', { size_bytes: opened.size, max_bytes });
    }
    const input = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < input.length) {
      const { bytesRead } = await handle.read(input, offset, input.length - offset, offset);
      if (bytesRead === 0) fail('ORIX_HAR_FILE_CHANGED', 'HAR file ended during the bounded read', { bytes_read: offset, expected_bytes: opened.size });
      offset += bytesRead;
    }
    const after = await handle.stat();
    const stable = opened.size === after.size && opened.mtimeMs === after.mtimeMs && opened.ctimeMs === after.ctimeMs;
    const report = parse_har(input, options);
    report.source.path = absolute;
    report.source.name = path.basename(absolute);
    report.source.modified_at = opened.mtime.toISOString();
    report.integrity.stable_during_read = stable;
    if (!stable) report.warnings.push('HAR file metadata changed while it was read; repeat analysis against a stable copy.');
    return report;
  } catch (error) {
    if (error instanceof OrixError || error instanceof TypeError) throw error;
    throw new OrixError('ORIX_HAR_READ_FAILED', 'Unable to read HAR file safely', { cause: error, recoverable: true });
  } finally {
    await handle?.close();
  }
}

export function render_har_markdown(report) {
  if (!report || report.schema_version !== 'orix.har.v1') throw new TypeError('render_har_markdown requires an orix.har.v1 report');
  const lines = [
    '# ORIX HAR Investigation',
    '',
    '- Source: ' + markdown_escape(report.source.name ?? 'in-memory HAR'),
    '- HAR version: ' + report.source.version,
    '- Creator: ' + markdown_escape(report.source.creator.name) + ' ' + markdown_escape(report.source.creator.version),
    '- SHA-256: ' + report.integrity.digest,
    '- Requests: ' + report.summary.entries_analyzed + ' / ' + report.summary.entries_total,
    '- Hosts: ' + report.summary.unique_hosts,
    '- HTTP / HTTPS: ' + report.summary.cleartext_requests + ' / ' + report.summary.encrypted_requests,
    '- Errors: ' + report.summary.error_count + ' · Redirects: ' + report.summary.redirect_count,
    '',
    '## Findings',
    '',
    ...(report.findings.length ? report.findings.map(item => '- **' + item.severity.toUpperCase() + '** ' + item.rule_id + ' — ' + item.summary + ' (entry ' + item.location.entry_index + ')') : ['- No configured HAR review rules matched.']),
    '',
    '## Hosts',
    '',
    '| Host | Requests | Response bytes | Errors | Schemes |',
    '|---|---:|---:|---:|---|',
    ...report.hosts.slice(0, 100).map(item => '| ' + item.host.replace(/\|/g, '') + ' | ' + item.requests + ' | ' + item.bytes_received + ' | ' + item.error_responses + ' | ' + item.schemes.join(', ') + ' |'),
    '',
    '## Privacy and limits',
    '',
    report.privacy.note,
    ...report.warnings.map(item => '- ' + item),
    '',
  ];
  return lines.join('\n');
}
