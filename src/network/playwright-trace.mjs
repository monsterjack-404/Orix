// JavaScript, src/network/playwright-trace.mjs, Node.js 20+, bounded offline Playwright trace import.
import { constants as FS_CONSTANTS, promises as fs } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { TextDecoder } from 'node:util';
import { inflateRawSync } from 'node:zlib';
import { parse_zip } from '../formats/zip.mjs';
import { OrixError } from '../core/errors.mjs';

const DEFAULTS = Object.freeze({
  max_archive_bytes: 32 * 1024 * 1024,
  max_entries: 20_000,
  max_trace_bytes: 16 * 1024 * 1024,
  max_events: 50_000,
  max_line_bytes: 1024 * 1024,
  max_actions: 10_000,
  max_requests: 20_000,
  max_pages: 2_000,
});
const SUPPORTED_TRACE_VERSIONS = new Set([8, 9]);
const IDENTIFIER = /^[A-Za-z][A-Za-z0-9_$]{0,63}$/;
const TRACE_EVENT_TYPES = new Set(['context-options', 'before', 'after', 'action', 'event', 'console', 'resource-snapshot', 'frame-snapshot', 'screenshot', 'aria-snapshot', 'screencast-frame', 'video', 'error', 'input', 'log', 'stdout', 'stderr']);
const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE']);

function fail(code, message, details = null) {
  throw new OrixError(code, message, { details, recoverable: true });
}
function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function positive_limit(value, fallback, name, maximum = fallback) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum) {
    throw new TypeError(name + ' must be a safe integer between 1 and ' + maximum);
  }
  return selected;
}
function limits_for(options) {
  const result = {};
  for (const [key, fallback] of Object.entries(DEFAULTS)) {
    result[key] = positive_limit(options[key], fallback, key, fallback);
  }
  return result;
}
function u16(buffer, offset) {
  if (offset < 0 || offset > buffer.length - 2) fail('ORIX_TRACE_ZIP_BOUNDS', 'ZIP local header is truncated', { offset });
  return buffer.readUInt16LE(offset);
}
function u32(buffer, offset) {
  if (offset < 0 || offset > buffer.length - 4) fail('ORIX_TRACE_ZIP_BOUNDS', 'ZIP local header is truncated', { offset });
  return buffer.readUInt32LE(offset);
}
function u64_safe(buffer, offset, end) {
  if (offset < 0 || offset > end - 8) fail('ORIX_TRACE_ZIP_BOUNDS', 'ZIP64 data descriptor is truncated', { offset });
  const value = buffer.readBigUInt64LE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail('ORIX_TRACE_ZIP64_RANGE', 'ZIP64 data descriptor exceeds safe integer precision', { offset });
  return Number(value);
}
function crc32(buffer) {
  let value = 0xffffffff;
  for (const byte of buffer) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0);
    }
  }
  return (value ^ 0xffffffff) >>> 0;
}
function entry_name_matches(buffer, offset, length, expected, utf8) {
  const bytes = buffer.subarray(offset, offset + length);
  const actual = bytes.toString(utf8 ? 'utf8' : 'latin1');
  return actual === expected;
}

/** Read only the trace JSONL member; never extracts archive resources to disk. */
function read_trace_member(archive, entry, central_directory_offset, max_bytes, archive_entries) {
  if (entry.unsafe_path || entry.is_symlink || entry.is_directory) {
    fail('ORIX_TRACE_UNSAFE_ENTRY', 'Playwright trace member has an unsafe archive path or file type', { name: 'trace.trace' });
  }
  if (entry.encrypted) fail('ORIX_TRACE_ENCRYPTED', 'Encrypted Playwright trace members are not supported');
  if (!entry.local_header_valid || !entry.local_data_range_valid) {
    fail('ORIX_TRACE_LOCAL_HEADER', 'Playwright trace member has an invalid local ZIP header or data range');
  }
  if (entry.uncompressed_size > max_bytes || entry.compressed_size > max_bytes) {
    fail('ORIX_TRACE_MEMBER_TOO_LARGE', 'Playwright trace member exceeds its compressed or expanded byte ceiling', {
      compressed_bytes: entry.compressed_size,
      uncompressed_bytes: entry.uncompressed_size,
      max_bytes,
    });
  }
  const local = entry.local_header_offset;
  if (!Number.isSafeInteger(local) || local < 0 || local > archive.length - 30 || u32(archive, local) !== 0x04034b50) {
    fail('ORIX_TRACE_LOCAL_HEADER', 'Playwright trace member local header is invalid');
  }
  let member_boundary = central_directory_offset;
  for (const other of archive_entries) {
    if (other === entry) continue;
    if (other.local_header_offset === local) {
      fail('ORIX_TRACE_LOCAL_HEADER_SHARED', 'Another ZIP entry reuses the trace member local-header offset');
    }
    if (Number.isSafeInteger(other.local_header_offset) && other.local_header_offset > local &&
        other.local_header_offset < member_boundary) {
      member_boundary = other.local_header_offset;
    }
  }
  const flags = u16(archive, local + 6);
  const method = u16(archive, local + 8);
  const name_length = u16(archive, local + 26);
  const extra_length = u16(archive, local + 28);
  const descriptor = Boolean(flags & 0x0008);
  const local_crc = u32(archive, local + 14);
  const local_compressed_size = u32(archive, local + 18);
  const local_uncompressed_size = u32(archive, local + 22);
  const expected_crc = Number.parseInt(entry.crc32.slice(2), 16) >>> 0;
  const method_ids = { stored: 0, deflate: 8, deflate64: 9, bzip2: 12, lzma: 14, zstandard: 93, xpress: 95, 'aes-wrapper': 99 };
  const expected_method = method_ids[entry.compression_method] ??
    (entry.compression_method.startsWith('unknown-') ? Number(entry.compression_method.slice(8)) : -1);
  const allowed_flags = 0x0808 | (method === 8 ? 0x0006 : 0);
  if (Boolean(flags & 0x0001) || (flags & ~allowed_flags) !== 0 ||
      method !== expected_method || descriptor !== entry.data_descriptor ||
      Boolean(flags & 0x0800) !== entry.utf8_name) {
    fail('ORIX_TRACE_LOCAL_HEADER_MISMATCH', 'Trace local-header flags or compression method are inconsistent');
  }
  if (!entry_name_matches(archive, local + 30, name_length, entry.name, Boolean(flags & 0x0800))) {
    fail('ORIX_TRACE_LOCAL_NAME_MISMATCH', 'Trace local-header name does not match the central directory');
  }
  const data_offset = local + 30 + name_length + extra_length;
  if (!Number.isSafeInteger(data_offset) || data_offset > member_boundary ||
      entry.compressed_size > member_boundary - data_offset) {
    fail('ORIX_TRACE_MEMBER_RANGE', 'Trace compressed data overlaps another ZIP entry or archive directory boundary');
  }
  if (!descriptor) {
    if (local_crc !== expected_crc || local_compressed_size !== entry.compressed_size ||
        local_uncompressed_size !== entry.uncompressed_size) {
      fail('ORIX_TRACE_LOCAL_SIZE_MISMATCH', 'Trace local-header sizes or CRC do not match the central directory');
    }
  } else {
    const local_crc_mismatch = local_crc !== 0 && local_crc !== expected_crc;
    const local_compressed_mismatch = local_compressed_size !== 0 && local_compressed_size !== 0xffffffff &&
      local_compressed_size !== entry.compressed_size;
    const local_uncompressed_mismatch = local_uncompressed_size !== 0 && local_uncompressed_size !== 0xffffffff &&
      local_uncompressed_size !== entry.uncompressed_size;
    if (local_crc_mismatch || local_compressed_mismatch || local_uncompressed_mismatch) {
      fail('ORIX_TRACE_LOCAL_SIZE_MISMATCH', 'Trace local-header placeholder values conflict with the central directory');
    }
    const zip64_descriptor = local_compressed_size === 0xffffffff || local_uncompressed_size === 0xffffffff;
    const descriptor_offset = data_offset + entry.compressed_size;
    const descriptor_width = zip64_descriptor ? 20 : 12;
    const has_valid_descriptor = (candidate, has_signature) => {
      const start = candidate + (has_signature ? 4 : 0);
      if (start < candidate || start > member_boundary - descriptor_width) return false;
      const descriptor_crc = u32(archive, start);
      const descriptor_compressed = zip64_descriptor
        ? u64_safe(archive, start + 4, central_directory_offset)
        : u32(archive, start + 4);
      const descriptor_uncompressed = zip64_descriptor
        ? u64_safe(archive, start + 12, central_directory_offset)
        : u32(archive, start + 8);
      return descriptor_crc === expected_crc &&
        descriptor_compressed === entry.compressed_size &&
        descriptor_uncompressed === entry.uncompressed_size;
    };
    const signature_present = descriptor_offset <= member_boundary - 4 &&
      u32(archive, descriptor_offset) === 0x08074b50;
    const descriptor_valid = has_valid_descriptor(descriptor_offset, false) ||
      (signature_present && has_valid_descriptor(descriptor_offset, true));
    if (!descriptor_valid) {
      fail('ORIX_TRACE_DATA_DESCRIPTOR_MISMATCH', 'Trace ZIP data descriptor does not match its central-directory CRC or sizes');
    }
  }
  const compressed = archive.subarray(data_offset, data_offset + entry.compressed_size);
  let expanded;
  try {
    if (entry.compression_method === 'stored') expanded = Buffer.from(compressed);
    else if (entry.compression_method === 'deflate') {
      expanded = inflateRawSync(compressed, { maxOutputLength: max_bytes });
    } else {
      fail('ORIX_TRACE_COMPRESSION_UNSUPPORTED', 'Only stored and raw-DEFLATE Playwright trace entries are supported', {
        compression_method: entry.compression_method,
      });
    }
  } catch (error) {
    if (error instanceof OrixError) throw error;
    fail('ORIX_TRACE_DECOMPRESSION_FAILED', 'Playwright trace member could not be safely decompressed', {
      system_code: error?.code ?? null,
    });
  }
  if (expanded.length !== entry.uncompressed_size || expanded.length > max_bytes) {
    fail('ORIX_TRACE_EXPANDED_SIZE_MISMATCH', 'Expanded trace size does not match its bounded ZIP metadata');
  }
  if (crc32(expanded) !== expected_crc) {
    fail('ORIX_TRACE_CRC_MISMATCH', 'Playwright trace member failed CRC32 integrity validation');
  }
  return expanded;
}
function safe_string(value, maximum = 120) {
  return typeof value === 'string' && value.length > 0 ? value.replace(/[\r\n\t\0]/g, ' ').slice(0, maximum) : null;
}
function safe_timestamp(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER ? value : null;
}
function normalized_method(value) {
  if (typeof value !== 'string') return 'OTHER';
  const method = value.toUpperCase();
  return HTTP_METHODS.has(method) ? method : 'OTHER';
}
function sanitized_url(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 16_384) {
    return { origin: null, path: null, scheme: null, redacted: true };
  }
  let url;
  try { url = new URL(raw); } catch {
    return { origin: null, path: null, scheme: null, redacted: true };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { origin: null, path: null, scheme: null, redacted: true };
  }
  const segments = url.pathname.split('/').map(segment => {
    if (!segment) return '';
    if (segment.length > 96 || /(?:^[0-9a-f]{16,}$)|(?:^[A-Za-z0-9_-]{28,}$)|(?:^[^@/\s]+@[^@/\s]+$)/i.test(segment)) {
      return '[redacted]';
    }
    return segment.replace(/[\r\n\t\0]/g, '').slice(0, 128);
  });
  return {
    origin: url.origin.slice(0, 256),
    path: segments.join('/').slice(0, 2048) || '/',
    scheme: url.protocol.slice(0, -1),
    redacted: Boolean(url.username || url.password || url.search || url.hash),
  };
}
function increment(record, key) {
  record[key] = (record[key] ?? 0) + 1;
}
function normalize_action_label(value) {
  return typeof value === 'string' && IDENTIFIER.test(value) ? value : 'other';
}
function normalized_resource_type(value) {
  return typeof value === 'string' && /^[a-z][a-z0-9_-]{0,39}$/i.test(value) ? value.toLowerCase() : 'unknown';
}
function normalized_mime_type(value) {
  return typeof value === 'string' && /^[a-z0-9!#$&^_.+-]{1,64}\/[a-z0-9!#$&^_.+-]{1,64}$/i.test(value)
    ? value.toLowerCase()
    : null;
}

function parse_trace_events(trace_bytes, limits) {
  let source;
  try { source = new TextDecoder('utf-8', { fatal: true }).decode(trace_bytes); }
  catch { fail('ORIX_TRACE_INVALID_UTF8', 'Playwright trace JSONL must be valid UTF-8'); }
  // Count non-empty JSONL records without materializing every line. A trace may
  // contain millions of blank lines inside the byte ceiling; split/filter would
  // allocate an attacker-controlled array before max_events could take effect.
  let events_total = 0;
  const lines = [];
  let cursor = 0;
  while (cursor <= source.length) {
    const newline = source.indexOf('\n', cursor);
    const end = newline < 0 ? source.length : newline;
    if (end > cursor) {
      events_total += 1;
      if (lines.length < limits.max_events) {
        const line = source.slice(cursor, end);
        if (Buffer.byteLength(line, 'utf8') > limits.max_line_bytes) {
          fail('ORIX_TRACE_LINE_TOO_LARGE', 'Trace event line exceeds the configured byte ceiling', { line: events_total });
        }
        lines.push(line);
      }
    }
    if (newline < 0) break;
    cursor = newline + 1;
  }
  if (events_total === 0) fail('ORIX_TRACE_EMPTY', 'Playwright trace JSONL contains no events');
  const analyzed_count = lines.length;
  let context = null;
  const action_map = new Map();
  const actions = [];
  const requests = [];
  const pages = new Set();
  const methods = Object.create(null);
  const statuses = Object.create(null);
  const resource_types = Object.create(null);
  const console = { errors: 0, warnings: 0, other: 0 };
  const media = { frame_snapshots: 0, screenshots: 0, aria_snapshots: 0, screencast_frames: 0, videos: 0 };
  const events = Object.create(null);
  let unknown_events = 0;
  let error_events = 0;
  let actions_omitted = 0;
  let requests_omitted = 0;
  let page_ids_omitted = 0;
  let request_bytes = 0;
  let response_bytes = 0;
  let duration_start = null;
  let duration_end = null;
  const request_limit = limits.max_requests;
  const action_limit = limits.max_actions;

  for (let index = 0; index < analyzed_count; index += 1) {
    const line = lines[index];
    let event;
    try { event = JSON.parse(line); }
    catch { fail('ORIX_TRACE_INVALID_EVENT_JSON', 'Trace contains a malformed JSONL event', { line: index + 1 }); }
    if (!object(event) || typeof event.type !== 'string') {
      fail('ORIX_TRACE_INVALID_EVENT', 'Trace event must be a JSON object with a type string', { line: index + 1 });
    }
    if (!TRACE_EVENT_TYPES.has(event.type)) {
      unknown_events += 1;
      continue;
    }
    increment(events, event.type);

    if (index === 0) {
      if (event.type !== 'context-options' || !Number.isSafeInteger(event.version)) {
        fail('ORIX_TRACE_CONTEXT_MISSING', 'The first Playwright trace event must declare a versioned context-options record');
      }
      if (!SUPPORTED_TRACE_VERSIONS.has(event.version)) {
        fail('ORIX_TRACE_VERSION_UNSUPPORTED', 'This ORIX build supports Playwright trace format versions 8 and 9 only', {
          version: event.version,
          supported_versions: [8, 9],
        });
      }
      context = {
        version: event.version,
        browser: ['chromium', 'firefox', 'webkit'].includes(event.browserName) ? event.browserName : null,
        playwright_version: typeof event.playwrightVersion === 'string' && /^\d{1,3}\.\d{1,3}(?:\.\d{1,3})?(?:[-+][A-Za-z0-9.-]{1,32})?$/.test(event.playwrightVersion)
          ? event.playwrightVersion.slice(0, 48) : null,
        platform: typeof event.platform === 'string' && /^(?:linux|darwin|win32|windows|freebsd)$/i.test(event.platform)
          ? event.platform.toLowerCase() : null,
        origin: event.origin === 'library' || event.origin === 'testRunner' ? event.origin : null,
      };
      continue;
    }

    if (event.type === 'before' || event.type === 'action') {
      const call_id = typeof event.callId === 'string' && event.callId.length <= 256 ? event.callId : null;
      const start = safe_timestamp(event.startTime);
      const end = event.type === 'action' ? safe_timestamp(event.endTime) : null;
      if (!call_id || start === null || (event.type === 'action' && (end === null || end < start))) {
        fail('ORIX_TRACE_ACTION_INVALID', 'Trace action has an invalid identifier or timing fields', { line: index + 1 });
      }
      if (!action_map.has(call_id)) {
        if (action_map.size >= action_limit) {
          actions_omitted += 1;
          continue;
        }
        const action = {
          id: 'action-' + String(action_map.size + 1).padStart(5, '0'),
          class: normalize_action_label(event.class),
          method: normalize_action_label(event.method),
          start_time_ms: start,
          end_time_ms: end,
          duration_ms: end === null ? null : Number((end - start).toFixed(3)),
          outcome: event.type === 'action' ? (object(event.error) && event.error.message ? 'failed' : 'success') : 'incomplete',
        };
        action_map.set(call_id, action);
        actions.push(action);
        duration_start = duration_start === null ? start : Math.min(duration_start, start);
        duration_end = end === null ? duration_end : Math.max(duration_end ?? end, end);
      } else if (event.type === 'action') {
        const action = action_map.get(call_id);
        if (end < action.start_time_ms) {
          fail('ORIX_TRACE_ACTION_TIMING', 'Trace action ends before its recorded start time', { line: index + 1 });
        }
        action.end_time_ms = end;
        action.duration_ms = Number((end - action.start_time_ms).toFixed(3));
        action.outcome = object(event.error) && event.error.message ? 'failed' : 'success';
        duration_end = Math.max(duration_end ?? end, end);
      }
      continue;
    }
    if (event.type === 'after') {
      const call_id = typeof event.callId === 'string' && event.callId.length <= 256 ? event.callId : null;
      const end = safe_timestamp(event.endTime);
      if (!call_id || end === null) continue;
      const action = action_map.get(call_id);
      if (!action) continue;
      if (end < action.start_time_ms) fail('ORIX_TRACE_ACTION_TIMING', 'Trace action ends before it starts', { line: index + 1 });
      action.end_time_ms = end;
      action.duration_ms = Number((end - action.start_time_ms).toFixed(3));
      action.outcome = object(event.error) && typeof event.error.message === 'string' ? 'failed' : 'success';
      duration_end = Math.max(duration_end ?? end, end);
      continue;
    }
    if (event.type === 'resource-snapshot') {
      const snapshot = event.snapshot;
      if (!object(snapshot) || !object(snapshot.request) || !object(snapshot.response)) continue;
      if (requests.length >= request_limit) {
        requests_omitted += 1;
        continue;
      }
      const url = sanitized_url(snapshot.request.url);
      const status = Number.isSafeInteger(snapshot.response.status) && snapshot.response.status >= 0 && snapshot.response.status <= 599
        ? snapshot.response.status : null;
      const method = normalized_method(snapshot.request.method);
      increment(methods, method);
      if (status !== null) increment(statuses, String(status));
      const content = object(snapshot.response.content) ? snapshot.response.content : {};
      const request_size = Number.isSafeInteger(snapshot.request.bodySize) && snapshot.request.bodySize > 0 ? snapshot.request.bodySize : 0;
      const response_size = Number.isSafeInteger(content.size) && content.size > 0 ? content.size : 0;
      request_bytes += request_size;
      response_bytes += response_size;
      const type = normalized_resource_type(snapshot._resourceType);
      increment(resource_types, type);
      const time = object(snapshot.timings) ? snapshot.timings : {};
      const duration = typeof snapshot.time === 'number' && Number.isFinite(snapshot.time) && snapshot.time >= 0 && snapshot.time <= 86_400_000
        ? Number(snapshot.time.toFixed(3)) : null;
      const failure = typeof snapshot.response._failureText === 'string' && snapshot.response._failureText.length > 0;
      requests.push({
        id: 'request-' + String(requests.length + 1).padStart(5, '0'),
        method,
        origin: url.origin,
        path: url.path,
        scheme: url.scheme,
        redacted: url.redacted,
        status,
        mime_type: normalized_mime_type(content.mimeType),
        resource_type: type,
        duration_ms: duration,
        request_body_bytes: request_size,
        response_body_bytes: response_size,
        failed: failure || snapshot._wasAborted === true || (status !== null && status >= 400),
        timing_ms: {
          dns: typeof time.dns === 'number' && Number.isFinite(time.dns) && time.dns >= 0 ? Math.min(time.dns, 86_400_000) : null,
          connect: typeof time.connect === 'number' && Number.isFinite(time.connect) && time.connect >= 0 ? Math.min(time.connect, 86_400_000) : null,
          wait: typeof time.wait === 'number' && Number.isFinite(time.wait) && time.wait >= 0 ? Math.min(time.wait, 86_400_000) : null,
          receive: typeof time.receive === 'number' && Number.isFinite(time.receive) && time.receive >= 0 ? Math.min(time.receive, 86_400_000) : null,
        },
      });
      continue;
    }
    if (event.type === 'console') {
      if (event.messageType === 'error') console.errors += 1;
      else if (event.messageType === 'warning' || event.messageType === 'warn') console.warnings += 1;
      else console.other += 1;
      continue;
    }
    if (event.type === 'event') {
      if (event.method === 'page' && typeof event.params?.pageId === 'string') {
        if (pages.size < limits.max_pages) pages.add(event.params.pageId);
        else page_ids_omitted += 1;
      } else if (event.method === 'pageError') {
        error_events += 1;
      }
      const event_page = typeof event.pageId === 'string' ? event.pageId : null;
      if (event_page && !pages.has(event_page)) {
        if (pages.size < limits.max_pages) pages.add(event_page);
        else page_ids_omitted += 1;
      }
      continue;
    }
    if (event.type === 'frame-snapshot') {
      media.frame_snapshots += 1;
      if (typeof event.snapshot?.pageId === 'string' && !pages.has(event.snapshot.pageId)) {
        if (pages.size < limits.max_pages) pages.add(event.snapshot.pageId);
        else page_ids_omitted += 1;
      }
      continue;
    }
    if (event.type === 'screenshot') media.screenshots += 1;
    else if (event.type === 'aria-snapshot') media.aria_snapshots += 1;
    else if (event.type === 'screencast-frame') media.screencast_frames += 1;
    else if (event.type === 'video') media.videos += 1;
    else if (event.type === 'error') error_events += 1;
    else if (!['input', 'log', 'stdout', 'stderr'].includes(event.type)) unknown_events += 1;
  }

  if (!context) fail('ORIX_TRACE_CONTEXT_MISSING', 'Playwright trace context metadata was not found');
  const failed_actions = actions.filter(item => item.outcome === 'failed').length;
  const incomplete_actions = actions.filter(item => item.outcome === 'incomplete').length;
  const failed_requests = requests.filter(item => item.failed).length;
  const omitted_events = Math.max(0, events_total - analyzed_count);
  const coverage_complete = omitted_events === 0 && actions_omitted === 0 && requests_omitted === 0 && page_ids_omitted === 0 && unknown_events === 0;
  const findings = [];
  if (failed_actions > 0) {
    findings.push({ rule_id: 'ORIX-TRACE-ACTION-FAILURE-001', severity: 'medium', confidence: 'observed', count: failed_actions, summary: 'One or more recorded browser actions failed.' });
  }
  if (console.errors > 0) {
    findings.push({ rule_id: 'ORIX-TRACE-CONSOLE-ERROR-001', severity: 'low', confidence: 'observed', count: console.errors, summary: 'The recording contains browser console error messages; message text is intentionally omitted.' });
  }
  if (failed_requests > 0) {
    findings.push({ rule_id: 'ORIX-TRACE-REQUEST-FAILURE-001', severity: 'low', confidence: 'observed', count: failed_requests, summary: 'One or more recorded network requests failed or returned an HTTP error status.' });
  }
  const action_durations = actions.filter(item => item.duration_ms !== null).map(item => item.duration_ms).sort((a, b) => a - b);
  const percentile = fraction => action_durations.length
    ? action_durations[Math.min(action_durations.length - 1, Math.floor((action_durations.length - 1) * fraction))]
    : null;
  return {
    schema_version: 'orix.playwright-trace.v1',
    source: { format: 'Playwright trace archive', trace_member: 'trace.trace' },
    trace: context,
    summary: {
      events_total,
      events_analyzed: analyzed_count,
      event_types: events,
      unknown_event_types: unknown_events,
      action_count: actions.length,
      failed_actions,
      incomplete_actions,
      failed_requests,
      request_count: requests.length,
      unique_pages: pages.size,
      recording_duration_ms: duration_start !== null && duration_end !== null
        ? Number(Math.max(0, duration_end - duration_start).toFixed(3))
        : null,
      page_ids_omitted,
      console_errors: console.errors,
      console_warnings: console.warnings,
      error_events,
      request_body_bytes_observed: request_bytes,
      response_body_bytes_observed: response_bytes,
      action_duration_ms: {
        min: action_durations.length ? action_durations[0] : null,
        median: percentile(0.5),
        p95: percentile(0.95),
        max: action_durations.length ? action_durations.at(-1) : null,
      },
    },
    coverage: {
      complete: coverage_complete,
      truncated: !coverage_complete,
      omitted_events,
      omitted_actions: actions_omitted,
      omitted_requests: requests_omitted,
      max_events: limits.max_events,
      max_actions: limits.max_actions,
      max_requests: limits.max_requests,
      max_pages: limits.max_pages,
    },
    actions,
    requests,
    methods,
    statuses,
    resource_types,
    media,
    findings,
    privacy: {
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
      note: 'Trace action parameters, selectors, typed values, titles, console text, headers, cookies, query values, payloads, DOM/ARIA snapshots and media bytes are excluded. URL origins and sanitized paths plus action method names are retained; review before sharing.',
    },
    limitations: [
      'Only the stable Playwright trace event format versions 8 and 9 are accepted. Newer or older formats are rejected rather than guessed.',
      'This is an offline trace importer, not a live browser provider, Trace Viewer replacement, DOM parser or deterministic replay engine.',
      'Trace records are user-supplied evidence and are not independently authenticated; a SHA-256 digest identifies the file but does not prove who created it.',
      'No page scripts are executed, URLs are not fetched, and archived resources, screenshots, videos and DOM snapshots are not extracted.',
      'Trace format internals may change between Playwright releases; verify the Playwright version and coverage before relying on the report.',
    ],
    warnings: [
      ...(omitted_events ? ['Event analysis was truncated by max_events; only the analyzed prefix contributes to findings.'] : []),
      ...(actions_omitted ? ['Action inventory was truncated by max_actions.'] : []),
      ...(requests_omitted ? ['Network request inventory was truncated by max_requests.'] : []),
      ...(page_ids_omitted ? ['Page inventory was truncated by max_pages.'] : []),
      ...(unknown_events ? ['Unknown event types were skipped; report coverage is incomplete.'] : []),
    ],
  };
}

/** Analyze an in-memory Playwright trace ZIP. No archive member is written to disk. */
export function parse_playwright_trace(input, options = {}) {
  if (!Buffer.isBuffer(input)) throw new TypeError('parse_playwright_trace requires a Buffer');
  const limits = limits_for(options);
  if (input.length < 1 || input.length > limits.max_archive_bytes) {
    fail('ORIX_TRACE_ARCHIVE_TOO_LARGE', 'Playwright trace archive is empty or exceeds its configured byte ceiling', {
      size_bytes: input.length, max_archive_bytes: limits.max_archive_bytes,
    });
  }
  const zip = parse_zip(input, { max_entries: limits.max_entries });
  const trace_entries = zip.entries.filter(entry => entry.name === 'trace.trace');
  if (trace_entries.length !== 1) {
    fail('ORIX_TRACE_MEMBER_MISSING', 'Archive must contain exactly one root trace.trace JSONL member', { matching_members: trace_entries.length });
  }
  const entry = trace_entries[0];
  const trace_bytes = read_trace_member(input, entry, zip.archive.central_directory_offset, limits.max_trace_bytes, zip.entries);
  const report = parse_trace_events(trace_bytes, limits);
  report.source.archive_entries = zip.archive.total_entries;
  report.source.bytes = input.length;
  report.integrity = { algorithm: 'sha256', digest: createHash('sha256').update(input).digest('hex'), bytes: input.length };
  return report;
}

/** Open one regular trace archive with no-follow semantics and stable-file checks. */
export async function analyze_playwright_trace_file(file_path, options = {}) {
  if (typeof file_path !== 'string' || file_path.length === 0) throw new TypeError('file_path must be a non-empty string');
  const limits = limits_for(options);
  const requested_path = path.resolve(file_path);
  let handle;
  try {
    const [absolute, temporary_root] = await Promise.all([fs.realpath(requested_path), fs.realpath(tmpdir())]);
    const relative_to_temp = path.relative(temporary_root, absolute);
    if (relative_to_temp === '' || (!path.isAbsolute(relative_to_temp) && relative_to_temp !== '..' &&
        !relative_to_temp.startsWith('..' + path.sep))) {
      fail('ORIX_TRACE_TEMP_PATH_REJECTED', 'Trace archives inside the shared OS temporary directory are not accepted; copy the trace to a private workspace first', { path: absolute });
    }
    const no_follow = FS_CONSTANTS.O_NOFOLLOW ?? 0;
    const non_blocking = FS_CONSTANTS.O_NONBLOCK ?? 0;
    handle = await fs.open(absolute, FS_CONSTANTS.O_RDONLY | no_follow | non_blocking);
    const opened = await handle.stat();
    if (!opened.isFile()) fail('ORIX_TRACE_NOT_REGULAR_FILE', 'Trace analyzer accepts regular files only', { path: absolute });
    if (!Number.isSafeInteger(opened.size) || opened.size < 1 || opened.size > limits.max_archive_bytes) {
      fail('ORIX_TRACE_ARCHIVE_TOO_LARGE', 'Opened trace file size is empty, unsafe or above the configured byte ceiling', {
        size_bytes: opened.size, max_archive_bytes: limits.max_archive_bytes,
      });
    }
    const path_stat = await fs.lstat(requested_path);
    if (path_stat.isSymbolicLink()) fail('ORIX_TRACE_SYMLINK_REJECTED', 'Trace analyzer does not follow symbolic links', { path: requested_path });
    if (!path_stat.isFile() || path_stat.size !== opened.size ||
        String(path_stat.ino) !== String(opened.ino) || String(path_stat.dev) !== String(opened.dev)) {
      fail('ORIX_TRACE_FILE_REPLACED', 'Trace path no longer identifies the opened regular file');
    }
    const input = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < input.length) {
      const { bytesRead } = await handle.read(input, offset, input.length - offset, offset);
      if (bytesRead === 0) fail('ORIX_TRACE_FILE_CHANGED', 'Trace archive ended during the bounded read', { bytes_read: offset, expected_bytes: opened.size });
      offset += bytesRead;
    }
    const after = await handle.stat();
    const path_after_read = await fs.lstat(requested_path);
    const path_stable = path_after_read.isFile() && !path_after_read.isSymbolicLink() &&
      path_after_read.size === opened.size &&
      String(path_after_read.ino) === String(opened.ino) &&
      String(path_after_read.dev) === String(opened.dev);
    const stable = path_stable && opened.size === after.size &&
      opened.mtimeMs === after.mtimeMs && opened.ctimeMs === after.ctimeMs &&
      String(opened.ino) === String(after.ino) && String(opened.dev) === String(after.dev);
    const report = parse_playwright_trace(input, options);
    report.source.path = absolute;
    report.source.name = path.basename(absolute);
    report.source.modified_at = opened.mtime.toISOString();
    report.integrity.stable_during_read = stable;
    if (!stable) report.warnings.push('Trace file metadata changed while it was read; repeat analysis against a stable copy.');
    return report;
  } catch (error) {
    if (error instanceof OrixError || error instanceof TypeError) throw error;
    if (error?.code === 'ELOOP') fail('ORIX_TRACE_SYMLINK_REJECTED', 'Trace analyzer does not follow symbolic links');
    throw new OrixError('ORIX_TRACE_FILE_UNAVAILABLE', 'Unable to open or read Playwright trace archive safely', {
      cause: error, details: { system_code: error?.code ?? null }, recoverable: true,
    });
  } finally {
    await handle?.close();
  }
}
function markdown_escape(value) {
  return String(value ?? '').replace(/[\r\n\t]/g, ' ').replaceAll('|', '\\|').replaceAll('`', '\\`').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}
export function render_playwright_trace_markdown(report) {
  if (!report || report.schema_version !== 'orix.playwright-trace.v1') {
    throw new TypeError('render_playwright_trace_markdown requires an orix.playwright-trace.v1 report');
  }
  const source_name = markdown_escape(report.source.name ?? 'in-memory trace');
  return [
    '# ORIX Playwright Trace Investigation',
    '',
    '- Source: ' + source_name,
    '- Trace format: v' + report.trace.version,
    '- Browser: ' + markdown_escape(report.trace.browser ?? 'unknown'),
    '- Playwright: ' + markdown_escape(report.trace.playwright_version ?? 'unknown'),
    '- SHA-256: ' + report.integrity.digest,
    '- Events: ' + report.summary.events_analyzed + ' / ' + report.summary.events_total,
    '- Actions: ' + report.summary.action_count + ' (' + report.summary.failed_actions + ' failed, ' + report.summary.incomplete_actions + ' incomplete)',
    '- Requests: ' + report.summary.request_count + ' (' + report.summary.failed_requests + ' failed)',
    '- Console: ' + report.summary.console_errors + ' errors, ' + report.summary.console_warnings + ' warnings',
    '',
    '## Findings',
    '',
    ...(report.findings.length ? report.findings.map(item => '- **' + item.severity.toUpperCase() + '** ' + item.rule_id + ' — ' + item.summary + ' (' + item.count + ')') : ['- No configured trace review signals were observed.']),
    '',
    '## Action timeline',
    '',
    '| ID | Action | Start (ms) | Duration (ms) | Outcome |',
    '|---|---|---:|---:|---|',
    ...report.actions.slice(0, 200).map(item => '| ' + item.id + ' | ' + item.class + '.' + item.method + ' | ' + item.start_time_ms + ' | ' + (item.duration_ms ?? 'n/a') + ' | ' + item.outcome + ' |'),
    '',
    '## Privacy and limits',
    '',
    report.privacy.note,
    ...report.warnings.map(item => '- ' + item),
    ...report.limitations.map(item => '- ' + item),
    '',
  ].join('\n');
}
