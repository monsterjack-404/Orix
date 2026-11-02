// JavaScript, src/core/evidence-ledger.mjs, Node.js 20+, append-only SHA-256 provenance ledger.

import { promises as fs, constants as fs_constants } from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { OrixError } from './errors.mjs';

const LEDGER_FORMAT = 'orix.evidence-ledger.v1';
const GENESIS_HASH = '0'.repeat(64);
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_RECORD_BYTES = 1024 * 1024;
const LOCK_RETRY_MS = 40;
const LOCK_WAIT_MS = 5000;

function fail(code, message, details = null, cause = undefined) {
  throw new OrixError(code, message, { details, cause, recoverable: true });
}

function canonical_value(value, seen = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('ORIX_LEDGER_NONFINITE_NUMBER', 'Ledger payload contains a non-finite number');
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value !== 'object') fail('ORIX_LEDGER_UNSERIALIZABLE', 'Ledger payload contains a value that JSON cannot represent', { type: typeof value });
  if (seen.has(value)) fail('ORIX_LEDGER_CIRCULAR_VALUE', 'Ledger payload contains a circular reference');
  seen.add(value);
  let result;
  if (Array.isArray(value)) {
    result = value.map(item => canonical_value(item, seen));
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail('ORIX_LEDGER_UNSAFE_OBJECT', 'Ledger payload must contain plain objects and arrays');
    result = {};
    for (const key of Object.keys(value).sort()) {
      const item = value[key];
      if (item === undefined) fail('ORIX_LEDGER_UNDEFINED_VALUE', 'Ledger payload contains an undefined property', { key });
      result[key] = canonical_value(item, seen);
    }
  }
  seen.delete(value);
  return result;
}

function stable_json(value) {
  return JSON.stringify(canonical_value(value));
}

function record_digest(record) {
  const body = {
    format: record.format,
    sequence: record.sequence,
    record_id: record.record_id,
    timestamp: record.timestamp,
    event: record.event,
    payload: record.payload,
    previous_hash: record.previous_hash,
  };
  return createHash('sha256').update(LEDGER_FORMAT + '\n' + stable_json(body)).digest('hex');
}

function validate_options(options = {}) {
  const max_bytes = options.max_bytes ?? DEFAULT_MAX_BYTES;
  const max_record_bytes = options.max_record_bytes ?? DEFAULT_MAX_RECORD_BYTES;
  if (!Number.isSafeInteger(max_bytes) || max_bytes < 1) fail('ORIX_LEDGER_BAD_LIMIT', 'max_bytes must be a positive safe integer', { max_bytes });
  if (!Number.isSafeInteger(max_record_bytes) || max_record_bytes < 256 || max_record_bytes > max_bytes) fail('ORIX_LEDGER_BAD_LIMIT', 'max_record_bytes must be between 256 and max_bytes', { max_record_bytes, max_bytes });
  return { max_bytes, max_record_bytes };
}

async function read_ledger_file(file_path, options = {}) {
  const limits = validate_options(options);
  const absolute = path.resolve(file_path);
  let before;
  try { before = await fs.lstat(absolute); }
  catch (error) { fail('ORIX_LEDGER_READ_FAILED', 'Cannot stat evidence ledger', { path: absolute, reason: error.code }, error); }
  if (before.isSymbolicLink() || !before.isFile()) fail('ORIX_LEDGER_NOT_REGULAR_FILE', 'Evidence ledger must be a regular non-symlink file', { path: absolute });
  if (before.size > limits.max_bytes) fail('ORIX_LEDGER_SIZE_LIMIT', 'Evidence ledger exceeds configured read limit', { size: before.size, maximum: limits.max_bytes });
  let handle;
  try {
    const nofollow = fs_constants.O_NOFOLLOW ?? 0;
    handle = await fs.open(absolute, fs_constants.O_RDONLY | nofollow);
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) fail('ORIX_LEDGER_FILE_CHANGED', 'Evidence ledger identity changed between lookup and open', { path: absolute });
    const chunks = [];
    let total = 0;
    const chunk = Buffer.allocUnsafe(64 * 1024);
    while (true) {
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > limits.max_bytes) fail('ORIX_LEDGER_SIZE_LIMIT', 'Evidence ledger grew beyond configured read limit', { maximum: limits.max_bytes });
      chunks.push(Buffer.from(chunk.subarray(0, bytesRead)));
    }
    const after = await handle.stat();
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs) fail('ORIX_LEDGER_FILE_CHANGED', 'Evidence ledger changed while it was being read', { path: absolute });
    return { absolute, buffer: Buffer.concat(chunks), limits };
  } catch (error) {
    if (error instanceof OrixError) throw error;
    fail('ORIX_LEDGER_READ_FAILED', 'Cannot read evidence ledger', { path: absolute, reason: error.code }, error);
  } finally {
    await handle?.close().catch(() => {});
  }
}

function parse_records(buffer, max_record_bytes) {
  if (buffer.length === 0) return [];
  if (buffer[buffer.length - 1] !== 0x0a) fail('ORIX_LEDGER_PARTIAL_TAIL', 'Evidence ledger ends with an incomplete record');
  const lines = buffer.toString('utf8').split('\n');
  lines.pop();
  const records = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const line_bytes = Buffer.byteLength(line, 'utf8');
    if (line_bytes > max_record_bytes) fail('ORIX_LEDGER_RECORD_LIMIT', 'Evidence ledger record exceeds configured limit', { line: index + 1, line_bytes, maximum: max_record_bytes });
    let record;
    try { record = JSON.parse(line); }
    catch (error) { fail('ORIX_LEDGER_INVALID_JSON', 'Evidence ledger contains invalid JSON', { line: index + 1 }, error); }
    records.push(record);
  }
  return records;
}

function validate_chain(records) {
  let previous_hash = GENESIS_HASH;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    const expected_sequence = index + 1;
    if (!record || typeof record !== 'object' || Array.isArray(record)) fail('ORIX_LEDGER_RECORD_SHAPE', 'Ledger record must be an object', { line: expected_sequence });
    if (record.format !== LEDGER_FORMAT) fail('ORIX_LEDGER_FORMAT_MISMATCH', 'Ledger record has an unsupported format identifier', { line: expected_sequence, format: record.format });
    if (record.sequence !== expected_sequence) fail('ORIX_LEDGER_SEQUENCE_MISMATCH', 'Ledger sequence is not contiguous', { line: expected_sequence, actual: record.sequence });
    if (typeof record.record_id !== 'string' || typeof record.timestamp !== 'string' || Number.isNaN(Date.parse(record.timestamp))) fail('ORIX_LEDGER_RECORD_METADATA', 'Ledger record metadata is invalid', { line: expected_sequence });
    if (typeof record.event !== 'string' || !/^[a-z][a-z0-9_.-]{1,79}$/.test(record.event)) fail('ORIX_LEDGER_EVENT_INVALID', 'Ledger event name is invalid', { line: expected_sequence });
    if (record.previous_hash !== previous_hash) fail('ORIX_LEDGER_CHAIN_BROKEN', 'Ledger previous-hash link does not match', { line: expected_sequence, expected: previous_hash, actual: record.previous_hash });
    const expected_hash = record_digest(record);
    if (record.hash !== expected_hash) fail('ORIX_LEDGER_HASH_MISMATCH', 'Ledger record hash does not match its contents', { line: expected_sequence, expected: expected_hash, actual: record.hash });
    previous_hash = record.hash;
  }
  return previous_hash;
}

async function acquire_lock(ledger_path, options = {}) {
  const lock_path = ledger_path + '.lock';
  const wait_ms = options.lock_wait_ms ?? LOCK_WAIT_MS;
  if (!Number.isSafeInteger(wait_ms) || wait_ms < 0 || wait_ms > 60000) fail('ORIX_LEDGER_BAD_LOCK_LIMIT', 'lock_wait_ms must be between 0 and 60000');
  const started = Date.now();
  while (true) {
    try {
      await fs.mkdir(lock_path, { mode: 0o700 });
      await fs.writeFile(path.join(lock_path, 'owner.json'), JSON.stringify({ pid: process.pid, token: randomUUID(), created_at: new Date().toISOString() }), { flag: 'wx', mode: 0o600 });
      return async () => { await fs.rm(lock_path, { recursive: true, force: true }); };
    } catch (error) {
      if (error.code !== 'EEXIST') fail('ORIX_LEDGER_LOCK_FAILED', 'Cannot acquire evidence-ledger append lock', { path: lock_path, reason: error.code }, error);
      if (Date.now() - started >= wait_ms) fail('ORIX_LEDGER_LOCK_TIMEOUT', 'Timed out waiting for evidence-ledger append lock', { path: lock_path, wait_ms });
      await new Promise(resolve => setTimeout(resolve, LOCK_RETRY_MS));
    }
  }
}

export async function create_evidence_ledger(file_path) {
  const absolute = path.resolve(file_path);
  await fs.mkdir(path.dirname(absolute), { recursive: true });
  const nofollow = fs_constants.O_NOFOLLOW ?? 0;
  let handle;
  try {
    handle = await fs.open(absolute, fs_constants.O_WRONLY | fs_constants.O_CREAT | fs_constants.O_EXCL | nofollow, 0o600);
    await handle.sync();
    return { path: absolute, created: true, format: LEDGER_FORMAT, genesis_hash: GENESIS_HASH };
  } catch (error) {
    if (error.code === 'EEXIST') fail('ORIX_LEDGER_ALREADY_EXISTS', 'Refusing to overwrite an existing evidence ledger', { path: absolute });
    fail('ORIX_LEDGER_CREATE_FAILED', 'Cannot create evidence ledger', { path: absolute, reason: error.code }, error);
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function append_evidence_event(file_path, event, payload, options = {}) {
  const absolute = path.resolve(file_path);
  if (typeof event !== 'string' || !/^[a-z][a-z0-9_.-]{1,79}$/.test(event)) fail('ORIX_LEDGER_EVENT_INVALID', 'Event must be 2-80 lowercase letters, digits, dots, underscores or hyphens');
  const safe_payload = canonical_value(payload);
  const release = await acquire_lock(absolute, options);
  try {
    const current = await read_ledger_file(absolute, options);
    const records = parse_records(current.buffer, current.limits.max_record_bytes);
    const previous_hash = validate_chain(records);
    const record = {
      format: LEDGER_FORMAT,
      sequence: records.length + 1,
      record_id: randomUUID(),
      timestamp: new Date().toISOString(),
      event,
      payload: safe_payload,
      previous_hash,
    };
    record.hash = record_digest(record);
    const line = stable_json(record) + '\n';
    const bytes = Buffer.byteLength(line, 'utf8');
    if (bytes > current.limits.max_record_bytes) fail('ORIX_LEDGER_RECORD_LIMIT', 'New evidence record exceeds configured limit', { bytes, maximum: current.limits.max_record_bytes });
    if (current.buffer.length + bytes > current.limits.max_bytes) fail('ORIX_LEDGER_SIZE_LIMIT', 'Appending this record would exceed configured ledger size', { current: current.buffer.length, incoming: bytes, maximum: current.limits.max_bytes });
    const nofollow = fs_constants.O_NOFOLLOW ?? 0;
    const handle = await fs.open(absolute, fs_constants.O_WRONLY | fs_constants.O_APPEND | nofollow);
    try {
      const opened = await handle.stat();
      if (opened.size !== current.buffer.length) fail('ORIX_LEDGER_CONCURRENT_MODIFICATION', 'Ledger size changed after chain verification', { verified_size: current.buffer.length, current_size: opened.size });
      await handle.writeFile(line, 'utf8');
      await handle.sync();
    } finally { await handle.close(); }
    return record;
  } finally { await release(); }
}

export async function verify_evidence_ledger(file_path, options = {}) {
  const loaded = await read_ledger_file(file_path, options);
  const records = parse_records(loaded.buffer, loaded.limits.max_record_bytes);
  const head_hash = validate_chain(records);
  return {
    valid: true,
    format: LEDGER_FORMAT,
    path: loaded.absolute,
    records: records.length,
    first_hash: records[0]?.hash ?? null,
    bytes: loaded.buffer.length,
    head_hash,
    first_timestamp: records[0]?.timestamp ?? null,
    last_timestamp: records.at(-1)?.timestamp ?? null,
  };
}

export async function read_evidence_ledger(file_path, options = {}) {
  const loaded = await read_ledger_file(file_path, options);
  const records = parse_records(loaded.buffer, loaded.limits.max_record_bytes);
  const head_hash = validate_chain(records);
  return { format: LEDGER_FORMAT, path: loaded.absolute, records, head_hash };
}
