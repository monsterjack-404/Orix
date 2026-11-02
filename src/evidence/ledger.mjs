// JavaScript, src/evidence/ledger.mjs, Node.js 20+, append-only SHA-256 chained evidence ledger.

import { createHash, randomUUID } from 'node:crypto';
import { constants as FS_CONSTANTS, promises as fs } from 'node:fs';
import path from 'node:path';
import { OrixError } from '../core/errors.mjs';

const LEDGER_VERSION = 1;
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_RECORD_BYTES = 4 * 1024 * 1024;
const ZERO_HASH = '0'.repeat(64);

function fail(code, message, details = null, cause = undefined) {
  throw new OrixError(code, message, { details, cause, recoverable: true });
}

function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}

function record_hash(record) {
  return createHash('sha256').update(canonical(record)).digest('hex');
}

function safe_json_clone(value) {
  let encoded;
  try { encoded = JSON.stringify(value); }
  catch (error) { fail('ORIX_LEDGER_PAYLOAD_INVALID', 'Ledger payload must be JSON-serializable', null, error); }
  if (encoded === undefined) fail('ORIX_LEDGER_PAYLOAD_INVALID', 'Ledger payload cannot be undefined');
  try { return JSON.parse(encoded); }
  catch (error) { fail('ORIX_LEDGER_PAYLOAD_INVALID', 'Ledger payload is not valid JSON data', null, error); }
}

async function ensure_regular_file(file_path, allow_missing = true) {
  try {
    const stats = await fs.lstat(file_path);
    if (stats.isSymbolicLink() || !stats.isFile()) fail('ORIX_LEDGER_UNSAFE_PATH', 'Ledger path must be a regular non-symbolic-link file', { path: file_path });
    return stats;
  } catch (error) {
    if (error.code === 'ENOENT' && allow_missing) return null;
    if (error instanceof OrixError) throw error;
    fail('ORIX_LEDGER_STAT_FAILED', 'Cannot inspect evidence ledger path', { path: file_path, system_code: error.code }, error);
  }
}

async function read_records(file_path, options = {}) {
  const max_bytes = options.max_bytes ?? DEFAULT_MAX_BYTES;
  const max_record_bytes = options.max_record_bytes ?? DEFAULT_MAX_RECORD_BYTES;
  const stats = await ensure_regular_file(file_path);
  if (!stats) return [];
  if (!Number.isSafeInteger(stats.size) || stats.size > max_bytes) {
    fail('ORIX_LEDGER_SIZE_LIMIT', 'Evidence ledger exceeds configured read limit', { size: stats.size, max_bytes });
  }
  const raw = await fs.readFile(file_path);
  if (raw.length === 0) return [];
  if (raw[raw.length - 1] !== 0x0a) fail('ORIX_LEDGER_PARTIAL_TAIL', 'Evidence ledger ends with an incomplete record; no automatic repair was attempted');
  const lines = raw.toString('utf8').split('\n');
  lines.pop();
  const records = [];
  let previous_hash = ZERO_HASH;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (Buffer.byteLength(line) > max_record_bytes) fail('ORIX_LEDGER_RECORD_LIMIT', 'Evidence ledger record exceeds configured size limit', { line: index + 1, max_record_bytes });
    let record;
    try { record = JSON.parse(line); }
    catch (error) { fail('ORIX_LEDGER_INVALID_JSON', 'Evidence ledger contains malformed JSON', { line: index + 1 }, error); }
    if (!record || record.ledger_version !== LEDGER_VERSION || !Number.isSafeInteger(record.sequence) || record.sequence !== index + 1 ||
        typeof record.previous_hash !== 'string' || typeof record.record_hash !== 'string' ||
        record.previous_hash !== previous_hash || typeof record.type !== 'string' || !record.payload) {
      fail('ORIX_LEDGER_CHAIN_INVALID', 'Evidence ledger record metadata or sequence is invalid', { line: index + 1 });
    }
    const { record_hash: supplied_hash, ...unsigned } = record;
    const expected_hash = record_hash(unsigned);
    if (supplied_hash !== expected_hash) fail('ORIX_LEDGER_HASH_MISMATCH', 'Evidence ledger record hash does not match its contents', { line: index + 1, sequence: record.sequence });
    previous_hash = supplied_hash;
    records.push(record);
  }
  return records;
}

async function acquire_lock(lock_path) {
  try {
    const handle = await fs.open(lock_path, FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_WRONLY, 0o600);
    await handle.writeFile(JSON.stringify({ pid: process.pid, token: randomUUID(), created_at: new Date().toISOString() }) + '\n');
    await handle.sync();
    return handle;
  } catch (error) {
    if (error.code === 'EEXIST') fail('ORIX_LEDGER_LOCKED', 'Evidence ledger is locked by another writer; inspect the lock before removing it', { lock_path });
    fail('ORIX_LEDGER_LOCK_FAILED', 'Cannot acquire evidence ledger writer lock', { lock_path, system_code: error.code }, error);
  }
}

export async function verify_ledger(ledger_path, options = {}) {
  if (typeof ledger_path !== 'string' || ledger_path.length === 0) throw new TypeError('ledger_path must be a non-empty string');
  const absolute_path = path.resolve(ledger_path);
  const records = await read_records(absolute_path, options);
  return {
    schema_version: 'orix.ledger-verification.v1',
    path: absolute_path,
    valid: true,
    records_verified: records.length,
    first_record_hash: records[0]?.record_hash ?? null,
    head_hash: records.at(-1)?.record_hash ?? ZERO_HASH,
    last_sequence: records.at(-1)?.sequence ?? 0,
  };
}

export async function list_ledger(ledger_path, options = {}) {
  const absolute_path = path.resolve(ledger_path);
  const records = await read_records(absolute_path, options);
  return {
    schema_version: 'orix.ledger.v1',
    path: absolute_path,
    records: records.map(({ ledger_version, record_hash: hash, ...record }) => ({ ...record, hash })),
  };
}

export async function append_ledger(ledger_path, { type, payload }, options = {}) {
  if (typeof ledger_path !== 'string' || ledger_path.length === 0) throw new TypeError('ledger_path must be a non-empty string');
  if (typeof type !== 'string' || !/^[a-z][a-z0-9.-]{0,63}$/.test(type)) throw new TypeError('type must be a lowercase ledger event identifier');
  const absolute_path = path.resolve(ledger_path);
  const parent = path.dirname(absolute_path);
  await fs.mkdir(parent, { recursive: true });
  const lock_path = absolute_path + '.lock';
  const lock = await acquire_lock(lock_path);
  try {
    const records = await read_records(absolute_path, options);
    const previous_hash = records.at(-1)?.record_hash ?? ZERO_HASH;
    const unsigned = {
      ledger_version: LEDGER_VERSION,
      sequence: records.length + 1,
      timestamp: new Date().toISOString(),
      type,
      previous_hash,
      payload: safe_json_clone(payload),
    };
    const record = { ...unsigned, record_hash: record_hash(unsigned) };
    const line = JSON.stringify(record) + '\n';
    const max_record_bytes = options.max_record_bytes ?? DEFAULT_MAX_RECORD_BYTES;
    if (Buffer.byteLength(line) > max_record_bytes) fail('ORIX_LEDGER_RECORD_LIMIT', 'Evidence payload exceeds maximum record size', { bytes: Buffer.byteLength(line), max_record_bytes });
    const existing = await ensure_regular_file(absolute_path);
    if (!existing) {
      const created = await fs.open(absolute_path, FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_WRONLY, 0o600);
      try { await created.writeFile(line); await created.sync(); }
      finally { await created.close(); }
    } else {
      const handle = await fs.open(absolute_path, FS_CONSTANTS.O_APPEND | FS_CONSTANTS.O_WRONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0));
      try { await handle.writeFile(line); await handle.sync(); }
      finally { await handle.close(); }
    }
    return {
      schema_version: 'orix.ledger-receipt.v1',
      path: absolute_path,
      sequence: record.sequence,
      record_hash: record.record_hash,
      previous_hash,
    };
  } finally {
    await lock.close();
    await fs.unlink(lock_path).catch(() => {});
  }
}
