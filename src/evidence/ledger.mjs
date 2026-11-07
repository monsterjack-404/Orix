// JavaScript, src/evidence/ledger.mjs, Node.js 20+, compatibility facade over the canonical evidence ledger.

import path from 'node:path';
import {
  create_evidence_ledger,
  append_evidence_event,
  verify_evidence_ledger,
  read_evidence_ledger,
} from '../core/evidence-ledger.mjs';

async function ensure_ledger(file_path) {
  try { await create_evidence_ledger(file_path); }
  catch (error) {
    if (error.code !== 'ORIX_LEDGER_ALREADY_EXISTS') throw error;
  }
}

export async function append_ledger(ledger_path, { type, payload }, options = {}) {
  if (typeof ledger_path !== 'string' || ledger_path.length === 0) throw new TypeError('ledger_path must be a non-empty string');
  await ensure_ledger(ledger_path);
  const record = await append_evidence_event(ledger_path, type, payload, options);
  return {
    schema_version: 'orix.ledger-receipt.v1',
    path: path.resolve(ledger_path),
    sequence: record.sequence,
    record_hash: record.hash,
    previous_hash: record.previous_hash,
  };
}

export async function verify_ledger(ledger_path, options = {}) {
  const result = await verify_evidence_ledger(ledger_path, options);
  return {
    schema_version: 'orix.ledger-verification.v1',
    path: result.path,
    valid: result.valid,
    records_verified: result.records,
    first_record_hash: result.first_hash,
    head_hash: result.head_hash,
    last_sequence: result.records,
    bytes: result.bytes,
    first_timestamp: result.first_timestamp,
    last_timestamp: result.last_timestamp,
  };
}

export async function list_ledger(ledger_path, options = {}) {
  const result = await read_evidence_ledger(ledger_path, options);
  return {
    schema_version: 'orix.ledger.v1',
    path: result.path,
    records: result.records.map(record => ({
      sequence: record.sequence,
      timestamp: record.timestamp,
      type: record.event,
      previous_hash: record.previous_hash,
      record_hash: record.hash,
      payload: record.payload,
    })),
    head_hash: result.head_hash,
  };
}
