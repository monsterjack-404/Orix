// JavaScript, src/cases/store.mjs, Node.js 20+, local event-sourced investigation cases.
import { constants as fs_constants, promises as fs } from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { inspect_file } from '../core/inspect.mjs';
import { create_evidence_ledger, append_evidence_event, read_evidence_ledger, verify_evidence_ledger } from '../core/evidence-ledger.mjs';
import { OrixError } from '../core/errors.mjs';

const CASES_FORMAT = 'orix.case.v1';
const BUNDLE_FORMAT = 'orix.case-bundle.v1';
const MAX_CASES = 1000;
const MAX_REPORT_BYTES = 2 * 1024 * 1024;
const MAX_BUNDLE_FILES = 512;
const MAX_BUNDLE_BYTES = 64 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const CASE_STATES = new Set(['open', 'in_review', 'closed']);
const FINDING_STATES = new Set(['open', 'triaged', 'confirmed', 'false_positive', 'accepted_risk', 'resolved']);
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info', 'unknown']);
const CONFIDENCES = new Set(['observed', 'derived', 'heuristic', 'unknown']);

function fail(code, message, details = null, cause = undefined) {
  throw new OrixError(code, message, { details, cause, recoverable: true });
}
function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}
function plain_object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    fail('ORIX_CASE_INVALID_INPUT', label + ' must be a plain object');
  }
}
function bounded_text(value, label, maximum, required = false) {
  if (typeof value !== 'string' || (required && value.trim().length === 0) || value.length > maximum || value.includes('\0')) {
    fail('ORIX_CASE_INVALID_INPUT', label + ' must be ' + (required ? 'a non-empty' : 'a') + ' string of at most ' + maximum + ' characters');
  }
  return value;
}
function canonical(value, seen = new Set(), budget = { nodes: 0 }, depth = 0) {
  budget.nodes += 1;
  if (budget.nodes > 100_000 || depth > 64) fail('ORIX_CASE_DATA_LIMIT', 'Case data exceeds the node or nesting limit');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('ORIX_CASE_INVALID_INPUT', 'Case data contains a non-finite number');
    return Object.is(value, -0) ? 0 : value;
  }
  if (!value || typeof value !== 'object') fail('ORIX_CASE_INVALID_INPUT', 'Case data contains a non-JSON value');
  if (seen.has(value)) fail('ORIX_CASE_CIRCULAR_VALUE', 'Case data contains a circular reference');
  seen.add(value);
  let result;
  if (Array.isArray(value)) {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor) fail('ORIX_CASE_INVALID_INPUT', 'Case arrays must not contain sparse elements', { index });
      if (!Object.hasOwn(descriptor, 'value') || descriptor.value === undefined) fail('ORIX_CASE_INVALID_INPUT', 'Case arrays cannot contain accessors or undefined values', { index });
      result.push(canonical(descriptor.value, seen, budget, depth + 1));
    }
    for (const key of Object.keys(descriptors)) if (key !== 'length' && (!/^(?:0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length)) fail('ORIX_CASE_INVALID_INPUT', 'Case arrays cannot contain custom properties', { key });
  } else {
    plain_object(value, 'Case data');
    result = Object.create(null);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    for (const key of Object.keys(value).sort()) {
      const descriptor = descriptors[key];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.value === undefined) fail('ORIX_CASE_INVALID_INPUT', 'Case data cannot contain accessors or undefined values', { key });
      result[key] = canonical(descriptor.value, seen, budget, depth + 1);
    }
  }
  seen.delete(value);
  return result;
}
function stable_json(value) { return JSON.stringify(canonical(value)); }
function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function safe_relative(value) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || path.isAbsolute(value) || value.includes('\\')) return false;
  const parts = value.split('/');
  return parts.every(part => part && part !== '.' && part !== '..');
}
async function ensure_directory(directory) {
  try { await fs.mkdir(directory, { mode: 0o700 }); }
  catch (error) { if (error.code !== 'EEXIST') fail('ORIX_CASE_STORAGE_FAILED', 'Cannot create case directory', { path: directory, system_code: error.code }, error); }
  let stats;
  try { stats = await fs.lstat(directory); }
  catch (error) { fail('ORIX_CASE_STORAGE_FAILED', 'Cannot inspect case directory', { path: directory, system_code: error.code }, error); }
  if (stats.isSymbolicLink() || !stats.isDirectory()) fail('ORIX_CASE_UNSAFE_DIRECTORY', 'Case storage path must be a regular non-symlink directory', { path: directory });
  const real = await fs.realpath(directory);
  if (real !== directory) fail('ORIX_CASE_UNSAFE_DIRECTORY', 'Case storage path resolves through an unexpected filesystem alias', { path: directory, real_path: real });
}
async function workspace_paths(workspace_path, create = false) {
  if (typeof workspace_path !== 'string' || workspace_path.length === 0 || workspace_path.includes('\0')) fail('ORIX_CASE_BAD_WORKSPACE', 'Workspace path must be a non-empty path');
  const absolute = path.resolve(workspace_path);
  let stats;
  try { stats = await fs.lstat(absolute); }
  catch (error) { fail('ORIX_CASE_BAD_WORKSPACE', 'Workspace directory is unavailable', { path: absolute, system_code: error.code }, error); }
  if (stats.isSymbolicLink() || !stats.isDirectory()) fail('ORIX_CASE_BAD_WORKSPACE', 'Workspace must be a regular non-symlink directory', { path: absolute });
  const root = await fs.realpath(absolute);
  const metadata = path.join(root, '.orix');
  const cases = path.join(metadata, 'cases');
  if (create) {
    await ensure_directory(metadata);
    await ensure_directory(cases);
  } else {
    for (const directory of [metadata, cases]) {
      let current;
      try { current = await fs.lstat(directory); }
      catch (error) { if (error.code === 'ENOENT') return { root, metadata, cases: null }; fail('ORIX_CASE_STORAGE_FAILED', 'Cannot inspect case workspace', { path: directory, system_code: error.code }, error); }
      if (current.isSymbolicLink() || !current.isDirectory() || await fs.realpath(directory) !== directory) fail('ORIX_CASE_UNSAFE_DIRECTORY', 'Case storage path must be a regular non-symlink directory', { path: directory });
    }
  }
  return { root, metadata, cases };
}
async function case_directory(workspace_path, case_id) {
  if (typeof case_id !== 'string' || !UUID.test(case_id)) fail('ORIX_CASE_INVALID_ID', 'Case ID must be a UUID');
  const paths = await workspace_paths(workspace_path, false);
  if (!paths.cases) fail('ORIX_CASE_NOT_FOUND', 'No ORIX case workspace exists here', { workspace: paths.root });
  const directory = path.join(paths.cases, case_id);
  let stats;
  try { stats = await fs.lstat(directory); }
  catch (error) { fail('ORIX_CASE_NOT_FOUND', 'Investigation case was not found', { case_id, system_code: error.code }, error); }
  if (stats.isSymbolicLink() || !stats.isDirectory()) fail('ORIX_CASE_UNSAFE_DIRECTORY', 'Case directory must be a regular non-symlink directory', { case_id });
  const real = await fs.realpath(directory);
  if (real !== directory || !within(paths.cases, real)) fail('ORIX_CASE_UNSAFE_DIRECTORY', 'Case directory escaped the configured case store', { case_id });
  return { ...paths, directory, events_path: path.join(directory, 'events.jsonl'), reports_path: path.join(directory, 'reports') };
}
async function write_new_file(file_path, bytes) {
  const handle = await fs.open(file_path, fs_constants.O_WRONLY | fs_constants.O_CREAT | fs_constants.O_EXCL | (fs_constants.O_NOFOLLOW ?? 0), 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); }
  finally { await handle.close(); }
}
async function read_bounded_file(file_path, maximum, options = {}) {
  let before;
  try { before = await fs.lstat(file_path); }
  catch (error) { fail('ORIX_CASE_FILE_UNAVAILABLE', 'Case file is unavailable', { path: file_path, system_code: error.code }, error); }
  if (before.isSymbolicLink() || !before.isFile() || before.size > maximum) fail('ORIX_CASE_FILE_LIMIT', 'Case file is unsafe or exceeds its read limit', { path: file_path, size: before.size, maximum });
  if (options.reject_hardlinks === true && before.nlink > 1) fail('ORIX_CASE_HARDLINK_REJECTED', 'Case file must not have hard-link aliases', { path: file_path, link_count: before.nlink });
  let handle;
  try {
    handle = await fs.open(file_path, fs_constants.O_RDONLY | (fs_constants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size > maximum) fail('ORIX_CASE_FILE_CHANGED', 'Case file identity changed before reading', { path: file_path });
    if (options.reject_hardlinks === true && opened.nlink > 1) fail('ORIX_CASE_HARDLINK_REJECTED', 'Case file acquired a hard-link alias before descriptor acquisition completed', { path: file_path, link_count: opened.nlink });
    const chunks = [];
    let total = 0;
    const chunk = Buffer.allocUnsafe(64 * 1024);
    while (true) {
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (!bytesRead) break;
      total += bytesRead;
      if (total > maximum) fail('ORIX_CASE_FILE_LIMIT', 'Case file grew beyond its read limit', { path: file_path, maximum });
      chunks.push(Buffer.from(chunk.subarray(0, bytesRead)));
    }
    const after = await handle.stat();
    if (options.reject_hardlinks === true && after.nlink > 1) fail('ORIX_CASE_HARDLINK_REJECTED', 'Case file acquired a hard-link alias while being read', { path: file_path, link_count: after.nlink });
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) fail('ORIX_CASE_FILE_CHANGED', 'Case file changed while being read', { path: file_path });
    return Buffer.concat(chunks);
  } catch (error) {
    if (error instanceof OrixError) throw error;
    fail('ORIX_CASE_READ_FAILED', 'Cannot read case file', { path: file_path, system_code: error.code }, error);
  } finally { await handle?.close().catch(() => {}); }
}
async function append_event(paths, event, payload, options = {}) {
  return append_evidence_event(paths.events_path, event, payload, options);
}
function apply_event(state, record) {
  const payload = record.payload;
  switch (record.event) {
    case 'case.created':
      if (state.case) fail('ORIX_CASE_EVENT_INVALID', 'Case creation event must be first and unique');
      state.case = { id: payload.case_id, title: payload.title, description: payload.description, created_at: payload.created_at, updated_at: record.timestamp, status: 'open' };
      break;
    case 'case.status_changed':
      if (!state.case || !CASE_STATES.has(payload.status)) fail('ORIX_CASE_EVENT_INVALID', 'Case status event is invalid');
      state.case.status = payload.status; state.case.updated_at = record.timestamp;
      break;
    case 'artifact.added':
      if (!state.case || state.artifacts.some(item => item.sha256 === payload.sha256)) fail('ORIX_CASE_EVENT_INVALID', 'Artifact event is invalid or duplicates an existing digest');
      state.artifacts.push(payload); state.case.updated_at = record.timestamp;
      break;
    case 'analysis.recorded':
      if (!state.case || state.analyses.some(item => item.run_id === payload.run_id)) fail('ORIX_CASE_EVENT_INVALID', 'Analysis event is invalid or duplicates a run ID');
      state.analyses.push(payload); state.case.updated_at = record.timestamp;
      break;
    case 'finding.recorded':
      if (!state.case || state.findings.some(item => item.finding_id === payload.finding_id)) fail('ORIX_CASE_EVENT_INVALID', 'Finding event is invalid or duplicates a finding ID');
      state.findings.push({ ...payload, status: 'open', status_history: [{ status: 'open', timestamp: record.timestamp, reason: 'Initial observation' }] });
      state.case.updated_at = record.timestamp;
      break;
    case 'finding.status_changed': {
      const finding = state.findings.find(item => item.finding_id === payload.finding_id);
      if (!finding || !FINDING_STATES.has(payload.status)) fail('ORIX_CASE_EVENT_INVALID', 'Finding status event references an unknown finding or status');
      finding.status = payload.status;
      finding.status_history.push({ status: payload.status, timestamp: record.timestamp, reason: payload.reason });
      state.case.updated_at = record.timestamp;
      break;
    }
    case 'note.added':
      if (!state.case || state.notes.some(item => item.note_id === payload.note_id)) fail('ORIX_CASE_EVENT_INVALID', 'Note event is invalid or duplicates a note ID');
      state.notes.push(payload); state.case.updated_at = record.timestamp;
      break;
    case 'relationship.added':
      if (!state.case || state.relationships.some(item => item.relationship_id === payload.relationship_id)) fail('ORIX_CASE_EVENT_INVALID', 'Relationship event is invalid or duplicates a relationship ID');
      state.relationships.push(payload); state.case.updated_at = record.timestamp;
      break;
    default:
      fail('ORIX_CASE_UNKNOWN_EVENT', 'Case ledger contains an unsupported event', { event: record.event, sequence: record.sequence });
  }
}
async function load_state(paths, options = {}) {
  const loaded = await read_evidence_ledger(paths.events_path, options);
  if (!loaded.records.length) fail('ORIX_CASE_EMPTY_LEDGER', 'Case event ledger is empty');
  const state = { schema_version: CASES_FORMAT, case: null, artifacts: [], analyses: [], findings: [], notes: [], relationships: [], timeline: [], integrity: { valid: true, records: loaded.records.length, head_hash: loaded.head_hash } };
  for (const record of loaded.records) {
    apply_event(state, record);
    state.timeline.push({ sequence: record.sequence, event: record.event, timestamp: record.timestamp, record_hash: record.hash });
  }
  if (state.case.id !== path.basename(paths.directory).toLowerCase()) fail('ORIX_CASE_ID_MISMATCH', 'Case directory ID does not match its creation event');
  return state;
}
function node_exists(state, type, id) {
  if (type === 'case') return state.case.id === id;
  if (type === 'artifact') return state.artifacts.some(item => item.artifact_id === id);
  if (type === 'analysis') return state.analyses.some(item => item.run_id === id);
  if (type === 'finding') return state.findings.some(item => item.finding_id === id);
  if (type === 'note') return state.notes.some(item => item.note_id === id);
  if (type === 'evidence') return state.findings.some(item => item.evidence.some(entry => entry.evidence_id === id));
  return false;
}
export async function create_case(workspace_path, { title, description = '' } = {}, options = {}) {
  bounded_text(title, 'title', 200, true); bounded_text(description, 'description', 4000);
  const paths = await workspace_paths(workspace_path, true);
  const case_id = randomUUID();
  const directory = path.join(paths.cases, case_id);
  await ensure_directory(directory);
  const events_path = path.join(directory, 'events.jsonl');
  try {
    await create_evidence_ledger(events_path);
    const created_at = new Date().toISOString();
    await append_evidence_event(events_path, 'case.created', { case_id, title: title.trim(), description, created_at }, options);
    return await load_state({ ...paths, directory, events_path, reports_path: path.join(directory, 'reports') }, options);
  } catch (error) { await fs.rm(directory, { recursive: true, force: true }).catch(() => {}); throw error; }
}
export async function list_cases(workspace_path, { max_cases = MAX_CASES, reject_hardlinks = false } = {}) {
  if (!Number.isSafeInteger(max_cases) || max_cases < 1 || max_cases > MAX_CASES) fail('ORIX_CASE_BAD_LIMIT', 'max_cases must be between 1 and ' + MAX_CASES);
  const paths = await workspace_paths(workspace_path, false);
  if (!paths.cases) return { schema_version: 'orix.case-list.v1', workspace: paths.root, cases: [], coverage: { complete: true, skipped_entries: 0, maximum_cases: max_cases } };
  const entries = await fs.readdir(paths.cases, { withFileTypes: true });
  const cases = [];
  let skipped = 0;
  for (const entry of entries) {
    if (!entry.isDirectory() || !UUID.test(entry.name)) { skipped += 1; continue; }
    if (cases.length >= max_cases) { skipped += 1; continue; }
    try {
      const state = await load_state(await case_directory(workspace_path, entry.name), { reject_hardlinks });
      cases.push({ ...state.case, artifact_count: state.artifacts.length, analysis_count: state.analyses.length, finding_count: state.findings.length, note_count: state.notes.length, integrity: state.integrity });
    } catch { skipped += 1; }
  }
  cases.sort((a, b) => b.updated_at.localeCompare(a.updated_at) || a.id.localeCompare(b.id));
  return { schema_version: 'orix.case-list.v1', workspace: paths.root, cases, coverage: { complete: skipped === 0, skipped_entries: skipped, maximum_cases: max_cases } };
}
export async function get_case(workspace_path, case_id, options = {}) {
  const paths = await case_directory(workspace_path, case_id);
  return load_state(paths, options);
}
async function verify_report_files(paths, state, options = {}) {
  const verified = [];
  for (const analysis of state.analyses) {
    if (!safe_relative(analysis.report_path) || !/^reports\/[0-9a-f-]{36}\.json$/.test(analysis.report_path)) fail('ORIX_CASE_REPORT_PATH', 'Analysis report path is invalid', { report_path: analysis.report_path });
    const reports_directory = paths.reports_path;
    let directory_stats;
    try { directory_stats = await fs.lstat(reports_directory); }
    catch (error) { fail('ORIX_CASE_REPORT_MISSING', 'Case reports directory is missing', { system_code: error.code }, error); }
    if (directory_stats.isSymbolicLink() || !directory_stats.isDirectory() || await fs.realpath(reports_directory) !== reports_directory) fail('ORIX_CASE_REPORT_PATH', 'Reports directory must be a regular non-symlink directory');
    const bytes = await read_bounded_file(path.join(paths.directory, ...analysis.report_path.split('/')), MAX_REPORT_BYTES, options);
    if (digest(bytes) !== analysis.report_sha256) fail('ORIX_CASE_REPORT_DIGEST', 'Stored analysis report SHA-256 does not match its case event', { run_id: analysis.run_id });
    let report;
    try { report = JSON.parse(bytes.toString('utf8')); } catch (error) { fail('ORIX_CASE_REPORT_INVALID', 'Stored analysis report is not valid JSON', { run_id: analysis.run_id }, error); }
    if ((report.schema_version ?? 'unknown') !== analysis.report_schema) fail('ORIX_CASE_REPORT_SCHEMA', 'Stored analysis report schema does not match its event', { run_id: analysis.run_id });
    verified.push({ run_id: analysis.run_id, sha256: analysis.report_sha256, valid: true });
  }
  return verified;
}
export async function verify_case(workspace_path, case_id, options = {}) {
  const paths = await case_directory(workspace_path, case_id);
  const verified = await verify_evidence_ledger(paths.events_path, options);
  const state = await load_state(paths, options);
  const reports = await verify_report_files(paths, state, options);
  return { schema_version: 'orix.case-verification.v1', case_id, valid: verified.valid && state.integrity.valid && reports.every(item => item.valid), records_verified: verified.records, head_hash: verified.head_hash, bytes: verified.bytes, first_timestamp: verified.first_timestamp, last_timestamp: verified.last_timestamp, findings: state.findings.length, artifact_references_recorded: state.artifacts.length, artifact_sources_revalidated: false, reports_verified: reports.length, reports };
}
export async function add_case_artifact(workspace_path, case_id, file_path, options = {}) {
  const paths = await case_directory(workspace_path, case_id);
  const io_options = { reject_hardlinks: options.reject_hardlinks === true };
  const absolute = path.resolve(file_path);
  let before;
  try { before = await fs.lstat(absolute); }
  catch (error) { fail('ORIX_CASE_ARTIFACT_UNAVAILABLE', 'Artifact path is unavailable', { path: absolute, system_code: error.code }, error); }
  if (before.isSymbolicLink() || !before.isFile()) fail('ORIX_CASE_ARTIFACT_UNSAFE', 'Case artifacts must be regular non-symlink files', { path: absolute });
  if (io_options.reject_hardlinks && before.nlink > 1) fail('ORIX_CASE_HARDLINK_REJECTED', 'Case artifact must not have hard-link aliases', { path: absolute, link_count: before.nlink });
  const real = await fs.realpath(absolute);
  if (!within(paths.root, real)) fail('ORIX_CASE_ARTIFACT_OUTSIDE_WORKSPACE', 'Artifact must be inside the case workspace', { path: real, workspace: paths.root });
  const report = await inspect_file(real, options);
  const sha256 = report.integrity?.digest;
  if (!HASH.test(sha256 ?? '')) fail('ORIX_CASE_ARTIFACT_HASH', 'Artifact inspection did not return a valid SHA-256 digest');
  const state = await load_state(paths, io_options);
  const existing = state.artifacts.find(item => item.sha256 === sha256);
  if (existing) return { schema_version: 'orix.case-artifact-receipt.v1', duplicate: true, artifact: existing };
  const artifact = {
    artifact_id: 'artifact-' + sha256,
    sha256,
    size_bytes: report.artifact.size_bytes,
    format: report.detection?.format ?? 'Unknown',
    parser_status: report.parser?.status ?? 'not-supported',
    source_path: path.relative(paths.root, real).split(path.sep).join('/'),
    added_at: new Date().toISOString(),
    stable_during_analysis: report.integrity.stable_during_read === true,
  };
  await append_event(paths, 'artifact.added', artifact, io_options);
  return { schema_version: 'orix.case-artifact-receipt.v1', duplicate: false, artifact };
}
export async function record_case_analysis(workspace_path, case_id, { report, tool = 'orix', tool_version = null, options = {} } = {}, io_options = {}) {
  const paths = await case_directory(workspace_path, case_id);
  plain_object(report, 'report');
  const bytes = Buffer.from(stable_json(report), 'utf8');
  if (bytes.length > MAX_REPORT_BYTES) fail('ORIX_CASE_REPORT_LIMIT', 'Analysis report exceeds the case report limit', { bytes: bytes.length, maximum: MAX_REPORT_BYTES });
  bounded_text(tool, 'tool', 100, true);
  if (tool_version !== null) bounded_text(tool_version, 'tool_version', 100);
  plain_object(options, 'options');
  const run_id = randomUUID();
  await ensure_directory(paths.reports_path);
  const relative_path = 'reports/' + run_id + '.json';
  const report_path = path.join(paths.directory, relative_path);
  await write_new_file(report_path, bytes);
  const record = {
    run_id,
    tool,
    tool_version,
    report_schema: typeof report.schema_version === 'string' ? report.schema_version : 'unknown',
    report_path: relative_path,
    report_sha256: digest(bytes),
    options_sha256: digest(Buffer.from(stable_json(options))),
    artifact_sha256: HASH.test(report.integrity?.digest ?? '') ? report.integrity.digest : null,
    recorded_at: new Date().toISOString(),
    coverage: canonical(report.coverage ?? report.scan?.coverage ?? {}),
    limitations: Array.isArray(report.limitations) ? report.limitations.slice(0, 100).map(item => String(item).slice(0, 500)) : [],
  };
  try { await append_event(paths, 'analysis.recorded', record, io_options); }
  catch (error) { await fs.rm(report_path, { force: true }).catch(() => {}); throw error; }
  return { schema_version: 'orix.case-analysis-receipt.v1', analysis: record };
}
export async function add_case_finding(workspace_path, case_id, {
  rule_id, title, summary = '', severity = 'unknown', confidence = 'unknown',
  artifact_id = null, run_id = null, evidence = [], source_location = null, references = [],
} = {}, io_options = {}) {
  const paths = await case_directory(workspace_path, case_id);
  bounded_text(rule_id, 'rule_id', 160, true); bounded_text(title, 'title', 300, true); bounded_text(summary, 'summary', 2000);
  if (!SEVERITIES.has(severity)) fail('ORIX_CASE_INVALID_FINDING', 'Finding severity is invalid', { severity });
  if (!CONFIDENCES.has(confidence)) fail('ORIX_CASE_INVALID_FINDING', 'Finding confidence is invalid', { confidence });
  if (artifact_id !== null) bounded_text(artifact_id, 'artifact_id', 100, true);
  if (run_id !== null && !UUID.test(run_id)) fail('ORIX_CASE_INVALID_FINDING', 'run_id must be a UUID');
  if (!Array.isArray(evidence) || evidence.length > 64) fail('ORIX_CASE_INVALID_FINDING', 'evidence must be an array of at most 64 entries');
  if (!Array.isArray(references) || references.length > 64) fail('ORIX_CASE_INVALID_FINDING', 'references must be an array of at most 64 entries');
  const state = await load_state(paths, io_options);
  if (artifact_id && !node_exists(state, 'artifact', artifact_id)) fail('ORIX_CASE_REFERENCE_MISSING', 'Finding references an artifact that is not in this case', { artifact_id });
  if (run_id && !node_exists(state, 'analysis', run_id)) fail('ORIX_CASE_REFERENCE_MISSING', 'Finding references an analysis run that is not in this case', { run_id });
  const normalized_evidence = evidence.map(item => {
    plain_object(item, 'evidence item');
    const item_confidence = item.confidence ?? confidence;
    if (!CONFIDENCES.has(item_confidence)) fail('ORIX_CASE_INVALID_EVIDENCE', 'Evidence confidence is invalid');
    return {
      evidence_id: randomUUID(),
      kind: bounded_text(item.kind ?? 'observation', 'evidence.kind', 80, true),
      summary: bounded_text(item.summary ?? '', 'evidence.summary', 1000, true),
      source: bounded_text(item.source ?? 'orix', 'evidence.source', 160, true),
      location: item.location === undefined ? null : canonical(item.location),
      confidence: item_confidence,
      details: item.details === undefined ? {} : canonical(item.details),
    };
  });
  const finding_id = randomUUID();
  const fingerprint = digest(Buffer.from(stable_json({ rule_id, title, summary, severity, artifact_id, source_location })));
  const record = {
    finding_id, fingerprint, rule_id, title, summary, severity, confidence,
    artifact_id, run_id, source_location: source_location === null ? null : canonical(source_location),
    evidence: normalized_evidence, references: references.map(value => bounded_text(value, 'reference', 500, true)),
    observed_at: new Date().toISOString(),
  };
  await append_event(paths, 'finding.recorded', record, io_options);
  return { schema_version: 'orix.case-finding-receipt.v1', finding: { ...record, status: 'open' } };
}
export async function change_case_finding_status(workspace_path, case_id, finding_id, status, reason = '', io_options = {}) {
  if (!UUID.test(finding_id)) fail('ORIX_CASE_INVALID_ID', 'Finding ID must be a UUID');
  if (!FINDING_STATES.has(status)) fail('ORIX_CASE_INVALID_STATUS', 'Finding status is not supported', { status });
  bounded_text(reason, 'reason', 1000);
  const paths = await case_directory(workspace_path, case_id);
  const state = await load_state(paths, io_options);
  if (!node_exists(state, 'finding', finding_id)) fail('ORIX_CASE_FINDING_NOT_FOUND', 'Finding was not found in this case', { finding_id });
  const current = state.findings.find(item => item.finding_id === finding_id);
  if (current.status === status) fail('ORIX_CASE_STATUS_UNCHANGED', 'Finding already has this status', { finding_id, status });
  await append_event(paths, 'finding.status_changed', { finding_id, status, reason, changed_at: new Date().toISOString() }, io_options);
  return { schema_version: 'orix.case-finding-status.v1', finding_id, previous_status: current.status, status };
}
export async function add_case_note(workspace_path, case_id, text, { links = [] } = {}, io_options = {}) {
  bounded_text(text, 'note', 5000, true);
  if (!Array.isArray(links) || links.length > 64) fail('ORIX_CASE_INVALID_NOTE', 'Note links must be an array of at most 64 IDs');
  const paths = await case_directory(workspace_path, case_id);
  const state = await load_state(paths, io_options);
  for (const link of links) {
    plain_object(link, 'note link');
    if (!node_exists(state, link.type, link.id)) fail('ORIX_CASE_REFERENCE_MISSING', 'Note link references an unknown case entity', { type: link.type, id: link.id });
  }
  const note = { note_id: randomUUID(), text, links: canonical(links), created_at: new Date().toISOString() };
  await append_event(paths, 'note.added', note, io_options);
  return { schema_version: 'orix.case-note-receipt.v1', note };
}
export async function add_case_relationship(workspace_path, case_id, { from_type, from_id, to_type, to_id, relation, confidence = 'derived' } = {}, io_options = {}) {
  const paths = await case_directory(workspace_path, case_id);
  const state = await load_state(paths, io_options);
  if (!node_exists(state, from_type, from_id) || !node_exists(state, to_type, to_id)) fail('ORIX_CASE_REFERENCE_MISSING', 'Relationship endpoints must exist in this case');
  if (from_type === to_type && from_id === to_id) fail('ORIX_CASE_INVALID_RELATIONSHIP', 'Relationship cannot point an entity to itself');
  bounded_text(relation, 'relation', 80, true);
  if (!CONFIDENCES.has(confidence)) fail('ORIX_CASE_INVALID_RELATIONSHIP', 'Relationship confidence is invalid');
  const duplicate = state.relationships.some(item => item.from_type === from_type && item.from_id === from_id && item.to_type === to_type && item.to_id === to_id && item.relation === relation);
  if (duplicate) fail('ORIX_CASE_RELATIONSHIP_EXISTS', 'This relationship already exists');
  const relationship = { relationship_id: randomUUID(), from_type, from_id, to_type, to_id, relation, confidence, created_at: new Date().toISOString() };
  await append_event(paths, 'relationship.added', relationship, io_options);
  return { schema_version: 'orix.case-relationship-receipt.v1', relationship };
}
export async function change_case_status(workspace_path, case_id, status, reason = '', io_options = {}) {
  if (!CASE_STATES.has(status)) fail('ORIX_CASE_INVALID_STATUS', 'Case status must be open, in_review or closed');
  bounded_text(reason, 'reason', 1000);
  const paths = await case_directory(workspace_path, case_id);
  const state = await load_state(paths, io_options);
  if (state.case.status === status) fail('ORIX_CASE_STATUS_UNCHANGED', 'Case already has this status', { status });
  await append_event(paths, 'case.status_changed', { status, reason, changed_at: new Date().toISOString() }, io_options);
  return { schema_version: 'orix.case-status.v1', case_id, previous_status: state.case.status, status };
}
export async function export_case_bundle(workspace_path, case_id, destination_path, options = {}) {
  const paths = await case_directory(workspace_path, case_id);
  const state = await load_state(paths, options);
  await verify_report_files(paths, state, options);
  const destination = path.resolve(destination_path);
  const parent = await fs.realpath(path.dirname(destination)).catch(error => fail('ORIX_CASE_EXPORT_PARENT', 'Bundle destination parent must exist', { path: path.dirname(destination), system_code: error.code }, error));
  const target = path.join(parent, path.basename(destination));
  if (!within(paths.root, parent) && within(paths.root, target)) fail('ORIX_CASE_EXPORT_PATH', 'Invalid bundle destination');
  try { await fs.lstat(target); fail('ORIX_CASE_EXPORT_EXISTS', 'Refusing to overwrite an existing case bundle', { path: target }); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  await ensure_directory(target);
  try {
    const files = [];
    const copy_entry = async relative => {
      if (!safe_relative(relative) || files.length >= MAX_BUNDLE_FILES) fail('ORIX_CASE_BUNDLE_LIMIT', 'Case bundle file count or path is invalid');
      const source = path.join(paths.directory, ...relative.split('/'));
      const bytes = await read_bounded_file(source, MAX_BUNDLE_BYTES, options);
      const output = path.join(target, ...relative.split('/'));
      await ensure_directory(path.dirname(output));
      await write_new_file(output, bytes);
      files.push({ path: relative, size_bytes: bytes.length, sha256: digest(bytes) });
    };
    await copy_entry('events.jsonl');
    for (const analysis of state.analyses) await copy_entry(analysis.report_path);
    const total = files.reduce((sum, file) => sum + file.size_bytes, 0);
    if (total > MAX_BUNDLE_BYTES) fail('ORIX_CASE_BUNDLE_LIMIT', 'Case bundle exceeds aggregate byte limit', { total, maximum: MAX_BUNDLE_BYTES });
    const manifest = {
      schema_version: BUNDLE_FORMAT,
      case_id,
      exported_at: new Date().toISOString(),
      case_head_hash: state.integrity.head_hash,
      event_count: state.timeline.length,
      files,
      source_artifacts_embedded: false,
      limitations: ['Artifact source files are referenced by workspace-relative path and SHA-256; their bytes are not copied.', 'Bundle hashes and the event chain detect accidental or partial modification but do not authenticate the exporter or provide a digital signature.'],
    };
    await write_new_file(path.join(target, 'manifest.json'), Buffer.from(stable_json(manifest) + '\n'));
    return { schema_version: 'orix.case-export.v1', case_id, destination: target, files: files.length, bytes: total, head_hash: state.integrity.head_hash, signed: false };
  } catch (error) { await fs.rm(target, { recursive: true, force: true }).catch(() => {}); throw error; }
}
export async function import_case_bundle(workspace_path, bundle_path, options = {}) {
  const source = path.resolve(bundle_path);
  let source_stats;
  try { source_stats = await fs.lstat(source); }
  catch (error) { fail('ORIX_CASE_BUNDLE_UNAVAILABLE', 'Case bundle directory is unavailable', { path: source, system_code: error.code }, error); }
  if (source_stats.isSymbolicLink() || !source_stats.isDirectory()) fail('ORIX_CASE_BUNDLE_UNSAFE', 'Case bundle must be a regular non-symlink directory');
  const real_source = await fs.realpath(source);
  const manifest_bytes = await read_bounded_file(path.join(real_source, 'manifest.json'), 2 * 1024 * 1024, options);
  let manifest;
  try { manifest = JSON.parse(manifest_bytes.toString('utf8')); }
  catch (error) { fail('ORIX_CASE_BUNDLE_MANIFEST', 'Case bundle manifest is invalid JSON', null, error); }
  if (manifest.schema_version !== BUNDLE_FORMAT || !UUID.test(manifest.case_id) || !Array.isArray(manifest.files) || manifest.files.length < 1 || manifest.files.length > MAX_BUNDLE_FILES) fail('ORIX_CASE_BUNDLE_MANIFEST', 'Case bundle manifest shape is invalid');
  const seen = new Set();
  let total = 0;
  const verified = [];
  for (const item of manifest.files) {
    if (!plain_bundle_file(item) || !safe_relative(item.path) || (!['events.jsonl'].includes(item.path) && !/^reports\/[0-9a-f-]{36}\.json$/.test(item.path)) || seen.has(item.path) || !HASH.test(item.sha256) || !Number.isSafeInteger(item.size_bytes) || item.size_bytes < 0) fail('ORIX_CASE_BUNDLE_MANIFEST', 'Case bundle file entry is invalid');
    seen.add(item.path);
    const segments = item.path.split('/');
    let parent = real_source;
    for (const segment of segments.slice(0, -1)) {
      parent = path.join(parent, segment);
      let parent_stats;
      try { parent_stats = await fs.lstat(parent); } catch (error) { fail('ORIX_CASE_BUNDLE_PATH', 'Bundle member parent is unavailable', { path: parent, system_code: error.code }, error); }
      if (parent_stats.isSymbolicLink() || !parent_stats.isDirectory() || await fs.realpath(parent) !== parent) fail('ORIX_CASE_BUNDLE_PATH', 'Bundle member parent must be a regular non-symlink directory', { path: parent });
    }
    const file_path = path.join(real_source, ...segments);
    if (!within(real_source, file_path)) fail('ORIX_CASE_BUNDLE_PATH', 'Bundle member escapes its directory');
    const bytes = await read_bounded_file(file_path, MAX_BUNDLE_BYTES, options);
    total += bytes.length;
    if (total > MAX_BUNDLE_BYTES || bytes.length !== item.size_bytes || digest(bytes) !== item.sha256) fail('ORIX_CASE_BUNDLE_DIGEST', 'Bundle member size or SHA-256 does not match its manifest', { path: item.path });
    verified.push({ path: item.path, bytes });
  }
  if (!seen.has('events.jsonl')) fail('ORIX_CASE_BUNDLE_MANIFEST', 'Bundle does not include its event ledger');
  if (!Number.isSafeInteger(manifest.event_count) || manifest.event_count < 1 || !HASH.test(manifest.case_head_hash ?? '')) fail('ORIX_CASE_BUNDLE_MANIFEST', 'Bundle event count or head hash is invalid');
  const paths = await workspace_paths(workspace_path, true);
  const directory = path.join(paths.cases, manifest.case_id);
  try { await fs.mkdir(directory, { mode: 0o700 }); }
  catch (error) { if (error.code === 'EEXIST') fail('ORIX_CASE_ALREADY_EXISTS', 'A case with this ID already exists', { case_id: manifest.case_id }); fail('ORIX_CASE_IMPORT_FAILED', 'Cannot create imported case directory', { system_code: error.code }, error); }
  try {
    for (const item of verified) {
      const output = path.join(directory, ...item.path.split('/'));
      await ensure_directory(path.dirname(output));
      await write_new_file(output, item.bytes);
    }
    const imported_paths = { ...paths, directory, events_path: path.join(directory, 'events.jsonl'), reports_path: path.join(directory, 'reports') };
    const state = await load_state(imported_paths, options);
    if (state.integrity.head_hash !== manifest.case_head_hash || state.timeline.length !== manifest.event_count) fail('ORIX_CASE_BUNDLE_CHAIN', 'Imported case event chain does not match the manifest');
    for (const analysis of state.analyses) if (!seen.has(analysis.report_path)) fail('ORIX_CASE_BUNDLE_REPORT_MISSING', 'Bundle is missing a referenced analysis report', { report_path: analysis.report_path });
    await verify_report_files(imported_paths, state, options);
    return { schema_version: 'orix.case-import.v1', case_id: manifest.case_id, title: state.case.title, events: state.timeline.length, reports: state.analyses.length, head_hash: state.integrity.head_hash, source_artifacts_embedded: false, signature_verified: false };
  } catch (error) { await fs.rm(directory, { recursive: true, force: true }).catch(() => {}); throw error; }
}
function plain_bundle_file(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype);
}
