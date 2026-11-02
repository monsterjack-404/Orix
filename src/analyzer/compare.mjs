// JavaScript, src/analyzer/compare.mjs, Node.js 20+, deterministic scan-report comparison.

import path from 'node:path';
import { OrixError } from '../core/errors.mjs';

function fail(code, message, details = {}) {
  throw new OrixError(code, message, { details, recoverable: true });
}

function validate_report(report, label) {
  if (!report || typeof report !== 'object') fail('ORIX_COMPARE_REPORT_INVALID', label + ' report must be an object');
  if (!['orix.scan.v1', 'orix.artifact.v1'].includes(report.schema_version)) {
    fail('ORIX_COMPARE_REPORT_UNSUPPORTED', label + ' report must be an artifact or directory-scan report', { schema_version: report.schema_version ?? null });
  }
  if (report.schema_version === 'orix.scan.v1' && !Array.isArray(report.artifacts)) {
    fail('ORIX_COMPARE_REPORT_INVALID', label + ' scan report has no artifact array');
  }
  if (report.schema_version === 'orix.artifact.v1' && (!report.artifact || !report.integrity)) {
    fail('ORIX_COMPARE_REPORT_INVALID', label + ' artifact report is missing identity or integrity metadata');
  }
}

function artifact_records(report) {
  if (report.schema_version === 'orix.artifact.v1') return [report];
  return report.artifacts;
}

function relative_key(artifact, report) {
  const absolute = path.resolve(artifact.artifact.path);
  if (report.schema_version === 'orix.artifact.v1') return path.basename(absolute);
  const root = path.resolve(report.scan.root);
  const relative = path.relative(root, absolute);
  if (relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
    fail('ORIX_COMPARE_PATH_ESCAPE', 'Artifact path falls outside its report root', { root, artifact: absolute });
  }
  return relative.split(path.sep).join('/');
}

function index_artifacts(report, label) {
  const indexed = new Map();
  for (const artifact of artifact_records(report)) {
    if (!artifact?.artifact?.path || !/^[a-f0-9]{64}$/i.test(artifact.integrity?.digest ?? '')) {
      fail('ORIX_COMPARE_ARTIFACT_INVALID', label + ' report contains an artifact without a valid path and SHA-256 digest');
    }
    const key = relative_key(artifact, report);
    if (indexed.has(key)) fail('ORIX_COMPARE_DUPLICATE_PATH', label + ' report contains duplicate normalized artifact paths', { path: key });
    indexed.set(key, artifact);
  }
  return indexed;
}

function indicator_key(path_key, indicator) {
  return [path_key, indicator.rule_id, indicator.severity, indicator.summary].join('\u0000');
}

function collect_indicators(indexed) {
  const findings = new Map();
  for (const [path_key, artifact] of indexed) {
    for (const indicator of artifact.indicators ?? []) {
      if (!indicator || typeof indicator.rule_id !== 'string') continue;
      const key = indicator_key(path_key, indicator);
      findings.set(key, { path: path_key, rule_id: indicator.rule_id, title: indicator.title ?? indicator.rule_id, severity: indicator.severity ?? 'info', summary: indicator.summary ?? '' });
    }
  }
  return findings;
}

export function compare_reports(baseline, current) {
  validate_report(baseline, 'Baseline');
  validate_report(current, 'Current');
  const before = index_artifacts(baseline, 'Baseline');
  const after = index_artifacts(current, 'Current');
  const added = [];
  const removed = [];
  const modified = [];
  const unchanged = [];
  for (const [key, item] of after) {
    const prior = before.get(key);
    if (!prior) added.push({ path: key, sha256: item.integrity.digest, format: item.detection?.format ?? 'Unknown' });
    else if (prior.integrity.digest !== item.integrity.digest) {
      modified.push({ path: key, before_sha256: prior.integrity.digest, after_sha256: item.integrity.digest, before_format: prior.detection?.format ?? 'Unknown', after_format: item.detection?.format ?? 'Unknown' });
    } else unchanged.push({ path: key, sha256: item.integrity.digest });
  }
  for (const [key, item] of before) {
    if (!after.has(key)) removed.push({ path: key, sha256: item.integrity.digest, format: item.detection?.format ?? 'Unknown' });
  }
  const prior_findings = collect_indicators(before);
  const current_findings = collect_indicators(after);
  const introduced = [...current_findings].filter(([key]) => !prior_findings.has(key)).map(([, value]) => value);
  const resolved = [...prior_findings].filter(([key]) => !current_findings.has(key)).map(([, value]) => value);
  const sort_path = (a, b) => a.path.localeCompare(b.path);
  added.sort(sort_path); removed.sort(sort_path); modified.sort(sort_path); unchanged.sort(sort_path);
  introduced.sort((a, b) => a.path.localeCompare(b.path) || a.rule_id.localeCompare(b.rule_id));
  resolved.sort((a, b) => a.path.localeCompare(b.path) || a.rule_id.localeCompare(b.rule_id));
  return {
    schema_version: 'orix.comparison.v1',
    comparison: {
      baseline_schema: baseline.schema_version,
      current_schema: current.schema_version,
      baseline_root: baseline.scan?.root ?? baseline.artifact.path,
      current_root: current.scan?.root ?? current.artifact.path,
      baseline_artifacts: before.size,
      current_artifacts: after.size,
      added: added.length,
      removed: removed.length,
      modified: modified.length,
      unchanged: unchanged.length,
      indicators_introduced: introduced.length,
      indicators_resolved: resolved.length,
    },
    artifacts: { added, removed, modified, unchanged },
    indicators: { introduced, resolved },
    limitations: [
      'Comparison uses normalized report-relative paths and SHA-256 identity; renamed files appear as one removal and one addition.',
      'Indicator deltas compare rule ID, severity and summary. They do not prove runtime behavior or exploitability.',
      'Reports are compared as supplied; this operation does not rescan either filesystem tree.',
    ],
  };
}
