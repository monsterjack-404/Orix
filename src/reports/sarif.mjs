// JavaScript, src/reports/sarif.mjs, Node.js 20+, SARIF 2.1.0 export for artifact, scan and project findings.

import { createHash } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const LEVELS = Object.freeze({ critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' });

function collect_artifacts(report) {
  if (report.schema_version === 'orix.artifact.v1') return [report];
  if (report.schema_version === 'orix.scan.v1') return report.artifacts ?? [];
  if (report.schema_version === 'orix.project.v1') return [];
  throw new TypeError('SARIF export supports artifact, directory-scan and project reports only');
}

function evidence_region(indicator) {
  const item = indicator.evidence?.find(entry => Number.isSafeInteger(entry.offset) && entry.offset >= 0);
  if (!item) return undefined;
  return {
    byteOffset: item.offset,
    byteLength: Number.isSafeInteger(item.length) && item.length >= 0 ? item.length : undefined,
  };
}

function project_file_uri(report, finding) {
  const root_input = report.project?.root;
  const relative_input = finding.file;
  if (typeof root_input !== 'string' || root_input.trim() === '') {
    throw new TypeError('Project SARIF export requires an absolute project root');
  }
  if (typeof relative_input !== 'string' || relative_input.trim() === '' || relative_input.includes('\0')) {
    throw new TypeError('Project SARIF finding requires a valid relative file path');
  }
  if (path.isAbsolute(relative_input) || path.win32.isAbsolute(relative_input)) {
    throw new TypeError('Project SARIF finding path must be relative to the project root');
  }
  const root = path.resolve(root_input);
  const absolute = path.resolve(root, relative_input);
  const relative = path.relative(root, absolute);
  if (!relative || relative === '.' || relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) {
    throw new TypeError('Project SARIF finding path escapes the project root or names the project root');
  }
  return pathToFileURL(absolute).href;
}

function add_rule(rules, finding) {
  if (rules.has(finding.rule_id)) return;
  const title = finding.title ?? finding.label ?? finding.rule_id;
  const summary = finding.summary ?? finding.description ?? finding.evidence ?? title;
  rules.set(finding.rule_id, {
    id: finding.rule_id,
    name: title,
    shortDescription: { text: title },
    fullDescription: { text: summary },
    defaultConfiguration: { level: LEVELS[finding.severity] ?? 'warning' },
    properties: {
      severity: finding.severity,
      confidence: finding.confidence,
      tags: finding.rule_id.includes('SECRET') ? ['security', 'secret-detection'] : ['static-analysis'],
    },
  });
}

function project_results(report, rules) {
  const file_hashes = new Map((report.files ?? []).map(file => [file.path, file.sha256]));
  const artifacts = new Map();
  const results = [];
  for (const finding of report.findings ?? []) {
    if (typeof finding.rule_id !== 'string' || finding.rule_id.length === 0) {
      throw new TypeError('Project SARIF findings require a rule_id');
    }
    if (!Number.isSafeInteger(finding.line) || finding.line < 1) {
      throw new TypeError('Project SARIF findings require a positive line number');
    }
    const uri = project_file_uri(report, finding);
    const sha256 = file_hashes.get(finding.file) ?? null;
    add_rule(rules, finding);
    artifacts.set(uri, { location: { uri } });
    const fingerprint = createHash('sha256')
      .update([finding.rule_id, finding.file, finding.line, sha256 ?? ''].join('\0'))
      .digest('hex');
    results.push({
      ruleId: finding.rule_id,
      level: LEVELS[finding.severity] ?? 'warning',
      message: {
        text: (finding.label ?? finding.rule_id) + ': static source pattern matched; review this line. Matched content is redacted.',
      },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri },
          region: { startLine: finding.line },
        },
      }],
      partialFingerprints: { primaryLocationLineHash: fingerprint },
      properties: {
        confidence: finding.confidence ?? 'unknown',
        severity: finding.severity ?? 'warning',
        project_file: finding.file,
        artifact_sha256: sha256,
        evidence: 'Credential-shaped or policy-defined source match; original matched content is not exported.',
      },
    });
  }
  return { artifacts: [...artifacts.values()].sort((a, b) => a.location.uri.localeCompare(b.location.uri)), results };
}

export function render_sarif(report, options = {}) {
  const rules = new Map();
  const results = [];
  let project_artifacts = [];
  if (report.schema_version === 'orix.project.v1') {
    const project = project_results(report, rules);
    project_artifacts = project.artifacts;
    results.push(...project.results);
  } else {
    for (const artifact of collect_artifacts(report)) {
      const uri = pathToFileURL(path.resolve(artifact.artifact.path)).href;
      for (const indicator of artifact.indicators ?? []) {
        add_rule(rules, indicator);
        const location = { physicalLocation: { artifactLocation: { uri } } };
        const region = evidence_region(indicator);
        if (region) location.physicalLocation.region = region;
        results.push({
          ruleId: indicator.rule_id,
          level: LEVELS[indicator.severity] ?? 'warning',
          message: { text: indicator.summary },
          locations: [{ location }],
          partialFingerprints: { primaryLocationLineHash: artifact.integrity?.digest ?? uri },
          properties: {
            confidence: indicator.confidence,
            severity: indicator.severity,
            evidence: indicator.evidence ?? [],
            artifact_sha256: artifact.integrity?.digest ?? null,
          },
        });
      }
    }
  }
  const document = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'ORIX',
          informationUri: options.information_uri ?? 'https://github.com/monsterjack-404/Orix',
          semanticVersion: options.version ?? '0.5.0',
          rules: [...rules.values()].sort((a, b) => a.id.localeCompare(b.id)),
        },
      },
      artifacts: project_artifacts,
      results,
      properties: {
        report_schema: report.schema_version,
        static_analysis_only: true,
        malware_verdict_assigned: false,
        project_findings_redacted: report.schema_version === 'orix.project.v1',
      },
    }],
  };
  return JSON.stringify(document, null, options.compact ? 0 : 2) + '\n';
}
