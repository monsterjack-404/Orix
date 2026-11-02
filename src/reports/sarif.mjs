// JavaScript, src/reports/sarif.mjs, Node.js 20+, SARIF 2.1.0 static-finding export.

import path from 'node:path';
import { pathToFileURL } from 'node:url';

const LEVELS = Object.freeze({ critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' });

function collect_artifacts(report) {
  if (report.schema_version === 'orix.artifact.v1') return [report];
  if (report.schema_version === 'orix.scan.v1') return report.artifacts ?? [];
  throw new TypeError('SARIF export supports artifact and directory-scan reports only');
}

function evidence_region(indicator) {
  const item = indicator.evidence?.find(entry => Number.isSafeInteger(entry.offset) && entry.offset >= 0);
  if (!item) return undefined;
  return { byteOffset: item.offset, byteLength: Number.isSafeInteger(item.length) && item.length >= 0 ? item.length : undefined };
}

export function render_sarif(report, options = {}) {
  const artifacts = collect_artifacts(report);
  const rules = new Map();
  const results = [];
  for (const artifact of artifacts) {
    const uri = pathToFileURL(path.resolve(artifact.artifact.path)).href;
    for (const indicator of artifact.indicators ?? []) {
      if (!rules.has(indicator.rule_id)) {
        rules.set(indicator.rule_id, {
          id: indicator.rule_id,
          name: indicator.title,
          shortDescription: { text: indicator.title },
          fullDescription: { text: indicator.summary },
          defaultConfiguration: { level: LEVELS[indicator.severity] ?? 'warning' },
          properties: { severity: indicator.severity, confidence: indicator.confidence },
        });
      }
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
  const document = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'ORIX',
          informationUri: options.information_uri ?? 'https://github.com/monsterjack-404/Orix',
          semanticVersion: options.version ?? '0.4.0',
          rules: [...rules.values()].sort((a, b) => a.id.localeCompare(b.id)),
        },
      },
      results,
      properties: {
        report_schema: report.schema_version,
        static_analysis_only: true,
        malware_verdict_assigned: false,
      },
    }],
  };
  return JSON.stringify(document, null, options.compact ? 0 : 2) + '\n';
}
