// JavaScript, src/reports/view-model.mjs, Node.js 20+, normalized ORIX report viewer model.

const severities = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);
const object = (value, label) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(label + ' must be an object');
  }
};

function findings(value, label) {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new TypeError(label + ' must be an array');
  return value
    .filter(item => item && typeof item === 'object' &&
      typeof item.rule_id === 'string' && item.rule_id)
    .map(item => ({
      rule_id: item.rule_id,
      title: String(item.title ?? item.label ?? item.rule_id),
      summary: String(item.summary ?? item.evidence ?? item.description ?? item.label ?? item.rule_id),
      severity: severities.includes(item.severity) ? item.severity : 'info',
      confidence: String(item.confidence ?? 'unknown'),
      line: Number.isSafeInteger(item.line) && item.line > 0 ? item.line : null,
    }));
}

function artifact(value, index) {
  object(value, 'Artifact record');
  object(value.artifact, 'Artifact identity');
  if (typeof value.artifact.path !== 'string' || !value.artifact.path) {
    throw new TypeError('Artifact record requires a non-empty path');
  }
  const hash = value.integrity?.digest ?? null;
  if (hash !== null && (typeof hash !== 'string' || !/^[a-f0-9]{64}$/i.test(hash))) {
    throw new TypeError('Invalid SHA-256 digest');
  }
  const size = value.artifact.size_bytes ?? 0;
  if (!Number.isSafeInteger(size) || size < 0) throw new TypeError('Invalid artifact size');
  return {
    id: 'artifact:' + index + ':' + value.artifact.path + ':' + (hash ?? ''),
    kind: 'artifact',
    path: value.artifact.path,
    name: String(value.artifact.name ?? value.artifact.path.split(/[\\/]/).at(-1)),
    format: String(value.detection?.format ?? 'Unknown'),
    size_bytes: size,
    sha256: hash,
    parser_status: String(value.parser?.status ?? 'unknown'),
    findings: findings(value.indicators, 'Artifact indicators'),
    raw: value,
  };
}

function source(file, index, by_file) {
  object(file, 'Project file');
  if (typeof file.path !== 'string' || !file.path) {
    throw new TypeError('Project file requires a non-empty path');
  }
  const hash = file.sha256 ?? file.digest ?? null;
  if (hash !== null && (typeof hash !== 'string' || !/^[a-f0-9]{64}$/i.test(hash))) {
    throw new TypeError('Invalid project SHA-256 digest');
  }
  const size = file.size_bytes ?? file.bytes ?? 0;
  if (!Number.isSafeInteger(size) || size < 0) throw new TypeError('Invalid project file size');
  return {
    id: 'source:' + index + ':' + file.path + ':' + (hash ?? ''),
    kind: 'source',
    path: file.path,
    name: String(file.name ?? file.path.split(/[\\/]/).at(-1)),
    format: String(file.language ?? file.format ?? 'Source'),
    size_bytes: size,
    sha256: hash,
    parser_status: 'indexed',
    findings: findings(by_file.get(file.path) ?? [], 'Project findings'),
    raw: file,
  };
}

function provider_import(report, item, index) {
  object(item, 'Rizin import');
  const name = typeof item.name === 'string' && item.name ? item.name : '(unnamed import)';
  const library = typeof item.library === 'string' ? item.library : '';
  return {
    id: 'provider-import:' + index + ':' + name + ':' + library,
    kind: 'provider-import',
    path: report.artifact.path,
    name,
    library,
    format: 'Native import',
    size_bytes: 0,
    sha256: report.artifact.sha256,
    parser_status: 'Rizin ' + String(report.provider.engine_version ?? 'unknown'),
    findings: [],
    raw: { provider: report.provider, artifact: report.artifact, import: item },
  };
}

function summarize(records, report, kind) {
  const formats = new Map();
  const severity = new Map(severities.map(value => [value, 0]));
  let bytes = 0;
  let total = 0;
  let with_findings = 0;
  for (const record of records) {
    bytes += record.size_bytes;
    formats.set(record.format, (formats.get(record.format) ?? 0) + 1);
    if (record.findings.length) with_findings += 1;
    for (const finding of record.findings) {
      severity.set(finding.severity, severity.get(finding.severity) + 1);
      total += 1;
    }
  }
  if (kind === 'provider-imports') bytes = report.artifact.size_bytes;
  return {
    items: records.length,
    bytes,
    findings: total,
    files_with_findings: with_findings,
    severity: Object.fromEntries(severities.map(value => [value, severity.get(value)])),
    formats: [...formats].map(([name, count]) => ({ name, count }))
      .sort((left, right) => left.name.localeCompare(right.name)),
    dependencies: Array.isArray(report.dependencies) ? report.dependencies.length : 0,
  };
}

export function build_report_view(report) {
  object(report, 'Report');
  let kind;
  let root;
  let records;
  if (report.schema_version === 'orix.artifact.v1') {
    kind = 'artifact';
    records = [artifact(report, 0)];
    root = report.artifact.path;
  } else if (report.schema_version === 'orix.scan.v1') {
    kind = 'scan';
    if (!Array.isArray(report.artifacts)) throw new TypeError('Scan report requires an artifacts array');
    root = typeof report.scan?.root === 'string' ? report.scan.root : '';
    records = report.artifacts.map(artifact);
  } else if (report.schema_version === 'orix.project.v1') {
    kind = 'project';
    if (!Array.isArray(report.files) || !Array.isArray(report.findings ?? [])) {
      throw new TypeError('Project report requires files and findings arrays');
    }
    root = typeof report.project?.root === 'string' ? report.project.root : '';
    const by_file = new Map();
    for (const finding of report.findings ?? []) {
      if (typeof finding?.file !== 'string') continue;
      const list = by_file.get(finding.file) ?? [];
      list.push(finding);
      by_file.set(finding.file, list);
    }
    records = report.files.map((file, index) => source(file, index, by_file));
    const known = new Set(records.map(record => record.path));
    for (const [file, list] of by_file) {
      if (!known.has(file)) records.push(source({ path: file }, records.length, new Map([[file, list]])));
    }
  } else if (report.schema_version === 'orix.rizin-imports.v1') {
    object(report.provider, 'Provider identity');
    object(report.artifact, 'Provider artifact');
    if (typeof report.artifact.path !== 'string' || !report.artifact.path ||
        typeof report.artifact.sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(report.artifact.sha256) ||
        !Number.isSafeInteger(report.artifact.size_bytes) || report.artifact.size_bytes < 0 ||
        !Array.isArray(report.imports)) {
      throw new TypeError('Rizin import report requires a valid artifact identity and imports array');
    }
    kind = 'provider-imports';
    root = report.artifact.path;
    records = report.imports.map((item, index) => provider_import(report, item, index));
  } else if (report.schema_version === 'orix.provider-probe.v1') {
    object(report.provider, 'Provider identity');
    if (typeof report.provider.id !== 'string' || typeof report.provider.engine_version !== 'string' ||
        typeof report.provider.executable !== 'string' || report.status !== 'available') {
      throw new TypeError('Provider probe report requires an available provider identity');
    }
    kind = 'provider-probe';
    root = report.provider.executable;
    records = [{
      id: 'provider:' + report.provider.id + ':' + report.provider.engine_version,
      kind: 'provider',
      path: report.provider.executable,
      name: report.provider.id + ' ' + report.provider.engine_version,
      format: 'Provider',
      size_bytes: 0,
      sha256: null,
      parser_status: report.status,
      findings: [],
      raw: report,
    }];
  } else {
    throw new TypeError('Viewer supports orix.artifact.v1, orix.scan.v1, orix.project.v1, orix.rizin-imports.v1 and orix.provider-probe.v1 reports');
  }
  records.sort((left, right) => left.path.localeCompare(right.path, 'en'));
  return Object.freeze({
    schema_version: report.schema_version,
    kind,
    root,
    records,
    summary: summarize(records, report, kind),
    generated_at: report.scan?.completed_at ?? report.project?.scanned_at ?? null,
  });
}

export function filter_report_view(view, filters = {}) {
  if (!view || !Array.isArray(view.records)) throw new TypeError('A normalized report view is required');
  const query = String(filters.query ?? '').trim().toLocaleLowerCase('en');
  const severity = filters.severity ?? 'all';
  const format = filters.format ?? 'all';
  if (severity !== 'all' && !severities.includes(severity)) throw new TypeError('Unknown severity filter');
  return view.records.filter(record => {
    if (format !== 'all' && record.format !== format) return false;
    if (severity !== 'all' && !record.findings.some(finding => finding.severity === severity)) return false;
    if (!query) return true;
    return [
      record.path, record.name, record.library ?? '', record.format, record.sha256 ?? '',
      ...record.findings.flatMap(finding => [finding.rule_id, finding.title, finding.summary]),
    ].join(' ').toLocaleLowerCase('en').includes(query);
  });
}

export const REPORT_VIEW_SEVERITIES = severities;
