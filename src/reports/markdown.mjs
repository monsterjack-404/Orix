// JavaScript, src/reports/markdown.mjs, Node.js 20+, human-readable evidence report rendering.

function escape_cell(value) {
  return String(value ?? '').replaceAll('\\', '\\\\').replaceAll('|', '\\|').replace(/[\r\n]+/g, ' ');
}

function code_span(value) {
  const text = escape_cell(value);
  const marker = String.fromCharCode(96);
  const runs = [...text.matchAll(new RegExp(marker + '+', 'g'))].map(match => match[0].length);
  const fence = marker.repeat(Math.max(1, ...runs.map(length => length + 1)));
  const padding = text.startsWith(marker) || text.endsWith(marker) || text.startsWith(' ') || text.endsWith(' ') ? ' ' : '';
  return fence + padding + text + padding + fence;
}

function fenced_block(value, language = '') {
  const text = String(value ?? '');
  const runs = [...text.matchAll(/^~{3,}/gm)].map(match => match[0].length);
  const fence = '~'.repeat(Math.max(3, ...runs.map(length => length + 1)));
  return [fence + language, text, fence];
}

function byte_size(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(2)} KiB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(2)} MiB`;
  return `${(value / 1024 ** 3).toFixed(2)} GiB`;
}

export function render_inspection_markdown(report) {
  const lines = [
    `# ORIX Artifact Report`, '',
    `- **Artifact:** ${code_span(report.artifact.name)}`,
    `- **Path:** ${code_span(report.artifact.path)}`,
    `- **Size:** ${byte_size(report.artifact.size_bytes)}`,
    `- **Format:** ${report.detection.format} (${report.detection.confidence})`,
    `- **SHA-256:** ${code_span(report.integrity.digest)}`,
    `- **Stable during read:** ${report.integrity.stable_during_read ? 'yes' : 'no'}`,
    '', '## Parser result', '',
  ];
  if (report.parser.status === 'parsed') {
    lines.push(...fenced_block(JSON.stringify(report.parser.result, null, 2), 'json'));
  } else {
    lines.push(`Parser status: **${report.parser.status}**`);
    if (report.parser.error) lines.push(`- Error: ${code_span(report.parser.error.code)} — ${escape_cell(report.parser.error.message)}`);
  }
  lines.push('', '## Metrics', '',
    `- Shannon entropy: **${report.metrics.entropy.bits_per_byte} bits/byte** (${report.metrics.entropy.scope})`,
    `- Extracted strings: **${report.metrics.strings.count}**`,
    `- Hex preview: ${code_span(report.metrics.hex_preview || '(empty)')}`,
    '', '## Static indicators', '');
  if (report.indicators?.length) {
    lines.push('| Severity | Rule | Confidence | Finding |', '|---|---|---|---|');
    for (const indicator of report.indicators) lines.push(`| ${indicator.severity} | ${indicator.rule_id} | ${indicator.confidence} | ${escape_cell(indicator.summary)} |`);
  } else {
    lines.push('No built-in static indicator rules matched the analyzed sample.');
  }
  lines.push('', '## Extracted strings', '',
    '| Offset | Encoding | Length | Value |', '|---:|---|---:|---|');
  for (const item of report.metrics.strings.values) lines.push(`| ${item.offset} | ${item.encoding} | ${item.length} | ${code_span(item.value)} |`);
  lines.push('', '## Evidence', '', '| ID | Kind | Confidence | Offset | Summary |', '|---|---|---|---:|---|');
  for (const evidence of report.evidence) lines.push(`| ${evidence.id} | ${evidence.kind} | ${evidence.confidence} | ${evidence.offset ?? '—'} | ${escape_cell(evidence.summary)} |`);
  if (report.warnings.length) lines.push('', '## Warnings', '', ...report.warnings.map(value => `- ${escape_cell(value)}`));
  lines.push('', '> ORIX performs static, read-only inspection. A recognized format or parsed header does not establish that an artifact is benign.', '');
  return lines.join('\n');
}

export function render_scan_markdown(report) {
  const lines = [
    '# ORIX Directory Scan', '',
    `- **Root:** ${code_span(report.scan.root)}`,
    `- **Files analyzed:** ${report.scan.files_analyzed}`,
    `- **Files skipped:** ${report.scan.files_skipped}`,
    `- **Files with indicators:** ${report.scan.files_with_indicators ?? 0}`,
    `- **Bytes analyzed:** ${byte_size(report.scan.total_bytes_analyzed)}`,
    `- **Indicator counts:** ${Object.entries(report.scan.indicator_counts ?? {}).map(([key, value]) => `${key}=${value}`).join(', ') || 'none'}`,
    `- **Duration:** ${report.scan.duration_ms} ms`, '',
    '## Format distribution', '', '| Format | Files |', '|---|---:|',
  ];
  for (const [format, count] of Object.entries(report.scan.formats)) lines.push(`| ${format} | ${count} |`);
  lines.push('', '## Artifacts', '', '| File | Format | Size | SHA-256 | Parser |', '|---|---|---:|---|---|');
  for (const artifact of report.artifacts) {
    lines.push(`| ${code_span(artifact.artifact.path)} | ${artifact.detection.format} | ${byte_size(artifact.artifact.size_bytes)} | ${code_span(artifact.integrity.digest)} | ${artifact.parser.status} |`);
  }
  const indicators = report.artifacts.flatMap(artifact => (artifact.indicators ?? []).map(indicator => ({ path: artifact.artifact.path, ...indicator })));
  if (indicators.length) {
    lines.push('', '## Static indicators', '', '| Severity | Rule | File | Finding |', '|---|---|---|---|');
    for (const indicator of indicators) lines.push(`| ${indicator.severity} | ${indicator.rule_id} | ${code_span(indicator.path)} | ${escape_cell(indicator.summary)} |`);
  }
  if (report.errors.length) {
    lines.push('', '## File errors', '');
    for (const item of report.errors) lines.push(`- ${code_span(item.path)}: ${item.error.code} — ${escape_cell(item.error.message)}`);
  }
  if (report.inventory_skips.length) {
    lines.push('', '## Inventory skips', '');
    for (const item of report.inventory_skips) lines.push(`- ${code_span(item.path)}: ${escape_cell(item.reason)}`);
  }
  lines.push('', '## Coverage', '', `- Directories examined: ${report.scan.coverage.directories_examined}`, `- Inventory truncated: ${report.scan.coverage.truncated ? 'yes' : 'no'}`, '', ...report.limitations.map(item => `- ${item}`), '');
  return lines.join('\n');
}
