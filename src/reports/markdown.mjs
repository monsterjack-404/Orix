// JavaScript, src/reports/markdown.mjs, Node.js 20+, human-readable evidence report rendering.

function escape_cell(value) {
  return String(value ?? '').replaceAll('|', '\\|').replaceAll('\n', ' ');
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
    `- **Artifact:** \`${report.artifact.name}\``,
    `- **Path:** \`${report.artifact.path}\``,
    `- **Size:** ${byte_size(report.artifact.size_bytes)}`,
    `- **Format:** ${report.detection.format} (${report.detection.confidence})`,
    `- **SHA-256:** \`${report.integrity.digest}\``,
    `- **Stable during read:** ${report.integrity.stable_during_read ? 'yes' : 'no'}`,
    '', '## Parser result', '',
  ];
  if (report.parser.status === 'parsed') {
    lines.push('```json', JSON.stringify(report.parser.result, null, 2), '```');
  } else {
    lines.push(`Parser status: **${report.parser.status}**`);
    if (report.parser.error) lines.push(`- Error: \`${report.parser.error.code}\` — ${report.parser.error.message}`);
  }
  lines.push('', '## Metrics', '',
    `- Shannon entropy: **${report.metrics.entropy.bits_per_byte} bits/byte** (${report.metrics.entropy.scope})`,
    `- Extracted strings: **${report.metrics.strings.count}**`,
    `- Hex preview: \`${report.metrics.hex_preview || '(empty)'}\``,
    '', '## Extracted strings', '',
    '| Offset | Encoding | Length | Value |', '|---:|---|---:|---|');
  for (const item of report.metrics.strings.values) lines.push(`| ${item.offset} | ${item.encoding} | ${item.length} | ${escape_cell(item.value)} |`);
  lines.push('', '## Evidence', '', '| ID | Kind | Confidence | Offset | Summary |', '|---|---|---|---:|---|');
  for (const evidence of report.evidence) lines.push(`| ${evidence.id} | ${evidence.kind} | ${evidence.confidence} | ${evidence.offset ?? '—'} | ${escape_cell(evidence.summary)} |`);
  if (report.warnings.length) lines.push('', '## Warnings', '', ...report.warnings.map(value => `- ${value}`));
  lines.push('', '> ORIX performs static, read-only inspection. A recognized format or parsed header does not establish that an artifact is benign.', '');
  return lines.join('\n');
}

export function render_scan_markdown(report) {
  const lines = [
    '# ORIX Directory Scan', '',
    `- **Root:** \`${report.scan.root}\``,
    `- **Files analyzed:** ${report.scan.files_analyzed}`,
    `- **Files skipped:** ${report.scan.files_skipped}`,
    `- **Bytes analyzed:** ${byte_size(report.scan.total_bytes_analyzed)}`,
    `- **Duration:** ${report.scan.duration_ms} ms`, '',
    '## Format distribution', '', '| Format | Files |', '|---|---:|',
  ];
  for (const [format, count] of Object.entries(report.scan.formats)) lines.push(`| ${format} | ${count} |`);
  lines.push('', '## Artifacts', '', '| File | Format | Size | SHA-256 | Parser |', '|---|---|---:|---|---|');
  for (const artifact of report.artifacts) {
    lines.push(`| \`${escape_cell(artifact.artifact.path)}\` | ${artifact.detection.format} | ${byte_size(artifact.artifact.size_bytes)} | \`${artifact.integrity.digest}\` | ${artifact.parser.status} |`);
  }
  if (report.errors.length) {
    lines.push('', '## File errors', '');
    for (const item of report.errors) lines.push(`- \`${item.path}\`: ${item.error.code} — ${item.error.message}`);
  }
  if (report.inventory_skips.length) {
    lines.push('', '## Inventory skips', '');
    for (const item of report.inventory_skips) lines.push(`- \`${item.path}\`: ${item.reason}`);
  }
  lines.push('', '## Coverage', '', `- Directories examined: ${report.scan.coverage.directories_examined}`, `- Inventory truncated: ${report.scan.coverage.truncated ? 'yes' : 'no'}`, '', ...report.limitations.map(item => `- ${item}`), '');
  return lines.join('\n');
}
