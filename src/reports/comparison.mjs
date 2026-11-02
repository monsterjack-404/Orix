// JavaScript, src/reports/comparison.mjs, Node.js 20+, readable artifact comparison report.

function cell(value) {
  return String(value ?? '').replaceAll('|', '\\|').replaceAll('\n', ' ');
}

export function render_comparison_markdown(report) {
  const c = report.comparison;
  const lines = [
    '# ORIX Report Comparison', '',
    `- **Baseline:** \`${c.baseline_root}\``,
    `- **Current:** \`${c.current_root}\``,
    `- **Artifacts:** ${c.baseline_artifacts} → ${c.current_artifacts}`,
    '',
    '## Change summary', '',
    '| Change | Count |', '|---|---:|',
    `| Added | ${c.added} |`,
    `| Removed | ${c.removed} |`,
    `| Modified | ${c.modified} |`,
    `| Unchanged | ${c.unchanged} |`,
    `| Indicators introduced | ${c.indicators_introduced} |`,
    `| Indicators resolved | ${c.indicators_resolved} |`,
  ];
  for (const [key, title] of [['added','Added artifacts'],['removed','Removed artifacts'],['modified','Modified artifacts']]) {
    const entries = report.artifacts[key];
    lines.push('', '## ' + title, '');
    if (!entries.length) lines.push('None.');
    else if (key === 'modified') {
      lines.push('| Path | Before SHA-256 | After SHA-256 |', '|---|---|---|');
      for (const item of entries) lines.push(`| \`${cell(item.path)}\` | \`${item.before_sha256}\` | \`${item.after_sha256}\` |`);
    } else {
      lines.push('| Path | Format | SHA-256 |', '|---|---|---|');
      for (const item of entries) lines.push(`| \`${cell(item.path)}\` | ${item.format} | \`${item.sha256}\` |`);
    }
  }
  for (const [key, title] of [['introduced','New indicators'],['resolved','Resolved indicators']]) {
    const entries = report.indicators[key];
    lines.push('', '## ' + title, '');
    if (!entries.length) lines.push('None.');
    else {
      lines.push('| Severity | Rule | Path | Finding |', '|---|---|---|---|');
      for (const item of entries) lines.push(`| ${item.severity} | ${item.rule_id} | \`${cell(item.path)}\` | ${cell(item.summary)} |`);
    }
  }
  lines.push('', '## Limitations', '', ...report.limitations.map(item => '- ' + item), '');
  return lines.join('\n');
}
