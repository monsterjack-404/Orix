// JavaScript, src/reports/rizin.mjs, Node.js 20+, bounded Rizin import report rendering.

function markdown_cell(value) {
  return String(value ?? '—')
    .replaceAll('\\', '\\\\')
    .replaceAll('|', '\\|')
    .replace(/[\r\n\t]+/g, ' ');
}

export function render_rizin_imports_markdown(report, options = {}) {
  if (!report || report.schema_version !== 'orix.rizin-imports.v1' ||
      !Array.isArray(report.imports) || !report.provider || !report.artifact) {
    throw new TypeError('render_rizin_imports_markdown requires an orix.rizin-imports.v1 report');
  }
  const maximum_rows = options.max_rows ?? 2_000;
  if (!Number.isSafeInteger(maximum_rows) || maximum_rows < 0 || maximum_rows > 20_000) {
    throw new TypeError('max_rows must be an integer between 0 and 20000');
  }

  const lines = [
    '# Rizin Import Analysis',
    '',
    '- **Provider:** ' + markdown_cell(report.provider.id) + ' ' + markdown_cell(report.provider.engine_version),
    '- **Artifact:** ' + markdown_cell(report.artifact.path),
    '- **SHA-256:** ' + markdown_cell(report.artifact.sha256),
    '- **Size:** ' + report.artifact.size_bytes + ' bytes',
    '- **Input stable:** ' + (report.artifact.stable_during_analysis ? 'yes' : 'no'),
    '- **Imports:** ' + report.summary.imports,
    '- **Libraries:** ' + report.summary.libraries,
    '',
    '| Name | Library | Ordinal | Binding | Type | PLT |',
    '|---|---|---:|---|---|---:|',
  ];

  for (const item of report.imports.slice(0, maximum_rows)) {
    lines.push('| ' + [
      item.name, item.library, item.ordinal, item.bind, item.type, item.plt,
    ].map(markdown_cell).join(' | ') + ' |');
  }

  const omitted = Math.max(0, report.imports.length - maximum_rows);
  if (omitted > 0) {
    lines.push('', '_' + omitted + ' additional imports omitted from this Markdown view._');
  }
  if (report.diagnostics?.stderr) {
    lines.push('', '## Provider diagnostics', '', '~~~text', report.diagnostics.stderr.slice(0, 1024), '~~~');
  }
  lines.push(
    '',
    '## Analysis boundaries',
    '',
    '- Static import metadata only; the inspected target is not executed.',
    '- Rizin is an external optional dependency.',
    '- The provider process is bounded by timeout and captured-output limits, not OS-sandboxed.',
    '',
  );
  return lines.join('\n');
}
