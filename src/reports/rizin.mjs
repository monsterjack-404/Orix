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
  if (report.decompilation) {
    const source = String(report.decompilation.source ?? '').replace(/\r/g, '');
    const longest_fence = Math.max(2, ...Array.from(source.matchAll(/~+/g), match => match[0].length));
    const fence = '~'.repeat(longest_fence + 1);
    lines.push(
      '',
      '## Optional pseudocode decompilation',
      '',
      '- **Backend:** ' + function_cell(report.decompilation.backend),
      '- **Function:** ' + function_cell(report.decompilation.function_name),
      '- **Entry:** 0x' + report.decompilation.address.toString(16),
      '- **Output truncated:** ' + (report.decompilation.truncated ? 'yes' : 'no'),
      '',
      fence + 'c',
      source,
      fence,
    );
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


function function_cell(value) {
  return String(value ?? '—')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('\\', '\\\\')
    .replaceAll('|', '\\|')
    .replace(/[\r\n\t]+/g, ' ');
}

export function render_rizin_functions_markdown(report, options = {}) {
  if (!report || report.schema_version !== 'orix.rizin-functions.v1' ||
      !Array.isArray(report.functions) || !report.provider || !report.artifact || !report.summary) {
    throw new TypeError('render_rizin_functions_markdown requires an orix.rizin-functions.v1 report');
  }
  const maximum_rows = options.max_rows ?? 2_000;
  if (!Number.isSafeInteger(maximum_rows) || maximum_rows < 0 || maximum_rows > 20_000) {
    throw new TypeError('max_rows must be an integer between 0 and 20000');
  }
  const lines = [
    '# Rizin Function Analysis',
    '',
    '- **Provider:** ' + function_cell(report.provider.id) + ' ' + function_cell(report.provider.engine_version),
    '- **Artifact:** ' + function_cell(report.artifact.path),
    '- **SHA-256:** ' + function_cell(report.artifact.sha256),
    '- **Functions:** ' + report.summary.functions_returned + ' / ' + report.summary.functions_total,
    '- **Function inventory truncated:** ' + (report.summary.functions_truncated ? 'yes' : 'no'),
    '',
    '| Function | Entry address | Size | Bits | Type | Basic blocks |',
    '|---|---:|---:|---:|---|---:|',
    ...report.functions.slice(0, maximum_rows).map(item => '| ' + [
      item.name, '0x' + item.offset.toString(16), item.size, item.bits, item.type, item.basic_blocks,
    ].map(function_cell).join(' | ') + ' |'),
  ];
  const omitted = Math.max(0, report.functions.length - maximum_rows);
  if (omitted > 0) lines.push('', '_' + omitted + ' additional functions omitted from this Markdown view._');
  if (report.disassembly) {
    lines.push(
      '',
      '## Bounded disassembly',
      '',
      '- **Function:** ' + function_cell(report.disassembly.function_name),
      '- **Entry:** 0x' + report.disassembly.address.toString(16),
      '- **Instruction limit:** ' + report.disassembly.instruction_limit,
      '- **Limit reached:** ' + (report.disassembly.instruction_limit_reached ? 'yes' : 'no'),
      '',
      '~~~asm',
      ...report.disassembly.instructions.map(item =>
        '0x' + item.offset.toString(16) + '  ' +
        function_cell(item.bytes ?? '') + '  ' +
        function_cell(item.disassembly ?? item.opcode ?? ''),
      ),
      '~~~',
    );
  }
  lines.push(
    '',
    '## Analysis boundaries',
    '',
    '- Rizin automatic analysis is heuristic and may miss or misclassify functions.',
    '- The optional instruction view is disassembly, not reconstructed source or proof of behavior.',
    '- The target is not executed. The external Rizin process is time/output bounded, not OS-sandboxed.',
    '',
  );
  return lines.join('\n');
}
