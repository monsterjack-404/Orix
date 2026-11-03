// JavaScript, src/reports/architecture.mjs, Node.js 20+, architecture report renderers.

function validate_report(report) {
  if (report?.schema_version !== 'orix.architecture.v1' || !report.summary ||
      !Array.isArray(report.graph?.nodes) || !Array.isArray(report.graph?.edges)) {
    throw new TypeError('Expected an ORIX architecture analysis report');
  }
}

function cell(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/\|/g, '\\|')
    .replace(/[\r\n]+/g, ' ')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function mermaid_label(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/[<>{}\[\]]/g, ' ')
    .replace(/[|;]/g, ' ')
    .replace(/[\r\n]+/g, ' ')
    .slice(0, 160);
}

export function render_architecture_markdown(report) {
  validate_report(report);
  const s = report.summary;
  const lines = [
    '# ORIX Project Architecture Analysis', '',
    '- **Project:** ' + cell(report.project?.name),
    '- **Root:** ' + cell(report.project?.root),
    '- **Input inventory complete:** ' + String(report.coverage.input_inventory_complete),
    '- **Graph analysis complete:** ' + String(report.coverage.graph_analysis_complete),
    '', '## Architecture summary', '',
    '| Metric | Result |', '|---|---:|',
    '| Source files in graph | ' + s.source_files + ' |',
    '| Resolved local import edges | ' + s.source_import_edges + ' |',
    '| Entry-point candidates | ' + s.entrypoint_candidates + ' |',
    '| Circular dependency groups | ' + s.cycle_count + ' |',
    '| Files participating in cycles | ' + s.cycle_participants + ' |',
    '| Isolated files | ' + s.isolated_files + ' |',
    '| Leaf modules | ' + s.leaf_modules + ' |',
    '| Reachable from candidates | ' + (s.reachable_from_candidates ?? 'not available') + ' |',
    '| External import specifiers observed | ' + s.external_import_specifiers + ' |',
    '| Locked packages | ' + s.locked_packages + ' |',
    '', '## Entry-point candidates', '',
  ];
  if (report.entrypoint_candidates.length === 0) lines.push('No source-graph root candidate was identified.');
  else {
    lines.push('| File | Language | Heuristic confidence | Reasons |', '|---|---|---|---|');
    for (const item of report.entrypoint_candidates) {
      lines.push('| ' + cell(item.path) + ' | ' + cell(item.language) + ' | ' +
        cell(item.confidence) + ' | ' + cell(item.reasons.join(', ')) + ' |');
    }
  }
  lines.push('', '## Circular dependency groups', '');
  if (report.cycles.length === 0) lines.push('No cycle was found in the discovered local-import graph.');
  else {
    for (const cycle of report.cycles) {
      lines.push('### ' + cycle.id + ' (' + cycle.member_count + ' files)', '');
      for (const member of cycle.members) lines.push('- ' + cell(member));
      lines.push('');
    }
  }
  lines.push('## Highest-connectivity modules', '');
  if (report.hotspots.length === 0) lines.push('No module records are available.');
  else {
    lines.push('| File | Language | Imported by | Imports | Score |', '|---|---|---:|---:|---:|');
    for (const item of report.hotspots) {
      lines.push('| ' + cell(item.path) + ' | ' + cell(item.language) + ' | ' +
        item.in_degree + ' | ' + item.out_degree + ' | ' + item.connectivity_score + ' |');
    }
  }
  lines.push('', '## External import specifiers observed', '');
  if (report.external_imports.length === 0) lines.push('No non-relative import specifiers were recorded.');
  else {
    lines.push('| Specifier | Import count | Example files |', '|---|---:|---|');
    for (const item of report.external_imports) {
      lines.push('| ' + cell(item.specifier) + ' | ' + item.import_count + ' | ' +
        cell(item.used_by.join(', ')) + ' |');
    }
  }
  lines.push('', '## Coverage and limitations', '');
  lines.push('- Analyzed nodes: ' + report.coverage.analyzed_nodes + '; omitted nodes: ' + report.coverage.omitted_nodes + '.');
  lines.push('- Analyzed edges: ' + report.coverage.analyzed_edges + '; omitted edges: ' + report.coverage.omitted_edges + '.');
  for (const item of report.limitations) lines.push('- ' + item);
  if (report.warnings.length > 0) {
    lines.push('', '## Warnings', '');
    for (const warning of report.warnings) lines.push('- ' + cell(warning));
  }
  return lines.join('\n') + '\n';
}

export function render_architecture_mermaid(report, options = {}) {
  validate_report(report);
  const max_nodes = options.max_nodes ?? 120;
  const max_edges = options.max_edges ?? 300;
  if (!Number.isSafeInteger(max_nodes) || max_nodes < 1 || max_nodes > 500) {
    throw new TypeError('max_nodes must be between 1 and 500');
  }
  if (!Number.isSafeInteger(max_edges) || max_edges < 1 || max_edges > 2000) {
    throw new TypeError('max_edges must be between 1 and 2000');
  }
  const selected = [...report.graph.nodes]
    .sort((a, b) => b.connectivity_score - a.connectivity_score || a.path.localeCompare(b.path))
    .slice(0, max_nodes)
    .sort((a, b) => a.path.localeCompare(b.path));
  const selected_ids = new Set(selected.map(item => item.id));
  const id_map = new Map(selected.map((item, index) => [item.id, 'n' + index]));
  const edges = report.graph.edges
    .filter(edge => selected_ids.has(edge.from) && selected_ids.has(edge.to))
    .slice(0, max_edges);
  const lines = ['flowchart LR'];
  for (const item of selected) {
    const label = mermaid_label(item.path + ' (' + item.language + ')');
    lines.push('  ' + id_map.get(item.id) + '["' + label + '"]');
  }
  for (const edge of edges) {
    const label = edge.label ? '|"' + mermaid_label(edge.label) + '"|' : '';
    lines.push('  ' + id_map.get(edge.from) + ' -->' + label + ' ' + id_map.get(edge.to));
  }
  const omitted_nodes = Math.max(0, report.graph.nodes.length - selected.length);
  const omitted_edges = Math.max(0, report.graph.edges.length - edges.length);
  if (omitted_nodes || omitted_edges) {
    lines.push('  %% Diagram bounded: omitted ' + omitted_nodes + ' node(s) and ' + omitted_edges + ' edge(s).');
  }
  return lines.join('\n') + '\n';
}
