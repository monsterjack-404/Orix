// JavaScript, src/project/architecture.mjs, Node.js 20+, static source-graph diagnostics.
// Consumes ORIX project-intelligence reports; never executes project code.

const DEFAULT_MAX_NODES = 20000;
const DEFAULT_MAX_EDGES = 100000;
const DEFAULT_MAX_HOTSPOTS = 25;
const ENTRYPOINT_NAMES = new Set([
  'index', 'main', 'app', 'server', 'cli', 'start', 'bootstrap',
  'program', '__main__', 'application',
]);

function bounded_limit(options, key, fallback, maximum) {
  const value = options[key] ?? fallback;
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(key + ' must be an integer between 1 and ' + maximum);
  }
  return value;
}

function safe_relative_path(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096) return false;
  if (value.startsWith('/') || value.includes('\\') || /^[A-Za-z]:/.test(value)) return false;
  if (/[\u0000-\u001f\u007f]/.test(value)) return false;
  return value.split('/').every(part => part.length > 0 && part !== '.' && part !== '..');
}

function basename_without_extension(value) {
  const base = value.slice(value.lastIndexOf('/') + 1);
  const index = base.lastIndexOf('.');
  return (index > 0 ? base.slice(0, index) : base).toLowerCase();
}

function strongly_connected_components(ids, outgoing, incoming) {
  const visited = new Set();
  const finish_order = [];
  for (const start of ids) {
    if (visited.has(start)) continue;
    visited.add(start);
    const stack = [{ id: start, next: 0 }];
    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      const neighbors = outgoing.get(frame.id) ?? [];
      if (frame.next < neighbors.length) {
        const next = neighbors[frame.next];
        frame.next += 1;
        if (!visited.has(next)) {
          visited.add(next);
          stack.push({ id: next, next: 0 });
        }
      } else {
        finish_order.push(frame.id);
        stack.pop();
      }
    }
  }

  const assigned = new Set();
  const components = [];
  for (let index = finish_order.length - 1; index >= 0; index -= 1) {
    const start = finish_order[index];
    if (assigned.has(start)) continue;
    const members = [];
    const stack = [start];
    assigned.add(start);
    while (stack.length > 0) {
      const current = stack.pop();
      members.push(current);
      for (const next of incoming.get(current) ?? []) {
        if (!assigned.has(next)) {
          assigned.add(next);
          stack.push(next);
        }
      }
    }
    members.sort((a, b) => a.localeCompare(b));
    components.push(members);
  }
  return components.sort((a, b) => a[0].localeCompare(b[0]));
}

function reachable_from(roots, outgoing) {
  const visited = new Set();
  const queue = [...roots].sort((a, b) => a.localeCompare(b));
  for (const root of queue) visited.add(root);
  for (let index = 0; index < queue.length; index += 1) {
    for (const next of outgoing.get(queue[index]) ?? []) {
      if (!visited.has(next)) {
        visited.add(next);
        queue.push(next);
      }
    }
  }
  return visited;
}

function collect_external_imports(files, maximum = 200) {
  const imports = new Map();
  for (const file of files) {
    for (const item of Array.isArray(file?.imports) ? file.imports : []) {
      const specifier = typeof item === 'string' ? item : item?.specifier;
      if (typeof specifier !== 'string' || !specifier || specifier.startsWith('.') ||
          specifier.startsWith('/') || specifier.startsWith('node:') || /^[A-Za-z]:/.test(specifier)) continue;
      const entry = imports.get(specifier) ?? { specifier, import_count: 0, used_by: [] };
      entry.import_count += 1;
      if (entry.used_by.length < 10 && !entry.used_by.includes(file.path)) entry.used_by.push(file.path);
      imports.set(specifier, entry);
    }
  }
  return [...imports.values()]
    .sort((a, b) => b.import_count - a.import_count || a.specifier.localeCompare(b.specifier))
    .slice(0, maximum)
    .map(item => ({ ...item, used_by: item.used_by.sort((a, b) => a.localeCompare(b)) }));
}

/**
 * Analyze an ORIX project report's resolved local source-import graph.
 * Findings are static graph heuristics, not proof of runtime behavior.
 */
export function analyze_project_architecture(project_report, options = {}) {
  if (!project_report || project_report.schema_version !== 'orix.project.v1' ||
      !Array.isArray(project_report.files) || !project_report.graph ||
      !Array.isArray(project_report.graph.nodes) || !Array.isArray(project_report.graph.edges)) {
    throw new TypeError('Architecture analysis requires an orix.project.v1 report with graph, files, and edges');
  }

  const max_nodes = bounded_limit(options, 'max_nodes', DEFAULT_MAX_NODES, 50000);
  const max_edges = bounded_limit(options, 'max_edges', DEFAULT_MAX_EDGES, 250000);
  const max_hotspots = bounded_limit(options, 'max_hotspots', DEFAULT_MAX_HOTSPOTS, 100);
  const warnings = [];
  const file_by_path = new Map(project_report.files
    .filter(file => file && typeof file.path === 'string')
    .map(file => [file.path, file]));
  const raw_nodes = [...project_report.graph.nodes]
    .filter(item => item && safe_relative_path(item.id))
    .sort((a, b) => a.id.localeCompare(b.id));

  const nodes = [];
  const node_by_id = new Map();
  let invalid_nodes = project_report.graph.nodes.length - raw_nodes.length;
  for (const item of raw_nodes) {
    if (node_by_id.has(item.id)) {
      invalid_nodes += 1;
      continue;
    }
    if (nodes.length >= max_nodes) break;
    const file = file_by_path.get(item.id);
    const node = { id: item.id, path: item.id, language: item.language ?? file?.language ?? 'Unknown' };
    nodes.push(node);
    node_by_id.set(node.id, node);
  }
  const omitted_nodes = Math.max(0, raw_nodes.length - node_by_id.size);
  if (invalid_nodes > 0) warnings.push('Ignored ' + invalid_nodes + ' invalid or duplicate graph node(s).');
  if (omitted_nodes > 0) warnings.push('Node limit reached; ' + omitted_nodes + ' graph node(s) were not analyzed.');

  const retained_input_ids = new Set(raw_nodes.map(item => item.id));
  const outgoing_sets = new Map(nodes.map(node => [node.id, new Set()]));
  const incoming_sets = new Map(nodes.map(node => [node.id, new Set()]));
  const accepted_edges = [];
  let invalid_edges = 0;
  let duplicate_edges = 0;
  let omitted_edges = 0;
  const raw_edges = [...project_report.graph.edges]
    .sort((a, b) => String(a?.from).localeCompare(String(b?.from)) ||
      String(a?.to).localeCompare(String(b?.to)) ||
      String(a?.label ?? '').localeCompare(String(b?.label ?? '')));

  for (let edge_index = 0; edge_index < raw_edges.length; edge_index += 1) {
    const edge = raw_edges[edge_index];
    if (!edge || !retained_input_ids.has(edge.from) || !retained_input_ids.has(edge.to)) {
      invalid_edges += 1;
      continue;
    }
    if (!node_by_id.has(edge.from) || !node_by_id.has(edge.to)) {
      omitted_edges += 1;
      continue;
    }
    const from = edge.from;
    const to = edge.to;
    if (outgoing_sets.get(from).has(to)) {
      duplicate_edges += 1;
      continue;
    }
    if (accepted_edges.length >= max_edges) {
      omitted_edges += raw_edges.length - edge_index;
      break;
    }
    outgoing_sets.get(from).add(to);
    incoming_sets.get(to).add(from);
    accepted_edges.push({
      from,
      to,
      kind: typeof edge.kind === 'string' ? edge.kind : 'source-import',
      label: typeof edge.label === 'string' ? edge.label.slice(0, 512) : '',
    });
  }
  if (invalid_edges > 0) warnings.push('Ignored ' + invalid_edges + ' edge(s) whose endpoints were not retained.');
  if (omitted_edges > 0) warnings.push('Edge limit reached; ' + omitted_edges + ' graph edge(s) were not analyzed.');

  const outgoing = new Map();
  const incoming = new Map();
  for (const node of nodes) {
    outgoing.set(node.id, [...outgoing_sets.get(node.id)].sort((a, b) => a.localeCompare(b)));
    incoming.set(node.id, [...incoming_sets.get(node.id)].sort((a, b) => a.localeCompare(b)));
  }

  const entrypoint_candidates = [];
  const roots = [];
  const isolated_files = [];
  const leaf_modules = [];
  const modules = nodes.map(node => {
    const in_degree = incoming.get(node.id).length;
    const out_degree = outgoing.get(node.id).length;
    const common_name = ENTRYPOINT_NAMES.has(basename_without_extension(node.path));
    let role = 'module';
    if (in_degree === 0 && out_degree === 0) {
      role = 'isolated';
      isolated_files.push(node.path);
    } else if (in_degree === 0 && out_degree > 0) {
      role = 'entrypoint-candidate';
      roots.push(node.id);
      entrypoint_candidates.push({
        path: node.path,
        language: node.language,
        confidence: common_name ? 'strong-heuristic' : 'heuristic',
        reasons: common_name
          ? ['no-incoming-local-imports', 'recognized-entrypoint-filename']
          : ['no-incoming-local-imports'],
      });
    } else if (out_degree === 0) {
      role = 'leaf';
      leaf_modules.push(node.path);
    }
    return {
      id: node.id, path: node.path, language: node.language,
      in_degree, out_degree, connectivity_score: in_degree + out_degree, role,
    };
  });

  const components = strongly_connected_components(nodes.map(item => item.id), outgoing, incoming);
  const component_by_node = new Map();
  for (let component_index = 0; component_index < components.length; component_index += 1) {
    for (const member of components[component_index]) component_by_node.set(member, component_index);
  }
  // Count intra-component edges in one pass. Filtering the full edge list once
  // per component becomes quadratic on repositories with many small cycles.
  const internal_edge_counts = new Map();
  for (const edge of accepted_edges) {
    const from_component = component_by_node.get(edge.from);
    if (from_component !== undefined && from_component === component_by_node.get(edge.to)) {
      internal_edge_counts.set(from_component, (internal_edge_counts.get(from_component) ?? 0) + 1);
    }
  }
  const cycles = [];
  for (let component_index = 0; component_index < components.length; component_index += 1) {
    const members = components[component_index];
    const self_loop = members.length === 1 && outgoing.get(members[0]).includes(members[0]);
    if (members.length < 2 && !self_loop) continue;
    cycles.push({
      id: 'cycle-' + String(cycles.length + 1).padStart(4, '0'),
      members, member_count: members.length,
      internal_edge_count: internal_edge_counts.get(component_index) ?? 0,
      kind: self_loop ? 'self-loop' : 'strongly-connected-component',
    });
  }

  const reachable = roots.length > 0 ? reachable_from(roots, outgoing) : new Set();
  const unreachable_from_candidates = roots.length > 0
    ? nodes.map(node => node.id).filter(id => !reachable.has(id)).sort((a, b) => a.localeCompare(b))
    : [];
  const hotspots = [...modules]
    .sort((a, b) => b.connectivity_score - a.connectivity_score ||
      b.in_degree - a.in_degree || a.path.localeCompare(b.path))
    .slice(0, max_hotspots)
    .map(({ path, language, in_degree, out_degree, connectivity_score }) => ({
      path, language, in_degree, out_degree, connectivity_score,
    }));

  const language_counts = {};
  const directory_counts = {};
  for (const node of nodes) {
    language_counts[node.language] = (language_counts[node.language] ?? 0) + 1;
    const slash = node.path.lastIndexOf('/');
    const directory = slash < 0 ? '(root)' : node.path.slice(0, slash);
    directory_counts[directory] = (directory_counts[directory] ?? 0) + 1;
  }
  const external_imports = collect_external_imports(project_report.files);

  return {
    schema_version: 'orix.architecture.v1',
    project: {
      name: project_report.project?.name ?? 'unknown',
      root: project_report.project?.root ?? null,
      scanned_at: project_report.project?.scanned_at ?? null,
    },
    summary: {
      source_files: nodes.length,
      source_import_edges: accepted_edges.length,
      entrypoint_candidates: entrypoint_candidates.length,
      cycle_count: cycles.length,
      cycle_participants: cycles.reduce((total, item) => total + item.member_count, 0),
      isolated_files: isolated_files.length,
      leaf_modules: leaf_modules.length,
      reachable_from_candidates: roots.length > 0 ? reachable.size : null,
      unreachable_from_candidates: unreachable_from_candidates.length,
      external_import_specifiers: external_imports.length,
      declared_dependencies: project_report.summary?.declared_dependencies ?? 0,
      locked_packages: project_report.summary?.locked_packages ?? 0,
      lockfile_dependency_edges: project_report.summary?.lockfile_edges ?? 0,
    },
    coverage: {
      input_inventory_complete: project_report.coverage?.complete === true,
      graph_analysis_complete: omitted_nodes === 0 && omitted_edges === 0 && invalid_nodes === 0 && invalid_edges === 0,
      analyzed_nodes: nodes.length, omitted_nodes,
      analyzed_edges: accepted_edges.length, omitted_edges,
      invalid_nodes, invalid_edges, duplicate_edges,
      reachability_available: roots.length > 0,
      skipped_project_entries: project_report.coverage?.skipped ?? null,
    },
    entrypoint_candidates, cycles, hotspots,
    isolated_files: isolated_files.sort((a, b) => a.localeCompare(b)),
    leaf_modules: leaf_modules.sort((a, b) => a.localeCompare(b)),
    unreachable_from_candidates,
    language_counts: Object.fromEntries(Object.entries(language_counts).sort(([a], [b]) => a.localeCompare(b))),
    directory_counts: Object.fromEntries(Object.entries(directory_counts).sort(([a], [b]) => a.localeCompare(b))),
    external_imports,
    graph: {
      nodes: modules.sort((a, b) => a.path.localeCompare(b.path)),
      edges: accepted_edges.sort((a, b) => a.from.localeCompare(b.from) || a.to.localeCompare(b.to)),
    },
    limitations: [
      'Edges represent only local imports resolved by the ORIX project scanner.',
      'The scanner uses bounded language-specific text patterns, not full compiler ASTs.',
      'Dynamic imports, reflection, runtime plugin loading, generated code and conditional resolution may be absent.',
      'An entry-point candidate is a graph heuristic, not proof of the executable entry point.',
      'Unreachable files are unreachable only within the discovered local-import graph; they are not proven dead code.',
      'No project code, package script, build step, test, or external provider is executed.',
    ],
    warnings,
  };
}
