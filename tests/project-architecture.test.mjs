// JavaScript, tests/project-architecture.test.mjs, Node.js 20+, architecture graph tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze_project_architecture } from '../src/project/architecture.mjs';
import { render_architecture_markdown, render_architecture_mermaid } from '../src/reports/architecture.mjs';

function fixture() {
  const files = [
    { path: 'src/index.js', language: 'JavaScript', imports: [{ specifier: './alpha' }, { specifier: 'lodash' }] },
    { path: 'src/alpha.js', language: 'JavaScript', imports: [{ specifier: './beta' }] },
    { path: 'src/beta.js', language: 'JavaScript', imports: [{ specifier: './alpha' }] },
    { path: 'src/leaf.js', language: 'JavaScript', imports: [] },
    { path: 'unused.js', language: 'JavaScript', imports: [] },
  ];
  const nodes = files.map(file => ({ id: file.path, type: 'file', language: file.language }));
  return {
    schema_version: 'orix.project.v1',
    project: { name: 'fixture', root: '/tmp/fixture', scanned_at: '2026-01-01T00:00:00.000Z' },
    summary: { declared_dependencies: 1, locked_packages: 2, lockfile_edges: 1 },
    coverage: { complete: true, skipped: 0 },
    files,
    graph: {
      nodes,
      edges: [
        { from: 'src/index.js', to: 'src/alpha.js', kind: 'source-import', label: './alpha' },
        { from: 'src/alpha.js', to: 'src/beta.js', kind: 'source-import', label: './beta' },
        { from: 'src/beta.js', to: 'src/alpha.js', kind: 'source-import', label: './alpha' },
        { from: 'src/index.js', to: 'src/leaf.js', kind: 'source-import', label: './leaf' },
      ],
    },
  };
}

test('detects cycles, entrypoint candidates, reachability, leaves and isolated files', () => {
  const report = analyze_project_architecture(fixture());
  assert.equal(report.schema_version, 'orix.architecture.v1');
  assert.equal(report.summary.source_files, 5);
  assert.equal(report.summary.source_import_edges, 4);
  assert.equal(report.summary.cycle_count, 1);
  assert.deepEqual(report.cycles[0].members, ['src/alpha.js', 'src/beta.js']);
  assert.deepEqual(report.entrypoint_candidates.map(item => item.path), ['src/index.js']);
  assert.equal(report.summary.reachable_from_candidates, 4);
  assert.deepEqual(report.isolated_files, ['unused.js']);
  assert.deepEqual(report.leaf_modules, ['src/leaf.js']);
  assert.equal(report.external_imports[0].specifier, 'lodash');
  assert.equal(report.coverage.graph_analysis_complete, true);
});

test('rejects non-ORIX inputs and invalid resource limits', () => {
  assert.throws(() => analyze_project_architecture({}), /orix.project.v1/);
  assert.throws(() => analyze_project_architecture(fixture(), { max_nodes: 0 }), /max_nodes/);
  assert.throws(() => analyze_project_architecture(fixture(), { max_edges: 250001 }), /max_edges/);
});

test('bounds oversized graphs and ignores unsafe or dangling graph references', () => {
  const input = fixture();
  input.graph.nodes.push({ id: '../outside.js', language: 'JavaScript' });
  input.graph.edges.push({ from: 'src/index.js', to: 'missing.js' });
  const report = analyze_project_architecture(input, { max_nodes: 3 });
  assert.equal(report.coverage.omitted_nodes, 2);
  assert.equal(report.coverage.invalid_nodes, 1);
  assert.equal(report.coverage.invalid_edges, 1);
  assert.equal(report.coverage.graph_analysis_complete, false);
  assert.ok(report.warnings.length >= 2);
});

test('renders usable Markdown and a bounded Mermaid graph', () => {
  const report = analyze_project_architecture(fixture());
  const markdown = render_architecture_markdown(report);
  const mermaid = render_architecture_mermaid(report, { max_nodes: 3, max_edges: 2 });
  assert.match(markdown, /Circular dependency groups/);
  assert.match(markdown, /src\/index\.js/);
  assert.match(mermaid, /^flowchart LR/m);
  assert.match(mermaid, /Diagram bounded/);
  assert.throws(() => render_architecture_mermaid(report, { max_nodes: 501 }), /max_nodes/);
});

test('analysis is deterministic and does not mutate its input report', () => {
  const input = fixture();
  const before = JSON.stringify(input);
  const first = analyze_project_architecture(input);
  const second = analyze_project_architecture(input);
  assert.equal(JSON.stringify(first), JSON.stringify(second));
  assert.equal(JSON.stringify(input), before);
});

test('counts many independent self-loop components without losing edge attribution', () => {
  const count = 1200;
  const nodes = Array.from({ length: count }, (_, index) => ({
    id: 'src/module-' + String(index).padStart(4, '0') + '.js',
    type: 'file',
    language: 'JavaScript',
  }));
  const input = {
    schema_version: 'orix.project.v1',
    project: { name: 'cycle-scale-fixture', root: '/tmp/cycle-scale-fixture', scanned_at: null },
    summary: { declared_dependencies: 0, locked_packages: 0, lockfile_edges: 0 },
    coverage: { complete: true, skipped: 0 },
    files: nodes.map(node => ({ path: node.id, language: node.language, imports: [] })),
    graph: { nodes, edges: nodes.map(node => ({ from: node.id, to: node.id, kind: 'source-import' })) },
  };

  const report = analyze_project_architecture(input);
  assert.equal(report.summary.cycle_count, count);
  assert.equal(report.summary.cycle_participants, count);
  assert.ok(report.cycles.every(cycle =>
    cycle.kind === 'self-loop' && cycle.member_count === 1 && cycle.internal_edge_count === 1
  ));
});
