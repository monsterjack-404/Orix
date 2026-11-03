// JavaScript, tests/mcp.test.mjs, Node.js 20+, MCP protocol and ORIX tool integration tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { handle_mcp_message, ORIX_MCP_TOOLS, call_orix_tool, start_mcp_server } from '../src/mcp/server.mjs';
import { append_ledger } from '../src/evidence/ledger.mjs';

test('MCP initialize negotiates protocol and advertises tool capability', async () => {
  const response = await handle_mcp_message({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } });
  assert.equal(response.result.protocolVersion, '2025-03-26');
  assert.ok(response.result.capabilities.tools);
  assert.equal(response.result.serverInfo.name, 'orix');
});

test('MCP tools/list exposes the complete local ORIX tool surface', async () => {
  const response = await handle_mcp_message({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.deepEqual(response.result.tools.map(tool => tool.name), ORIX_MCP_TOOLS.map(tool => tool.name));
  assert.ok(response.result.tools.some(tool => tool.name === 'orix.inspect_file'));
  assert.ok(response.result.tools.some(tool => tool.name === 'orix.analyze_architecture'));
  assert.ok(response.result.tools.some(tool => tool.name === 'orix.ledger.verify'));
});

test('MCP inspect tool returns the same versioned artifact report as the library API', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-mcp-'));
  try {
    const file = path.join(directory, 'sample.bin');
    await writeFile(file, Buffer.from('MCP static analysis fixture'));
    const response = await handle_mcp_message({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'orix.inspect_file', arguments: { path: file } } }, { roots: [directory] });
    assert.equal(response.result.isError, false);
    const report = JSON.parse(response.result.content[0].text);
    assert.equal(report.schema_version, 'orix.artifact.v1');
    assert.equal(report.integrity.digest.length, 64);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('MCP maps tool errors to isError and unknown methods to JSON-RPC errors', async () => {
  const bad = await handle_mcp_message({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'orix.inspect_file', arguments: { path: '' } } });
  assert.equal(bad.result.isError, true);
  const unknown_tool = await handle_mcp_message({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'orix.not_a_tool', arguments: {} } });
  assert.equal(unknown_tool.result.isError, true);
  const unknown = await handle_mcp_message({ jsonrpc: '2.0', id: 5, method: 'unknown/method' });
  assert.equal(unknown.error.code, -32601);
  assert.equal(await handle_mcp_message({ jsonrpc: '2.0', method: 'notifications/initialized' }), null);
});

test('MCP direct tool invocation validates argument objects', async () => {
  await assert.rejects(call_orix_tool('orix.formats', null), /Tool arguments/);
  await assert.rejects(call_orix_tool('orix.formats', []), /Tool arguments/);
});


test('MCP server enforces advertised argument schemas', async () => {
  await assert.rejects(call_orix_tool('orix.formats', { unexpected: true }), /Unknown tool argument/);
  await assert.rejects(call_orix_tool('orix.inspect_file', { path: 'x', max_strings: -1 }), /between/);
  await assert.rejects(call_orix_tool('orix.inspect_file', {}), /Missing required/);
});

test('MCP stdio transport reads and writes newline-delimited JSON-RPC messages', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  let captured = '';
  output.setEncoding('utf8');
  output.on('data', chunk => { captured += chunk; });
  const running = start_mcp_server({ input, output, error_output: errors });
  input.write(JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'ping' }) + '\n');
  input.write(JSON.stringify({ jsonrpc: '2.0', id: 11, method: 'tools/list' }) + '\n');
  input.end();
  await running;
  const messages = captured.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(messages.length, 2);
  assert.deepEqual(messages[0].result, {});
  assert.equal(messages[1].result.tools.length, ORIX_MCP_TOOLS.length);
});


test('MCP comparison tool reads bounded reports and returns artifact deltas', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-mcp-compare-'));
  try {
    const baseline_path = path.join(directory, 'baseline.json');
    const current_path = path.join(directory, 'current.json');
    const baseline = {
      schema_version: 'orix.artifact.v1',
      artifact: { path: path.join(directory, 'sample.bin') },
      integrity: { digest: 'a'.repeat(64) },
      detection: { format: 'Unknown' },
      indicators: [],
    };
    const current = structuredClone(baseline);
    current.integrity.digest = 'b'.repeat(64);
    await writeFile(baseline_path, JSON.stringify(baseline));
    await writeFile(current_path, JSON.stringify(current));
    const response = await handle_mcp_message({
      jsonrpc: '2.0', id: 20, method: 'tools/call',
      params: { name: 'orix.compare_reports', arguments: { baseline_path, current_path } },
    }, { roots: [directory] });
    assert.equal(response.result.isError, false);
    const comparison = JSON.parse(response.result.content[0].text);
    assert.equal(comparison.schema_version, 'orix.comparison.v1');
    assert.equal(comparison.comparison.modified, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('MCP comparison tool rejects unsupported report shapes', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-mcp-compare-invalid-'));
  try {
    const baseline_path = path.join(directory, 'baseline.json');
    const current_path = path.join(directory, 'current.json');
    await writeFile(baseline_path, JSON.stringify({ schema_version: 'orix.unknown.v1' }));
    await writeFile(current_path, JSON.stringify({ schema_version: 'orix.unknown.v1' }));
    const response = await handle_mcp_message({
      jsonrpc: '2.0', id: 21, method: 'tools/call',
      params: { name: 'orix.compare_reports', arguments: { baseline_path, current_path } },
    }, { roots: [directory] });
    assert.equal(response.result.isError, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});


test('MCP directory and project tools reuse bounded ORIX analysis services', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-mcp-scan-'));
  try {
    await writeFile(path.join(directory, 'package.json'), JSON.stringify({ name: 'fixture', version: '1.0.0' }));
    await writeFile(path.join(directory, 'index.js'), 'export function run() { return 7; }');
    const scan = await call_orix_tool('orix.scan_directory', { path: directory, max_files: 20, concurrency: 1 }, { roots: [directory] });
    assert.equal(scan.schema_version, 'orix.scan.v1');
    assert.equal(scan.scan.files_analyzed, 2);
    const project = await call_orix_tool('orix.scan_project', { path: directory, max_files: 20 }, { roots: [directory] });
    assert.equal(project.schema_version, 'orix.project.v1');
    assert.ok(project.inventory || project.files || project.summary);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('MCP ledger tools verify and list existing evidence without write access', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-mcp-ledger-'));
  try {
    const ledger_path = path.join(directory, 'evidence.jsonl');
    await append_ledger(ledger_path, { type: 'test.completed', payload: { safe: true } });
    const verified = await call_orix_tool('orix.ledger.verify', { path: ledger_path }, { roots: [directory] });
    const listed = await call_orix_tool('orix.ledger.list', { path: ledger_path }, { roots: [directory] });
    assert.equal(verified.valid, true);
    assert.equal(verified.records_verified, 1);
    assert.equal(listed.records.length, 1);
    assert.equal(listed.records[0].type, 'test.completed');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});


test('MCP confines artifact access to configured roots and rejects symlinks', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'orix-mcp-root-'));
  const outside = await mkdtemp(path.join(tmpdir(), 'orix-mcp-outside-'));
  try {
    const file = path.join(root, 'inside.bin');
    const external = path.join(outside, 'outside.bin');
    await writeFile(file, 'inside');
    await writeFile(external, 'outside');
    const link = path.join(root, 'linked.bin');
    const { symlink } = await import('node:fs/promises');
    await symlink(file, link);
    const denied = await handle_mcp_message({ jsonrpc: '2.0', id: 30, method: 'tools/call', params: { name: 'orix.inspect_file', arguments: { path: external } } }, { roots: [root] });
    assert.equal(denied.result.isError, true);
    assert.match(denied.result.content[0].text, /ORIX_MCP_PATH_OUTSIDE_WORKSPACE/);
    const linked = await handle_mcp_message({ jsonrpc: '2.0', id: 31, method: 'tools/call', params: { name: 'orix.inspect_file', arguments: { path: link } } }, { roots: [root] });
    assert.equal(linked.result.isError, true);
    assert.match(linked.result.content[0].text, /ORIX_MCP_SYMLINK_REJECTED/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('MCP exposes an explicit append operation for hash-chained evidence', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-mcp-ledger-'));
  try {
    const { mkdir } = await import('node:fs/promises');
    await mkdir(path.join(directory, '.orix'));
    const ledger = path.join(directory, '.orix', 'evidence.jsonl');
    const response = await handle_mcp_message({ jsonrpc: '2.0', id: 40, method: 'tools/call', params: { name: 'orix.ledger.append', arguments: { path: ledger, type: 'analysis.completed', payload: { artifacts: 2 } } } }, { roots: [directory] });
    assert.equal(response.result.isError, false);
    const receipt = JSON.parse(response.result.content[0].text);
    assert.equal(receipt.sequence, 1);
    const verified = await handle_mcp_message({ jsonrpc: '2.0', id: 41, method: 'tools/call', params: { name: 'orix.ledger.verify', arguments: { path: ledger } } }, { roots: [directory] });
    assert.equal(verified.result.isError, false);
    assert.match(verified.result.content[0].text, /"valid":true/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});


test('MCP transport discards oversized frames and continues with the next request', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  let captured = '';
  let diagnostics = '';
  output.setEncoding('utf8');
  errors.setEncoding('utf8');
  output.on('data', chunk => { captured += chunk; });
  errors.on('data', chunk => { diagnostics += chunk; });
  const running = start_mcp_server({ input, output, error_output: errors });
  input.write('x'.repeat(4 * 1024 * 1024 + 1) + '\n');
  input.write(JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'ping' }) + '\n');
  input.end();
  await running;
  const messages = captured.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(messages.length, 1);
  assert.equal(messages[0].id, 99);
  assert.match(diagnostics, /input line exceeded/);
});


test('MCP ledger event schema matches accepted underscore and minimum-length names', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-mcp-event-schema-'));
  try {
    const ledger_path = path.join(directory, 'events.jsonl');
    const accepted = await handle_mcp_message({
      jsonrpc: '2.0', id: 51, method: 'tools/call',
      params: { name: 'orix.ledger.append', arguments: { path: ledger_path, type: 'analysis_started', payload: {} } },
    }, { roots: [directory] });
    assert.equal(accepted.result.isError, false);
    const rejected = await handle_mcp_message({
      jsonrpc: '2.0', id: 52, method: 'tools/call',
      params: { name: 'orix.ledger.append', arguments: { path: ledger_path, type: 'a', payload: {} } },
    }, { roots: [directory] });
    assert.equal(rejected.result.isError, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});


test('MCP returns JSON-RPC invalid-request errors for malformed notification objects', async () => {
  const response = await handle_mcp_message({ jsonrpc: '2.0', params: {} });
  assert.equal(response.jsonrpc, '2.0');
  assert.equal(response.id, null);
  assert.equal(response.error.code, -32600);
});

test('MCP rejects malformed UTF-8 frames and continues with the next request', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  let captured = '';
  output.setEncoding('utf8');
  output.on('data', chunk => { captured += chunk; });
  const running = start_mcp_server({ input, output, error_output: errors });
  input.write(Buffer.concat([
    Buffer.from([0xc3, 0x28, 0x0a]),
    Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 71, method: 'ping' }) + '\n'),
  ]));
  input.end();
  await running;
  const messages = captured.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(messages.length, 2);
  assert.equal(messages[0].error.code, -32700);
  assert.equal(messages[1].id, 71);
  assert.deepEqual(messages[1].result, {});
});

test('MCP architecture analysis reuses the bounded scanner and reports local cycles', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-mcp-architecture-'));
  try {
    await writeFile(path.join(directory, 'index.js'), "import './service.js';\n");
    await writeFile(path.join(directory, 'service.js'), "import './index.js';\n");
    await writeFile(path.join(directory, 'isolated.js'), 'export const isolated = true;\n');

    const report = await call_orix_tool('orix.analyze_architecture', {
      path: directory,
      max_files: 100,
      max_nodes: 100,
      max_edges: 100,
      max_hotspots: 10,
    }, { roots: [directory] });

    assert.equal(report.schema_version, 'orix.architecture.v1');
    assert.equal(report.summary.source_files, 3);
    assert.equal(report.summary.cycle_count, 1);
    assert.deepEqual(report.cycles[0].members, ['index.js', 'service.js']);
    assert.deepEqual(report.isolated_files, ['isolated.js']);
    assert.equal(report.coverage.input_inventory_complete, true);

    const default_report = await call_orix_tool(
      'orix.analyze_architecture',
      { path: directory },
      { roots: [directory] },
    );
    assert.equal(default_report.schema_version, 'orix.architecture.v1');
    assert.equal(default_report.summary.cycle_count, 1);

    await assert.rejects(
      call_orix_tool('orix.analyze_architecture', { path: directory, max_nodes: 50001 }, { roots: [directory] }),
      /between 1 and 50000/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
