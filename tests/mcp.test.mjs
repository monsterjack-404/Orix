// JavaScript, tests/mcp.test.mjs, Node.js 20+, MCP protocol and ORIX tool integration tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PassThrough } from 'node:stream';
import { handle_mcp_message, ORIX_MCP_TOOLS, call_orix_tool, start_mcp_server } from '../src/mcp/server.mjs';
import { inspect_file } from '../src/core/inspect.mjs';
import { append_ledger, verify_ledger } from '../src/evidence/ledger.mjs';

test('MCP case tools create, mutate, verify, export and import a workspace-confined case', async t => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'orix-mcp-case-'));
  const imported_workspace = await mkdtemp(path.join(tmpdir(), 'orix-mcp-case-import-'));
  t.after(async () => { await rm(workspace, { recursive: true, force: true }); await rm(imported_workspace, { recursive: true, force: true }); });
  const created = await call_orix_tool('orix.case.create', { workspace, title: 'MCP case', description: 'Workspace test' }, { roots: [workspace] });
  assert.equal(created.schema_version, 'orix.case.v1');
  const note = await call_orix_tool('orix.case.mutate', { workspace, case_id: created.case.id, action: 'add_note', text: 'Review the sample' }, { roots: [workspace] });
  assert.ok(note.note.note_id);
  const shown = await call_orix_tool('orix.case.get', { workspace, case_id: created.case.id, action: 'show' }, { roots: [workspace] });
  assert.equal(shown.notes.length, 1);
  const verified = await call_orix_tool('orix.case.get', { workspace, case_id: created.case.id, action: 'verify' }, { roots: [workspace] });
  assert.equal(verified.valid, true);
  const bundle = path.join(workspace, 'case-bundle');
  const exported = await call_orix_tool('orix.case.exchange', { workspace, case_id: created.case.id, action: 'export', path: bundle }, { roots: [workspace] });
  assert.equal(exported.signed, false);
  const imported = await call_orix_tool('orix.case.exchange', { workspace: imported_workspace, action: 'import', path: bundle }, { roots: [workspace, imported_workspace] });
  assert.equal(imported.case_id, created.case.id);
  const listed = await call_orix_tool('orix.case.get', { workspace: imported_workspace, action: 'list' }, { roots: [workspace, imported_workspace] });
  assert.equal(listed.cases.length, 1);
});

test('MCP case workspace access remains confined to configured roots', async () => {
  const allowed = await mkdtemp(path.join(tmpdir(), 'orix-mcp-case-root-'));
  const denied = await mkdtemp(path.join(tmpdir(), 'orix-mcp-case-outside-'));
  try {
    await assert.rejects(call_orix_tool('orix.case.create', { workspace: denied, title: 'Denied' }, { roots: [allowed] }), error => error.code === 'ORIX_MCP_PATH_OUTSIDE_WORKSPACE');
  } finally {
    await rm(allowed, { recursive: true, force: true });
    await rm(denied, { recursive: true, force: true });
  }
});

test('MCP initialize negotiates protocol and advertises tool capability', async () => {
  const response = await handle_mcp_message({
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'orix-test-client', version: '1.0.0' },
    },
  });
  assert.equal(response.result.protocolVersion, '2025-03-26');
  assert.ok(response.result.capabilities.tools);
  assert.equal(response.result.serverInfo.name, 'orix');
});

test('MCP initialization negotiates the server-supported version when the client requests an unknown version', async () => {
  const response = await handle_mcp_message({
    jsonrpc: '2.0',
    id: 'init-2',
    method: 'initialize',
    params: {
      protocolVersion: '2099-01-01',
      capabilities: {},
      clientInfo: { name: 'future-client', version: '9.9.9' },
    },
  });
  assert.equal(response.result.protocolVersion, '2025-03-26');
});

test('MCP rejects incomplete initialize parameters with JSON-RPC invalid-params', async () => {
  const response = await handle_mcp_message({
    jsonrpc: '2.0', id: 3, method: 'initialize',
    params: { protocolVersion: '2025-03-26' },
  });
  assert.equal(response.error.code, -32602);
});

test('MCP exposes only the capability families it actually implements', async () => {
  const initialized = await handle_mcp_message({
    jsonrpc: '2.0', id: 70, method: 'initialize',
    params: {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'capability-test-client', version: '1.0.0' },
    },
  });
  assert.deepEqual(Object.keys(initialized.result.capabilities), ['tools']);
  for (const method of ['resources/list', 'prompts/list']) {
    const unsupported = await handle_mcp_message({ jsonrpc: '2.0', id: 71, method });
    assert.equal(unsupported.error.code, -32601);
  }
});

test('MCP tools/list exposes the complete local ORIX tool surface', async () => {
  const response = await handle_mcp_message({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.deepEqual(response.result.tools.map(tool => tool.name), ORIX_MCP_TOOLS.map(tool => tool.name));
  assert.ok(response.result.tools.some(tool => tool.name === 'orix.inspect_file'));
  assert.ok(response.result.tools.some(tool => tool.name === 'orix.rizin_functions'));
  assert.ok(response.result.tools.some(tool => tool.name === 'orix.analyze_architecture'));
  assert.ok(response.result.tools.some(tool => tool.name === 'orix.analyze_har'));
  assert.ok(response.result.tools.some(tool => tool.name === 'orix.capabilities'));
  assert.ok(response.result.tools.some(tool => tool.name === 'orix.ledger.verify'));
  assert.ok(response.result.tools.some(tool => tool.name === 'orix.case.create'));
  assert.ok(response.result.tools.some(tool => tool.name === 'orix.case.mutate'));
  assert.ok(response.result.tools.some(tool => tool.name === 'orix.case.exchange'));
  for (const tool of response.result.tools) {
    assert.ok(tool.annotations, tool.name + ' must advertise safety annotations');
    assert.equal(tool.annotations.openWorldHint, false);
  }
  assert.equal(response.result.tools.find(tool => tool.name === 'orix.inspect_file').annotations.readOnlyHint, true);
  assert.equal(response.result.tools.find(tool => tool.name === 'orix.rizin_functions').annotations.readOnlyHint, true);
  assert.equal(response.result.tools.find(tool => tool.name === 'orix.ledger.append').annotations.readOnlyHint, false);
  assert.equal(response.result.tools.find(tool => tool.name === 'orix.ledger.append').annotations.idempotentHint, false);
});

test('MCP Rizin tool validates executable argument prefixes before resolving workspace paths', async () => {
  await assert.rejects(
    call_orix_tool('orix.rizin_functions', {
      path: '/not/used/sample.elf',
      executable: '/not/used/rizin',
      executable_args: 'not-an-array',
    }),
    /executable_args must be an array/,
  );
  await assert.rejects(
    call_orix_tool('orix.rizin_functions', {
      path: '/not/used/sample.elf',
      executable: '/not/used/rizin',
      executable_args: Array.from({ length: 17 }, () => 'prefix'),
    }),
    /executable_args must be an array/,
  );
});

test('MCP Rizin function tool runs an explicit provider through a bounded argv prefix', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-mcp-rizin-'));
  try {
    const file = path.join(directory, 'native sample.elf');
    const config_path = path.join(directory, 'rizin-stub-config.json');
    const executable = await realpath(process.execPath);
    const executable_args = [
      fileURLToPath(new URL('./fixtures/rizin-stub.mjs', import.meta.url)),
      config_path,
    ];
    await writeFile(file, Buffer.from('MCP native fixture'));
    await writeFile(config_path, JSON.stringify({
      function_output: JSON.stringify([
        { offset: 4198400, name: 'sym.main', size: 24, bits: 64, type: 'fcn', nbbs: 2 },
      ]),
      disassembly_output: JSON.stringify([
        { offset: 4198400, size: 1, bytes: 'c3', opcode: 'ret', disasm: 'ret', type: 'ret' },
      ]),
      decompilation_output: 'int main(void) { return 0; }',
    }));
    const response = await handle_mcp_message({
      jsonrpc: '2.0', id: 510, method: 'tools/call',
      params: {
        name: 'orix.rizin_functions',
        arguments: {
          path: file, executable, executable_args,
          max_functions: 100, address: '0x401000',
          decompile: true, timeout_ms: 10000,
        },
      },
    }, { roots: [directory] });
    assert.equal(response.result.isError, false);
    const report = JSON.parse(response.result.content[0].text);
    assert.equal(report.schema_version, 'orix.rizin-functions.v1');
    assert.equal(report.functions[0].name, 'sym.main');
    assert.equal(report.disassembly.instructions[0].disassembly, 'ret');
    assert.match(report.decompilation.source, /int main/);
    assert.equal(report.artifact.stable_during_analysis, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('MCP capability tool returns the source-backed inventory including its own tool definition', async () => {
  const response = await handle_mcp_message({
    jsonrpc: '2.0', id: 91, method: 'tools/call',
    params: { name: 'orix.capabilities', arguments: {} },
  });
  assert.equal(response.result.isError, false);
  const report = JSON.parse(response.result.content[0].text);
  assert.equal(report.schema_version, 'orix.capabilities.v1');
  assert.ok(report.formats.some(item => item.format === 'PNG' && item.parser_status === 'available'));
  const mcp = report.interfaces.find(item => item.id === 'mcp.stdio');
  assert.equal(mcp.protocol_version, '2025-03-26');
  assert.ok(mcp.tools.some(tool => tool.name === 'orix.capabilities'));
  assert.equal(mcp.tools.length, ORIX_MCP_TOOLS.length);
  assert.ok(report.intelligence.some(item => item.id === 'dynamic-analysis' && item.status === 'planned'));
});

test('MCP HAR tool analyzes only workspace-confined captures and omits secret values', async () => {
  const file_path = fileURLToPath(new URL('./fixtures/network/basic.har', import.meta.url));
  const workspace = path.dirname(file_path);
  {
    const result = await call_orix_tool('orix.analyze_har', { path: file_path, max_entries: 10 }, { roots: [workspace] });
    assert.equal(result.schema_version, 'orix.har.v1');
    assert.equal(result.summary.entries_analyzed, 1);
    assert.equal(JSON.stringify(result).includes('secret-value'), false);
    await assert.rejects(
      call_orix_tool('orix.analyze_har', { path: path.resolve('README.md') }, { roots: [workspace] }),
      /workspace|outside|root/i,
    );
  }
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

test('MCP validates JSON-RPC request IDs and echoes valid string and numeric IDs', async () => {
  for (const id of ['request-abc', 42]) {
    const response = await handle_mcp_message({ jsonrpc: '2.0', id, method: 'ping' });
    assert.equal(response.id, id);
    assert.deepEqual(response.result, {});
  }
  for (const id of [null, {}, [], true]) {
    const response = await handle_mcp_message({ jsonrpc: '2.0', id, method: 'ping' });
    assert.equal(response.error.code, -32600);
    assert.equal(response.id, null);
  }
  const invalid_version_with_invalid_id = await handle_mcp_message({
    jsonrpc: '1.0', id: { unexpected: true }, method: 'ping',
  });
  assert.equal(invalid_version_with_invalid_id.error.code, -32600);
  assert.equal(invalid_version_with_invalid_id.id, null);

  const invalid_version_with_valid_id = await handle_mcp_message({
    jsonrpc: '1.0', id: 'legacy-request', method: 'ping',
  });
  assert.equal(invalid_version_with_valid_id.error.code, -32600);
  assert.equal(invalid_version_with_valid_id.id, 'legacy-request');
});

test('MCP rejects malformed request params before invoking a tool', async () => {
  const invalid_container = await handle_mcp_message({
    jsonrpc: '2.0', id: 61, method: 'tools/call', params: [],
  });
  assert.equal(invalid_container.error.code, -32602);

  const missing_name = await handle_mcp_message({
    jsonrpc: '2.0', id: 62, method: 'tools/call', params: { arguments: {} },
  });
  assert.equal(missing_name.error.code, -32602);

  const invalid_arguments = await handle_mcp_message({
    jsonrpc: '2.0', id: 63, method: 'tools/call',
    params: { name: 'orix.formats', arguments: [] },
  });
  assert.equal(invalid_arguments.error.code, -32602);
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

test('MCP processes bounded JSON-RPC batches and omits notification responses', async () => {
  const batch = await handle_mcp_message([
    { jsonrpc: '2.0', id: 'batch-1', method: 'ping' },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'ping' },
  ]);
  assert.equal(batch.length, 2);
  assert.deepEqual(batch.map(item => item.id), ['batch-1', 2]);
  assert.ok(batch.every(item => item.result && !item.error));

  const notifications_only = await handle_mcp_message([
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', method: 'initialize' },
  ]);
  assert.equal(notifications_only, null);

  const empty = await handle_mcp_message([]);
  assert.equal(empty.error.code, -32600);

  const initialize = await handle_mcp_message([{
    jsonrpc: '2.0', id: 9, method: 'initialize',
    params: {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'batch-client', version: '1.0.0' },
    },
  }]);
  assert.equal(initialize[0].error.code, -32600);
});

test('MCP rejects batches beyond the configured message ceiling', async () => {
  const oversized = Array.from({ length: 101 }, (_, index) => ({
    jsonrpc: '2.0', id: index, method: 'ping',
  }));
  const response = await handle_mcp_message(oversized);
  assert.equal(response.error.code, -32600);
});

test('MCP stdio transport rate-limits tool calls per connection while leaving protocol requests available', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  let captured = '';
  output.setEncoding('utf8');
  output.on('data', chunk => { captured += chunk; });
  const running = start_mcp_server({
    input, output, error_output: errors, max_tool_calls_per_minute: 1,
  });
  const send = value => input.write(JSON.stringify(value) + '\n');
  send({
    jsonrpc: '2.0', id: 80, method: 'initialize',
    params: {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'rate-limit-client', version: '1.0.0' },
    },
  });
  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  const request = id => ({
    jsonrpc: '2.0', id, method: 'tools/call',
    params: { name: 'orix.formats', arguments: {} },
  });
  send(request(81));
  send(request(82));
  send({ jsonrpc: '2.0', id: 83, method: 'ping' });
  input.end();
  await running;

  const messages = captured.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(messages.length, 4);
  assert.equal(messages[0].result.protocolVersion, '2025-03-26');
  assert.equal(messages[1].result.isError, false);
  assert.equal(messages[2].result.isError, true);
  assert.equal(JSON.parse(messages[2].result.content[0].text).code, 'ORIX_MCP_RATE_LIMITED');
  assert.deepEqual(messages[3].result, {});
});

test('MCP stdio transport rejects invalid per-connection rate limits', async () => {
  await assert.rejects(
    start_mcp_server({
      input: new PassThrough(),
      output: new PassThrough(),
      error_output: new PassThrough(),
      max_tool_calls_per_minute: 0,
    }),
    /between 1 and 10000/,
  );
});

test('MCP stdio enforces initialize, initialized notification, and active-session lifecycle', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  let captured = '';
  output.setEncoding('utf8');
  output.on('data', chunk => { captured += chunk; });
  const running = start_mcp_server({ input, output, error_output: errors });
  const send = value => input.write(JSON.stringify(value) + '\n');

  send({ jsonrpc: '2.0', id: 90, method: 'tools/list' });
  send({ jsonrpc: '2.0', id: 91, method: 'ping' });
  send({
    jsonrpc: '2.0', id: 92, method: 'initialize',
    params: {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'lifecycle-client', version: '1.0.0' },
    },
  });
  send({ jsonrpc: '2.0', id: 93, method: 'tools/list' });
  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  send({ jsonrpc: '2.0', id: 94, method: 'tools/list' });
  send({
    jsonrpc: '2.0', id: 95, method: 'initialize',
    params: {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'duplicate-client', version: '1.0.0' },
    },
  });
  input.end();
  await running;

  const messages = captured.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(messages.length, 6);
  assert.equal(messages[0].error.code, -32002);
  assert.deepEqual(messages[1].result, {});
  assert.equal(messages[2].result.protocolVersion, '2025-03-26');
  assert.equal(messages[3].error.code, -32002);
  assert.equal(messages[4].result.tools.length, ORIX_MCP_TOOLS.length);
  assert.equal(messages[5].error.code, -32600);
});

test('MCP stdio keeps the session uninitialized when initialize validation fails', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const errors = new PassThrough();
  let captured = '';
  output.setEncoding('utf8');
  output.on('data', chunk => { captured += chunk; });
  const running = start_mcp_server({ input, output, error_output: errors });
  input.write(JSON.stringify({ jsonrpc: '2.0', id: 96, method: 'initialize', params: {} }) + '\n');
  input.write(JSON.stringify({ jsonrpc: '2.0', id: 97, method: 'tools/list' }) + '\n');
  input.end();
  await running;

  const messages = captured.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(messages[0].error.code, -32602);
  assert.equal(messages[1].error.code, -32002);
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
  input.write(JSON.stringify({
    jsonrpc: '2.0', id: 11, method: 'initialize',
    params: {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'transport-test-client', version: '1.0.0' },
    },
  }) + '\n');
  input.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  input.write(JSON.stringify({ jsonrpc: '2.0', id: 12, method: 'tools/list' }) + '\n');
  input.end();
  await running;
  const messages = captured.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(messages.length, 3);
  assert.deepEqual(messages[0].result, {});
  assert.equal(messages[1].result.protocolVersion, '2025-03-26');
  assert.equal(messages[2].result.tools.length, ORIX_MCP_TOOLS.length);
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

test('MCP case read, verification and mutation reject hard-linked case ledgers', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'orix-mcp-case-ledger-hardlink-'));
  const alias_dir = await mkdtemp(path.join(tmpdir(), 'orix-mcp-case-ledger-alias-'));
  try {
    const created = await call_orix_tool('orix.case.create', {
      workspace, title: 'Case ledger alias',
    }, { roots: [workspace] });
    const events = path.join(workspace, '.orix', 'cases', created.case.id, 'events.jsonl');
    const alias = path.join(alias_dir, 'outside-ledger-alias.jsonl');
    const { link } = await import('node:fs/promises');
    await link(events, alias);
    const before = await readFile(events, 'utf8');

    await assert.rejects(
      call_orix_tool('orix.case.get', {
        workspace, case_id: created.case.id, action: 'show',
      }, { roots: [workspace] }),
      error => error.code === 'ORIX_LEDGER_HARDLINK_REJECTED',
    );
    await assert.rejects(
      call_orix_tool('orix.case.get', {
        workspace, case_id: created.case.id, action: 'verify',
      }, { roots: [workspace] }),
      error => error.code === 'ORIX_LEDGER_HARDLINK_REJECTED',
    );
    await assert.rejects(
      call_orix_tool('orix.case.mutate', {
        workspace, case_id: created.case.id, action: 'add_note', text: 'must not append',
      }, { roots: [workspace] }),
      error => error.code === 'ORIX_LEDGER_HARDLINK_REJECTED',
    );
    const listed = await call_orix_tool('orix.case.get', {
      workspace, action: 'list',
    }, { roots: [workspace] });
    assert.equal(listed.cases.length, 0);
    assert.equal(listed.coverage.skipped_entries, 1);
    assert.equal(await readFile(events, 'utf8'), before);
    assert.equal(await readFile(alias, 'utf8'), before);
  } finally {
    await rm(workspace, { recursive: true, force: true });
    await rm(alias_dir, { recursive: true, force: true });
  }
});

test('MCP case artifact intake rejects hard-linked source files', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'orix-mcp-case-hardlink-'));
  try {
    const source = path.join(workspace, 'source.bin');
    const alias = path.join(workspace, 'source-alias.bin');
    const created = await call_orix_tool('orix.case.create', {
      workspace, title: 'Hard-link intake',
    }, { roots: [workspace] });
    await writeFile(source, 'case source bytes');
    const { link } = await import('node:fs/promises');
    await link(source, alias);
    await assert.rejects(
      call_orix_tool('orix.case.mutate', {
        workspace, case_id: created.case.id, action: 'add_artifact', path: source,
      }, { roots: [workspace] }),
      error => error.code === 'ORIX_MCP_HARDLINK_REJECTED',
    );
    const state = await call_orix_tool('orix.case.get', {
      workspace, case_id: created.case.id, action: 'show',
    }, { roots: [workspace] });
    assert.equal(state.artifacts.length, 0);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('MCP refuses to append evidence through a hard-linked output alias', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'orix-mcp-hardlink-output-root-'));
  const outside = await mkdtemp(path.join(tmpdir(), 'orix-mcp-hardlink-output-outside-'));
  try {
    const external = path.join(outside, 'external-ledger.jsonl');
    const alias = path.join(root, 'ledger.jsonl');
    const { link, readFile } = await import('node:fs/promises');
    await writeFile(external, 'external data must remain unchanged');
    await link(external, alias);
    await assert.rejects(
      call_orix_tool('orix.ledger.append', { path: alias, type: 'analysis.completed', payload: {} }, { roots: [root] }),
      error => error.code === 'ORIX_MCP_HARDLINK_REJECTED',
    );
    assert.equal(await readFile(external, 'utf8'), 'external data must remain unchanged');
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('MCP rejects hard-linked files to prevent workspace aliases to external file content', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'orix-mcp-hardlink-root-'));
  const outside = await mkdtemp(path.join(tmpdir(), 'orix-mcp-hardlink-outside-'));
  try {
    const external = path.join(outside, 'external.bin');
    const alias = path.join(root, 'external-alias.bin');
    const { link } = await import('node:fs/promises');
    await writeFile(external, 'outside workspace content');
    await link(external, alias);
    await assert.rejects(
      call_orix_tool('orix.inspect_file', { path: alias }, { roots: [root] }),
      error => error.code === 'ORIX_MCP_HARDLINK_REJECTED',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('MCP inspector can enforce hard-link rejection at its opened-file boundary', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'orix-mcp-inspector-hardlink-root-'));
  const outside = await mkdtemp(path.join(tmpdir(), 'orix-mcp-inspector-hardlink-outside-'));
  try {
    const external = path.join(outside, 'external.bin');
    const alias = path.join(root, 'alias.bin');
    const { link } = await import('node:fs/promises');
    await writeFile(external, 'protected external content');
    await link(external, alias);
    await assert.rejects(
      inspect_file(alias, { reject_hardlinks: true }),
      error => error.code === 'ORIX_HARDLINK_REJECTED',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('Evidence-ledger read and append reject hard-link aliases when requested by MCP', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'orix-mcp-ledger-hardlink-root-'));
  const outside = await mkdtemp(path.join(tmpdir(), 'orix-mcp-ledger-hardlink-outside-'));
  try {
    const external = path.join(outside, 'external-ledger.jsonl');
    const alias = path.join(root, 'alias-ledger.jsonl');
    await append_ledger(external, { type: 'test.created', payload: { safe: true } });
    const { link, readFile } = await import('node:fs/promises');
    await link(external, alias);
    await assert.rejects(
      verify_ledger(alias, { reject_hardlinks: true }),
      error => error.code === 'ORIX_LEDGER_HARDLINK_REJECTED',
    );
    await assert.rejects(
      append_ledger(alias, { type: 'test.appended', payload: {} }, { reject_hardlinks: true }),
      error => error.code === 'ORIX_LEDGER_HARDLINK_REJECTED',
    );
    assert.equal((await readFile(external, 'utf8')).split('\n').length, 2);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('MCP rejects intermediate directory symlinks even when they resolve inside the workspace', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'orix-mcp-intermediate-link-'));
  try {
    const real_directory = path.join(root, 'real-directory');
    const linked_directory = path.join(root, 'linked-directory');
    const file = path.join(real_directory, 'sample.bin');
    const { symlink } = await import('node:fs/promises');
    await mkdir(real_directory);
    await writeFile(file, 'workspace content');
    await symlink(real_directory, linked_directory);

    await assert.rejects(
      call_orix_tool('orix.inspect_file', { path: path.join(linked_directory, 'sample.bin') }, { roots: [root] }),
      error => error.code === 'ORIX_MCP_SYMLINK_REJECTED',
    );
    const direct = await call_orix_tool('orix.inspect_file', { path: file }, { roots: [root] });
    assert.equal(direct.schema_version, 'orix.artifact.v1');
  } finally {
    await rm(root, { recursive: true, force: true });
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


test('MCP enforces declared enum and array constraints before tool dispatch', async () => {
  await assert.rejects(
    call_orix_tool('orix.case.get', { workspace: '/not-used', action: 'delete' }),
    /action must be one of the declared values/,
  );
  await assert.rejects(
    call_orix_tool('orix.case.mutate', {
      workspace: '/not-used',
      case_id: '00000000-0000-4000-8000-000000000000',
      action: 'status',
      status: 'pending',
    }),
    /status must be one of the declared values/,
  );
  await assert.rejects(
    call_orix_tool('orix.rizin_functions', {
      path: '/not-used/sample.bin',
      executable: '/not-used/rizin',
      executable_args: Array.from({ length: 17 }, () => 'prefix'),
    }),
    /executable_args must be an array within its declared item limits/,
  );
});
