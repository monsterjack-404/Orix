// JavaScript, tests/mcp.test.mjs, Node.js 20+, MCP protocol and ORIX tool integration tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { handle_mcp_message, ORIX_MCP_TOOLS, call_orix_tool, start_mcp_server } from '../src/mcp/server.mjs';

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
  assert.ok(response.result.tools.some(tool => tool.name === 'orix.ledger.verify'));
});

test('MCP inspect tool returns the same versioned artifact report as the library API', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'orix-mcp-'));
  try {
    const file = path.join(directory, 'sample.bin');
    await writeFile(file, Buffer.from('MCP static analysis fixture'));
    const response = await handle_mcp_message({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'orix.inspect_file', arguments: { path: file } } });
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
  input.write(JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'ping' }) + '\\n');
  input.write(JSON.stringify({ jsonrpc: '2.0', id: 11, method: 'tools/list' }) + '\\n');
  input.end();
  await running;
  const messages = captured.trim().split('\\n').map(line => JSON.parse(line));
  assert.equal(messages.length, 2);
  assert.deepEqual(messages[0].result, {});
  assert.equal(messages[1].result.tools.length, ORIX_MCP_TOOLS.length);
});
