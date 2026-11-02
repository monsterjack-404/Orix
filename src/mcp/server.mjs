// JavaScript, src/mcp/server.mjs, Node.js 20+, JSON-RPC stdio transport for the ORIX MCP tool registry.

import readline from 'node:readline';
import { normalize_error } from '../core/errors.mjs';
import { create_tool_registry, MCP_TOOLS } from './tools.mjs';

export const MCP_PROTOCOL_VERSION = '2025-03-26';
export const MCP_MAX_LINE_BYTES = 4 * 1024 * 1024;
export const MCP_MAX_RESULT_BYTES = 2 * 1024 * 1024;
export const ORIX_MCP_TOOLS = MCP_TOOLS;

function jsonrpc_error(id, code, message, data = undefined) {
  return { jsonrpc: '2.0', id, error: { code, message, ...(data === undefined ? {} : { data }) } };
}

export async function call_orix_tool(name, args = {}, options = {}) {
  const registry = create_tool_registry(options);
  const encoded = await registry.call(name, args);
  return JSON.parse(encoded);
}

export async function handle_mcp_message(message, options = {}) {
  if (!message || typeof message !== 'object' || Array.isArray(message) || message.jsonrpc !== '2.0') {
    return jsonrpc_error(message?.id ?? null, -32600, 'Invalid JSON-RPC request');
  }
  const has_id = Object.hasOwn(message, 'id');
  const id = has_id ? message.id : null;
  if (typeof message.method !== 'string') return has_id ? jsonrpc_error(id, -32600, 'Request method must be a string') : null;
  if (!has_id) return null;
  if (message.method === 'ping') return { jsonrpc: '2.0', id, result: {} };
  if (message.method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: message.params?.protocolVersion === MCP_PROTOCOL_VERSION ? MCP_PROTOCOL_VERSION : MCP_PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'orix', version: '0.4.0' },
        instructions: 'ORIX performs local static analysis only. Workspace roots constrain file access. Target files and project code are never executed.',
      },
    };
  }
  if (message.method === 'tools/list') return { jsonrpc: '2.0', id, result: { tools: ORIX_MCP_TOOLS } };
  if (message.method === 'tools/call') {
    try {
      const name = message.params?.name;
      const args = message.params?.arguments ?? {};
      const registry = create_tool_registry(options);
      const text = await registry.call(name, args);
      if (Buffer.byteLength(text, 'utf8') > MCP_MAX_RESULT_BYTES) {
        return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({ code: 'ORIX_MCP_RESULT_LIMIT', message: 'Tool result exceeds the configured response limit.' }) }], isError: true } };
      }
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }], isError: false } };
    } catch (error) {
      const normalized = normalize_error(error);
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(normalized) }], isError: true } };
    }
  }
  if (message.method === 'resources/list') return { jsonrpc: '2.0', id, result: { resources: [] } };
  if (message.method === 'prompts/list') return { jsonrpc: '2.0', id, result: { prompts: [] } };
  return jsonrpc_error(id, -32601, 'Method not found: ' + message.method);
}

export async function start_mcp_server({ input = process.stdin, output = process.stdout, error_output = process.stderr, roots, environment } = {}) {
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  for await (const line of lines) {
    if (Buffer.byteLength(line, 'utf8') > MCP_MAX_LINE_BYTES) {
      error_output.write('ORIX MCP input line exceeded the configured limit.\\n');
      continue;
    }
    let message;
    try { message = JSON.parse(line); }
    catch {
      output.write(JSON.stringify(jsonrpc_error(null, -32700, 'Parse error')) + '\\n');
      continue;
    }
    const response = await handle_mcp_message(message, { roots, environment });
    if (response !== null) output.write(JSON.stringify(response) + '\\n');
  }
  return 0;
}
