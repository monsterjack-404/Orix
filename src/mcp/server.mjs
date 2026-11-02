// JavaScript, src/mcp/server.mjs, Node.js 20+, read-only Model Context Protocol stdio server.

import readline from 'node:readline';
import { inspect_file } from '../core/inspect.mjs';
import { scan_directory } from '../analyzer/scan.mjs';
import { scan_project } from '../project/intelligence.mjs';
import { list_format_capabilities } from '../formats/index.mjs';
import { verify_ledger, list_ledger } from '../evidence/ledger.mjs';
import { compare_reports } from '../analyzer/compare.mjs';
import { read_json_report } from '../core/read-report.mjs';
import { normalize_error } from '../core/errors.mjs';
import { append_ledger } from '../evidence/ledger.mjs';
import { configured_workspace_roots, resolve_workspace_path, resolve_workspace_output, read_workspace_json } from './security.mjs';

export const MCP_PROTOCOL_VERSION = '2025-03-26';
export const MCP_MAX_LINE_BYTES = 4 * 1024 * 1024;
export const MCP_MAX_RESULT_BYTES = 2 * 1024 * 1024;

const integer = (description, maximum) => ({ type: 'integer', minimum: 0, maximum, description });
const path_schema = { type: 'object', properties: { path: { type: 'string', minLength: 1 } }, required: ['path'], additionalProperties: false };

export const ORIX_MCP_TOOLS = Object.freeze([
  {
    name: 'orix.inspect_file',
    description: 'Statically inspect one regular file. Hashes complete bytes, parses a bounded prefix, and never executes the target.',
    inputSchema: { type: 'object', properties: {
      path: { type: 'string', minLength: 1 },
      max_read_mib: integer('Maximum prefix bytes parsed, in MiB.', 512),
      max_file_mib: integer('Maximum complete file size hashed, in MiB.', 2048),
      max_strings: integer('Maximum extracted strings.', 100000),
      extract_strings: { type: 'boolean' },
    }, required: ['path'], additionalProperties: false },
  },
  {
    name: 'orix.scan_directory',
    description: 'Inventory and statically inspect a directory with bounded traversal and concurrency. Symlinks are skipped.',
    inputSchema: { type: 'object', properties: {
      path: { type: 'string', minLength: 1 },
      max_files: integer('Maximum files inspected.', 1000000),
      max_entries: integer('Maximum directory entries examined.', 10000000),
      max_depth: integer('Maximum directory depth.', 256),
      concurrency: { type: 'integer', minimum: 1, maximum: 32 },
    }, required: ['path'], additionalProperties: false },
  },
  {
    name: 'orix.scan_project',
    description: 'Build a bounded source, manifest, import and symbol inventory without running project code, scripts, builds or tests.',
    inputSchema: { type: 'object', properties: {
      path: { type: 'string', minLength: 1 },
      max_files: integer('Maximum source files.', 1000000),
      max_entries: integer('Maximum entries examined.', 10000000),
      max_depth: integer('Maximum traversal depth.', 256),
    }, required: ['path'], additionalProperties: false },
  },
  {
    name: 'orix.formats',
    description: 'List recognized signatures and structural parser capabilities.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'orix.compare_reports',
    description: 'Compare two previously generated artifact or directory-scan JSON reports by normalized path, SHA-256 and indicator deltas. Does not rescan either path.',
    inputSchema: { type: 'object', properties: {
      baseline_path: { type: 'string', minLength: 1 },
      current_path: { type: 'string', minLength: 1 },
    }, required: ['baseline_path', 'current_path'], additionalProperties: false },
  },
  {
    name: 'orix.ledger.verify',
    description: 'Verify sequence, canonical record hashes and previous-hash links in a local evidence ledger.',
    inputSchema: path_schema,
  },
  {
    name: 'orix.ledger.list',
    description: 'Read and validate all records in a local evidence ledger.',
    inputSchema: path_schema,
  },
  {
    name: 'orix.ledger.append',
    description: 'Append a typed evidence event to a workspace-confined, hash-chained local ledger.',
    inputSchema: { type: 'object', properties: {
      path: { type: 'string', minLength: 1 },
      type: { type: 'string', pattern: '^[a-z][a-z0-9.-]{1,63}
]);

function jsonrpc_error(id, code, message, data = undefined) {
  return { jsonrpc: '2.0', id, error: { code, message, ...(data === undefined ? {} : { data }) } };
}

function tool_result(value) {
  const text = JSON.stringify(value);
  if (Buffer.byteLength(text, 'utf8') > MCP_MAX_RESULT_BYTES) {
    return {
      content: [{ type: 'text', text: JSON.stringify({ code: 'ORIX_MCP_RESULT_TOO_LARGE', message: 'Tool result exceeds the configured MCP output limit. Narrow the scan or reduce its limits.' }) }],
      isError: true,
    };
  }
  return { content: [{ type: 'text', text }], isError: false };
}

function validate_arguments(name, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Tool arguments must be a JSON object');
  const tool = ORIX_MCP_TOOLS.find(item => item.name === name);
  if (!tool) throw new TypeError('Unknown ORIX tool: ' + name);
  const properties = tool.inputSchema.properties ?? {};
  for (const required of tool.inputSchema.required ?? []) {
    if (!Object.hasOwn(value, required)) throw new TypeError('Missing required tool argument: ' + required);
  }
  for (const [key, item] of Object.entries(value)) {
    const schema = properties[key];
    if (!schema) throw new TypeError('Unknown tool argument: ' + key);
    if (schema.type === 'string' && (typeof item !== 'string' || (schema.minLength && item.length < schema.minLength) || (schema.pattern && !new RegExp(schema.pattern).test(item)))) {
      throw new TypeError(key + ' must be a non-empty string');
    }
    if (schema.type === 'boolean' && typeof item !== 'boolean') throw new TypeError(key + ' must be a boolean');
    if (schema.type === 'integer' && (!Number.isSafeInteger(item) || item < schema.minimum || item > schema.maximum)) {
      throw new TypeError(key + ' must be an integer between ' + schema.minimum + ' and ' + schema.maximum);
    }
  }
}

export async function call_orix_tool(name, args = {}, options = {}) {
  validate_arguments(name, args);
  const roots = options.roots ?? configured_workspace_roots(options.environment);
  switch (name) {
    case 'orix.inspect_file': {
      const limits = {};
      if (args.max_read_mib !== undefined) limits.max_read_bytes = args.max_read_mib * 1024 * 1024;
      if (args.max_file_mib !== undefined) limits.max_file_bytes = args.max_file_mib * 1024 * 1024;
      if (args.max_strings !== undefined) limits.max_strings = args.max_strings;
      const target = await resolve_workspace_path(args.path, roots, { kind: 'file' });
      return inspect_file(target.path, { limits, extract_strings: args.extract_strings });
    }
    case 'orix.scan_directory': {
      const limits = {};
      if (args.max_files !== undefined) limits.max_scan_files = args.max_files;
      if (args.max_entries !== undefined) limits.max_scan_entries = args.max_entries;
      if (args.max_depth !== undefined) limits.max_scan_depth = args.max_depth;
      if (args.concurrency !== undefined) limits.max_scan_concurrency = args.concurrency;
      const target = await resolve_workspace_path(args.path, roots, { kind: 'directory' });
      return scan_directory(target.path, { limits });
    }
    case 'orix.scan_project': {
      const limits = {};
      if (args.max_files !== undefined) limits.max_files = args.max_files;
      if (args.max_entries !== undefined) limits.max_entries = args.max_entries;
      if (args.max_depth !== undefined) limits.max_depth = args.max_depth;
      const target = await resolve_workspace_path(args.path, roots, { kind: 'directory' });
      return scan_project(target.path, limits);
    }
    case 'orix.formats':
      return { schema_version: 'orix.formats.v1', formats: list_format_capabilities() };
    case 'orix.compare_reports': {
      const baseline = await read_workspace_json(args.baseline_path, roots);
      const current = await read_workspace_json(args.current_path, roots);
      return compare_reports(baseline, current);
    }
    case 'orix.ledger.verify': {
      const target = await resolve_workspace_path(args.path, roots, { kind: 'file' });
      return verify_ledger(target.path);
    }
    case 'orix.ledger.list': {
      const target = await resolve_workspace_path(args.path, roots, { kind: 'file' });
      return list_ledger(target.path);
    }
    case 'orix.ledger.append': {
      const target = await resolve_workspace_output(args.path, roots);
      return append_ledger(target, { type: args.type, payload: args.payload });
    }
    default:
      throw new TypeError('Unknown ORIX tool: ' + name);
  }
}

export async function handle_mcp_message(message, options = {}) {
  if (!message || typeof message !== 'object' || Array.isArray(message) || message.jsonrpc !== '2.0') {
    return jsonrpc_error(message?.id ?? null, -32600, 'Invalid JSON-RPC request');
  }
  const has_id = Object.hasOwn(message, 'id');
  const id = has_id ? message.id : null;
  if (typeof message.method !== 'string') return has_id ? jsonrpc_error(id, -32600, 'Request method must be a string') : null;
  if (!has_id) {
    if (message.method === 'notifications/exit') return null;
    return null;
  }
  if (message.method === 'ping') return { jsonrpc: '2.0', id, result: {} };
  if (message.method === 'initialize') {
    const requested = message.params?.protocolVersion;
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: requested === MCP_PROTOCOL_VERSION ? requested : MCP_PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'orix', version: '0.4.0' },
        instructions: 'ORIX performs local static analysis only. Tool calls do not execute samples, project scripts, build hooks or tests.',
      },
    };
  }
  if (message.method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: ORIX_MCP_TOOLS } };
  }
  if (message.method === 'tools/call') {
    const name = message.params?.name;
    const args = message.params?.arguments ?? {};
    try {
      if (!ORIX_MCP_TOOLS.some(tool => tool.name === name)) return { jsonrpc: '2.0', id, result: tool_result({ code: 'ORIX_MCP_TOOL_NOT_FOUND', message: 'Unknown tool: ' + String(name) }) };
      return { jsonrpc: '2.0', id, result: tool_result(await call_orix_tool(name, args, options)) };
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
      error_output.write('ORIX MCP input line exceeded the configured limit.\n');
      continue;
    }
    let message;
    try { message = JSON.parse(line); }
    catch {
      output.write(JSON.stringify(jsonrpc_error(null, -32700, 'Parse error')) + '\n');
      continue;
    }
    const response = await handle_mcp_message(message, { roots, environment });
    if (response !== null) output.write(JSON.stringify(response) + '\n');
  }
  return 0;
}
 },
      payload: { type: 'object' },
    }, required: ['path', 'type', 'payload'], additionalProperties: false },
  },

]);

function jsonrpc_error(id, code, message, data = undefined) {
  return { jsonrpc: '2.0', id, error: { code, message, ...(data === undefined ? {} : { data }) } };
}

function tool_result(value) {
  const text = JSON.stringify(value);
  if (Buffer.byteLength(text, 'utf8') > MCP_MAX_RESULT_BYTES) {
    return {
      content: [{ type: 'text', text: JSON.stringify({ code: 'ORIX_MCP_RESULT_TOO_LARGE', message: 'Tool result exceeds the configured MCP output limit. Narrow the scan or reduce its limits.' }) }],
      isError: true,
    };
  }
  return { content: [{ type: 'text', text }], isError: false };
}

function validate_arguments(name, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Tool arguments must be a JSON object');
  const tool = ORIX_MCP_TOOLS.find(item => item.name === name);
  if (!tool) throw new TypeError('Unknown ORIX tool: ' + name);
  const properties = tool.inputSchema.properties ?? {};
  for (const required of tool.inputSchema.required ?? []) {
    if (!Object.hasOwn(value, required)) throw new TypeError('Missing required tool argument: ' + required);
  }
  for (const [key, item] of Object.entries(value)) {
    const schema = properties[key];
    if (!schema) throw new TypeError('Unknown tool argument: ' + key);
    if (schema.type === 'string' && (typeof item !== 'string' || (schema.minLength && item.length < schema.minLength))) {
      throw new TypeError(key + ' must be a non-empty string');
    }
    if (schema.type === 'boolean' && typeof item !== 'boolean') throw new TypeError(key + ' must be a boolean');
    if (schema.type === 'integer' && (!Number.isSafeInteger(item) || item < schema.minimum || item > schema.maximum)) {
      throw new TypeError(key + ' must be an integer between ' + schema.minimum + ' and ' + schema.maximum);
    }
  }
}

export async function call_orix_tool(name, args = {}) {
  validate_arguments(name, args);
  switch (name) {
    case 'orix.inspect_file': {
      const limits = {};
      if (args.max_read_mib !== undefined) limits.max_read_bytes = args.max_read_mib * 1024 * 1024;
      if (args.max_file_mib !== undefined) limits.max_file_bytes = args.max_file_mib * 1024 * 1024;
      if (args.max_strings !== undefined) limits.max_strings = args.max_strings;
      return inspect_file(args.path, { limits, extract_strings: args.extract_strings });
    }
    case 'orix.scan_directory': {
      const limits = {};
      if (args.max_files !== undefined) limits.max_scan_files = args.max_files;
      if (args.max_entries !== undefined) limits.max_scan_entries = args.max_entries;
      if (args.max_depth !== undefined) limits.max_scan_depth = args.max_depth;
      if (args.concurrency !== undefined) limits.max_scan_concurrency = args.concurrency;
      return scan_directory(args.path, { limits });
    }
    case 'orix.scan_project': {
      const limits = {};
      if (args.max_files !== undefined) limits.max_files = args.max_files;
      if (args.max_entries !== undefined) limits.max_entries = args.max_entries;
      if (args.max_depth !== undefined) limits.max_depth = args.max_depth;
      return scan_project(args.path, limits);
    }
    case 'orix.formats':
      return { schema_version: 'orix.formats.v1', formats: list_format_capabilities() };
    case 'orix.compare_reports': {
      const baseline = await read_json_report(args.baseline_path);
      const current = await read_json_report(args.current_path);
      return compare_reports(baseline, current);
    }
    case 'orix.ledger.verify':
      return verify_ledger(args.path);
    case 'orix.ledger.list':
      return list_ledger(args.path);
    default:
      throw new TypeError('Unknown ORIX tool: ' + name);
  }
}

export async function handle_mcp_message(message) {
  if (!message || typeof message !== 'object' || Array.isArray(message) || message.jsonrpc !== '2.0') {
    return jsonrpc_error(message?.id ?? null, -32600, 'Invalid JSON-RPC request');
  }
  const has_id = Object.hasOwn(message, 'id');
  const id = has_id ? message.id : null;
  if (typeof message.method !== 'string') return has_id ? jsonrpc_error(id, -32600, 'Request method must be a string') : null;
  if (!has_id) {
    if (message.method === 'notifications/exit') return null;
    return null;
  }
  if (message.method === 'ping') return { jsonrpc: '2.0', id, result: {} };
  if (message.method === 'initialize') {
    const requested = message.params?.protocolVersion;
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: requested === MCP_PROTOCOL_VERSION ? requested : MCP_PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'orix', version: '0.4.0' },
        instructions: 'ORIX performs local static analysis only. Tool calls do not execute samples, project scripts, build hooks or tests.',
      },
    };
  }
  if (message.method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: ORIX_MCP_TOOLS } };
  }
  if (message.method === 'tools/call') {
    const name = message.params?.name;
    const args = message.params?.arguments ?? {};
    try {
      if (!ORIX_MCP_TOOLS.some(tool => tool.name === name)) return { jsonrpc: '2.0', id, result: tool_result({ code: 'ORIX_MCP_TOOL_NOT_FOUND', message: 'Unknown tool: ' + String(name) }) };
      return { jsonrpc: '2.0', id, result: tool_result(await call_orix_tool(name, args)) };
    } catch (error) {
      const normalized = normalize_error(error);
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(normalized) }], isError: true } };
    }
  }
  if (message.method === 'resources/list') return { jsonrpc: '2.0', id, result: { resources: [] } };
  if (message.method === 'prompts/list') return { jsonrpc: '2.0', id, result: { prompts: [] } };
  return jsonrpc_error(id, -32601, 'Method not found: ' + message.method);
}

export async function start_mcp_server({ input = process.stdin, output = process.stdout, error_output = process.stderr } = {}) {
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  for await (const line of lines) {
    if (Buffer.byteLength(line, 'utf8') > MCP_MAX_LINE_BYTES) {
      error_output.write('ORIX MCP input line exceeded the configured limit.\n');
      continue;
    }
    let message;
    try { message = JSON.parse(line); }
    catch {
      output.write(JSON.stringify(jsonrpc_error(null, -32700, 'Parse error')) + '\n');
      continue;
    }
    const response = await handle_mcp_message(message);
    if (response !== null) output.write(JSON.stringify(response) + '\n');
  }
  return 0;
}
