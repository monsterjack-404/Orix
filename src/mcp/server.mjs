// JavaScript, src/mcp/server.mjs, Node.js 20+, bounded read-only Model Context Protocol stdio server.

import { inspect_file } from '../core/inspect.mjs';
import { scan_directory } from '../analyzer/scan.mjs';
import { scan_project } from '../project/intelligence.mjs';
import { analyze_project_architecture } from '../project/architecture.mjs';
import { list_format_capabilities } from '../formats/index.mjs';
import { verify_ledger, list_ledger, append_ledger } from '../evidence/ledger.mjs';
import { compare_reports } from '../analyzer/compare.mjs';
import { normalize_error } from '../core/errors.mjs';
import { TextDecoder } from 'node:util';
import {
  configured_workspace_roots,
  resolve_workspace_path,
  resolve_workspace_output,
  read_workspace_json,
} from './security.mjs';

export const MCP_PROTOCOL_VERSION = '2025-03-26';
export const MCP_MAX_LINE_BYTES = 4 * 1024 * 1024;
export const MCP_MAX_RESULT_BYTES = 2 * 1024 * 1024;
export const MCP_MAX_BATCH_MESSAGES = 100;

const integer = (description, maximum, minimum = 0) => ({ type: 'integer', minimum, maximum, description });
const path_schema = {
  type: 'object',
  properties: { path: { type: 'string', minLength: 1 } },
  required: ['path'],
  additionalProperties: false,
};

export const ORIX_MCP_TOOLS = Object.freeze([
  {
    name: 'orix.inspect_file',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Statically inspect one regular file. Hashes complete bytes, parses a bounded prefix, and never executes the target.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', minLength: 1 },
        max_read_mib: integer('Maximum prefix bytes parsed, in MiB.', 512, 1),
        max_file_mib: integer('Maximum complete file size hashed, in MiB.', 2048, 1),
        max_strings: integer('Maximum extracted strings.', 100000),
        extract_strings: { type: 'boolean' },
      },
      required: ['path'],
      additionalProperties: false,
    },
  },
  {
    name: 'orix.scan_directory',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Inventory and statically inspect a directory with bounded traversal and concurrency. Symlinks are skipped.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', minLength: 1 },
        max_files: integer('Maximum files inspected.', 1000000, 1),
        max_entries: integer('Maximum directory entries examined.', 10000000, 1),
        max_depth: integer('Maximum traversal depth.', 256),
        concurrency: integer('Maximum concurrent file inspections.', 32, 1),
      },
      required: ['path'],
      additionalProperties: false,
    },
  },
  {
    name: 'orix.scan_project',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Build a bounded source, manifest, import and symbol inventory without running project code, scripts, builds or tests.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', minLength: 1 },
        max_files: integer('Maximum source files.', 1000000, 1),
        max_entries: integer('Maximum entries examined.', 10000000, 1),
        max_depth: integer('Maximum traversal depth.', 256),
      },
      required: ['path'],
      additionalProperties: false,
    },
  },
  {
    name: 'orix.analyze_architecture',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Build a bounded source-import graph and report entry-point candidates, circular dependencies, reachability, isolated modules and external imports. Uses static inventory only; it never executes project code.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', minLength: 1 },
        max_files: integer('Maximum source files inventoried.', 50000, 1),
        max_entries: integer('Maximum project entries examined.', 200000, 1),
        max_depth: integer('Maximum traversal depth.', 24),
        max_nodes: integer('Maximum graph nodes analyzed.', 50000, 1),
        max_edges: integer('Maximum graph edges analyzed.', 250000, 1),
        max_hotspots: integer('Maximum connectivity hotspots returned.', 100, 1),
      },
      required: ['path'],
      additionalProperties: false,
    },
  },
  {
    name: 'orix.formats',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'List recognized signatures and structural parser capabilities.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'orix.compare_reports',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Compare two previously generated artifact or directory-scan JSON reports by normalized path, SHA-256 and indicator deltas. Does not rescan either path.',
    inputSchema: {
      type: 'object',
      properties: {
        baseline_path: { type: 'string', minLength: 1 },
        current_path: { type: 'string', minLength: 1 },
      },
      required: ['baseline_path', 'current_path'],
      additionalProperties: false,
    },
  },
  {
    name: 'orix.ledger.verify',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Verify sequence, canonical record hashes and previous-hash links in a workspace-confined local evidence ledger.',
    inputSchema: path_schema,
  },
  {
    name: 'orix.ledger.list',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Read and validate all records in a workspace-confined local evidence ledger.',
    inputSchema: path_schema,
  },
  {
    name: 'orix.ledger.append',
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    description: 'Append a typed evidence event to a workspace-confined, hash-chained local ledger.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', minLength: 1 },
        type: { type: 'string', minLength: 2, maxLength: 80, pattern: '^[a-z][a-z0-9_.-]{1,79}$' },
        payload: { type: 'object' },
      },
      required: ['path', 'type', 'payload'],
      additionalProperties: false,
    },
  },
]);

function is_request_id(value) {
  return typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value));
}

function is_json_object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function jsonrpc_error(id, code, message, data = undefined) {
  return {
    jsonrpc: '2.0',
    id,
    error: { code, message, ...(data === undefined ? {} : { data }) },
  };
}

function tool_result(value) {
  const text = JSON.stringify(value);
  if (Buffer.byteLength(text, 'utf8') > MCP_MAX_RESULT_BYTES) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          code: 'ORIX_MCP_RESULT_TOO_LARGE',
          message: 'Tool result exceeds the configured MCP output limit. Narrow the scan or reduce its limits.',
        }),
      }],
      isError: true,
    };
  }
  return { content: [{ type: 'text', text }], isError: false };
}

function validate_arguments(name, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Tool arguments must be a JSON object');
  }
  const tool = ORIX_MCP_TOOLS.find(item => item.name === name);
  if (!tool) throw new TypeError('Unknown ORIX tool: ' + name);
  const properties = tool.inputSchema.properties ?? {};
  for (const required of tool.inputSchema.required ?? []) {
    if (!Object.hasOwn(value, required)) throw new TypeError('Missing required tool argument: ' + required);
  }
  for (const [key, item] of Object.entries(value)) {
    const schema = properties[key];
    if (!schema) throw new TypeError('Unknown tool argument: ' + key);
    if (schema.type === 'string') {
      if (typeof item !== 'string' || item.length < (schema.minLength ?? 0) || item.length > (schema.maxLength ?? Infinity)) {
        throw new TypeError(key + ' must be a string within its declared length bounds');
      }
      if (schema.pattern && !new RegExp(schema.pattern).test(item)) throw new TypeError(key + ' does not match its required pattern');
    }
    if (schema.type === 'boolean' && typeof item !== 'boolean') throw new TypeError(key + ' must be a boolean');
    if (schema.type === 'integer' && (!Number.isSafeInteger(item) || item < schema.minimum || item > schema.maximum)) {
      throw new TypeError(key + ' must be an integer between ' + schema.minimum + ' and ' + schema.maximum);
    }
    if (schema.type === 'object' && (!item || typeof item !== 'object' || Array.isArray(item))) {
      throw new TypeError(key + ' must be an object');
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
    case 'orix.analyze_architecture': {
      const limits = {};
      if (args.max_files !== undefined) limits.max_files = args.max_files;
      if (args.max_entries !== undefined) limits.max_entries = args.max_entries;
      if (args.max_depth !== undefined) limits.max_depth = args.max_depth;
      const target = await resolve_workspace_path(args.path, roots, { kind: 'directory' });
      const project = await scan_project(target.path, limits);
      // Keep default MCP graph results comfortably below the 2 MiB transport
      // result ceiling. Callers can raise these ceilings explicitly when needed.
      return analyze_project_architecture(project, {
        max_nodes: args.max_nodes ?? 4000,
        max_edges: args.max_edges ?? 8000,
        max_hotspots: args.max_hotspots ?? 25,
      });
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
  if (Array.isArray(message)) {
    if (message.length === 0) return jsonrpc_error(null, -32600, 'Empty JSON-RPC batch');
    if (message.length > MCP_MAX_BATCH_MESSAGES) {
      return jsonrpc_error(null, -32600, 'JSON-RPC batch exceeds the configured message limit');
    }
    const responses = [];
    for (const item of message) {
      if (is_json_object(item) && item.method === 'initialize') {
        // Preserve JSON-RPC's no-response rule for notifications, even though
        // initialize requests themselves are forbidden inside a batch.
        if (!Object.hasOwn(item, 'id')) continue;
        const item_id = is_request_id(item.id) ? item.id : null;
        responses.push(jsonrpc_error(item_id, -32600, 'initialize requests must not be sent in a JSON-RPC batch'));
        continue;
      }
      const response = await handle_mcp_message(item, options);
      if (response !== null) responses.push(response);
    }
    return responses.length > 0 ? responses : null;
  }
  if (!message || typeof message !== 'object' || Array.isArray(message)) {
    return jsonrpc_error(null, -32600, 'Invalid JSON-RPC request');
  }
  if (message.jsonrpc !== '2.0') {
    const invalid_version_id = Object.hasOwn(message, 'id') && is_request_id(message.id)
      ? message.id
      : null;
    return jsonrpc_error(invalid_version_id, -32600, 'Invalid JSON-RPC request');
  }
  const has_id = Object.hasOwn(message, 'id');
  if (has_id && !is_request_id(message.id)) {
    return jsonrpc_error(null, -32600, 'Invalid JSON-RPC request ID');
  }
  const id = has_id ? message.id : null;
  if (typeof message.method !== 'string' || message.method.length === 0) {
    return jsonrpc_error(id, -32600, 'Request method must be a non-empty string');
  }
  // A valid notification never receives a response, including for unsupported methods.
  if (!has_id) return null;
  if (message.params !== undefined && !is_json_object(message.params)) {
    return jsonrpc_error(id, -32602, 'Request params must be a JSON object');
  }
  if (message.method === 'ping') return { jsonrpc: '2.0', id, result: {} };
  if (message.method === 'initialize') {
    const params = message.params;
    if (
      !is_json_object(params)
      || typeof params.protocolVersion !== 'string'
      || params.protocolVersion.length === 0
      || !is_json_object(params.capabilities)
      || !is_json_object(params.clientInfo)
      || typeof params.clientInfo.name !== 'string'
      || params.clientInfo.name.length === 0
      || typeof params.clientInfo.version !== 'string'
      || params.clientInfo.version.length === 0
    ) {
      return jsonrpc_error(id, -32602, 'initialize requires protocolVersion, capabilities, and clientInfo.name/version');
    }
    const protocol_version = params.protocolVersion === MCP_PROTOCOL_VERSION
      ? params.protocolVersion
      : MCP_PROTOCOL_VERSION;
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: protocol_version,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'orix', version: '0.5.0' },
        instructions: 'ORIX performs local static analysis only. Tool calls do not execute samples, project scripts, build hooks or tests.',
      },
    };
  }
  if (message.method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: ORIX_MCP_TOOLS } };
  }
  if (message.method === 'tools/call') {
    const params = message.params;
    if (
      !is_json_object(params)
      || typeof params.name !== 'string'
      || params.name.trim().length === 0
      || (params.arguments !== undefined && !is_json_object(params.arguments))
    ) {
      return jsonrpc_error(id, -32602, 'tools/call requires a tool name and an optional JSON object for arguments');
    }
    const name = params.name;
    const args = params.arguments ?? {};
    try {
      return { jsonrpc: '2.0', id, result: tool_result(await call_orix_tool(name, args, options)) };
    } catch (error) {
      const normalized = normalize_error(error);
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(normalized) }], isError: true } };
    }
  }
  return jsonrpc_error(id, -32601, 'Method not found: ' + message.method);
}

async function process_input_line(line, output, options) {
  if (line.length === 0) return;
  let message;
  try { message = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line)); }
  catch {
    output.write(JSON.stringify(jsonrpc_error(null, -32700, 'Parse error')) + '\n');
    return;
  }
  const response = await handle_mcp_message(message, options);
  if (response !== null) output.write(JSON.stringify(response) + '\n');
}

export async function start_mcp_server({
  input = process.stdin,
  output = process.stdout,
  error_output = process.stderr,
  roots,
  environment,
} = {}) {
  const options = { roots, environment };
  let pending = Buffer.alloc(0);
  let discarding = false;
  for await (const chunk of input) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    let cursor = 0;
    while (cursor < bytes.length) {
      const newline = bytes.indexOf(0x0a, cursor);
      const end = newline < 0 ? bytes.length : newline;
      const part = bytes.subarray(cursor, end);
      if (discarding) {
        if (newline < 0) break;
        discarding = false;
        pending = Buffer.alloc(0);
        cursor = newline + 1;
        continue;
      }
      if (pending.length + part.length > MCP_MAX_LINE_BYTES) {
        error_output.write('ORIX MCP input line exceeded the configured limit.\n');
        pending = Buffer.alloc(0);
        if (newline < 0) {
          discarding = true;
          break;
        }
        cursor = newline + 1;
        continue;
      }
      if (newline < 0) {
        pending = part.length ? Buffer.concat([pending, part]) : pending;
        break;
      }
      const line = part.length ? Buffer.concat([pending, part]) : pending;
      pending = Buffer.alloc(0);
      await process_input_line(line, output, options);
      cursor = newline + 1;
    }
  }
  if (!discarding && pending.length > 0) {
    if (pending.length <= MCP_MAX_LINE_BYTES) await process_input_line(pending, output, options);
    else error_output.write('ORIX MCP input line exceeded the configured limit.\n');
  }
  return 0;
}
