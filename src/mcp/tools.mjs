// JavaScript, src/mcp/tools.mjs, Node.js 20+, bounded ORIX MCP tool catalog and dispatch.
import { inspect_file } from '../core/inspect.mjs';
import { scan_directory } from '../analyzer/scan.mjs';
import { scan_project } from '../project/intelligence.mjs';
import { list_format_capabilities } from '../formats/index.mjs';
import { append_ledger, list_ledger, verify_ledger } from '../evidence/ledger.mjs';
import { compare_reports } from '../analyzer/compare.mjs';
import { OrixError } from '../core/errors.mjs';
import { configured_workspace_roots, resolve_workspace_path, resolve_workspace_output, read_workspace_json } from './security.mjs';

const MAX_RESULT_BYTES = 2 * 1024 * 1024;
export const MCP_TOOLS = Object.freeze([
  { name: 'orix.inspect_file', description: 'Statically inspect one regular file inside an allowed workspace. Does not execute the file.', inputSchema: { type: 'object', properties: { path: { type: 'string', minLength: 1 } }, required: ['path'], additionalProperties: false } },
  { name: 'orix.scan_directory', description: 'Inventory and statically inspect files beneath an allowed workspace directory with explicit resource limits.', inputSchema: { type: 'object', properties: { path: { type: 'string', minLength: 1 }, max_files: { type: 'integer', minimum: 1, maximum: 10000 }, max_depth: { type: 'integer', minimum: 0, maximum: 64 }, concurrency: { type: 'integer', minimum: 1, maximum: 16 } }, required: ['path'], additionalProperties: false } },
  { name: 'orix.scan_project', description: 'Build a bounded source, manifest, dependency and import index without running project code.', inputSchema: { type: 'object', properties: { path: { type: 'string', minLength: 1 }, max_files: { type: 'integer', minimum: 1, maximum: 10000 }, max_depth: { type: 'integer', minimum: 0, maximum: 64 } }, required: ['path'], additionalProperties: false } },
  { name: 'orix.formats', description: 'List recognized file signatures and the availability of structural parsers.', inputSchema: { type: 'object', properties: {}, additionalProperties: false } },
  { name: 'orix.ledger.verify', description: 'Verify sequence continuity and the SHA-256 hash chain of a local ORIX evidence ledger.', inputSchema: { type: 'object', properties: { path: { type: 'string', minLength: 1 } }, required: ['path'], additionalProperties: false } },
  { name: 'orix.ledger.list', description: 'Read and verify records from a local ORIX evidence ledger.', inputSchema: { type: 'object', properties: { path: { type: 'string', minLength: 1 } }, required: ['path'], additionalProperties: false } },
  { name: 'orix.ledger.append', description: 'Append a typed, hash-chained evidence event to a local ledger inside an allowed workspace.', inputSchema: { type: 'object', properties: { path: { type: 'string', minLength: 1 }, type: { type: 'string', pattern: '^[a-z][a-z0-9.-]{1,63}$' }, payload: { type: 'object' } }, required: ['path','type','payload'], additionalProperties: false } },
  { name: 'orix.compare_reports', description: 'Compare two saved ORIX artifact or directory-scan JSON reports by relative path, SHA-256 and indicator deltas.', inputSchema: { type: 'object', properties: { baseline_path: { type: 'string', minLength: 1 }, current_path: { type: 'string', minLength: 1 } }, required: ['baseline_path','current_path'], additionalProperties: false } },
]);
function validate_tool_arguments(name, args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new OrixError('ORIX_MCP_INVALID_ARGUMENTS', 'Tool arguments must be a JSON object', { recoverable: true });
  const definition = MCP_TOOLS.find(tool => tool.name === name);
  if (!definition) throw new OrixError('ORIX_MCP_UNKNOWN_TOOL', 'Unknown ORIX tool: ' + name, { recoverable: true });
  const schema = definition.inputSchema;
  const properties = schema.properties ?? {};
  for (const required of schema.required ?? []) {
    if (!Object.hasOwn(args, required)) throw new OrixError('ORIX_MCP_REQUIRED_ARGUMENT', 'Missing required tool argument: ' + required, { details: { tool: name, argument: required }, recoverable: true });
  }
  for (const [key, value] of Object.entries(args)) {
    const rule = properties[key];
    if (!rule) throw new OrixError('ORIX_MCP_UNKNOWN_ARGUMENT', 'Unknown tool argument: ' + key, { details: { tool: name, argument: key }, recoverable: true });
    if (rule.type === 'string') {
      if (typeof value !== 'string' || value.length < (rule.minLength ?? 0) || (rule.pattern && !new RegExp(rule.pattern).test(value))) {
        throw new OrixError('ORIX_MCP_ARGUMENT_TYPE', 'Tool argument ' + key + ' does not satisfy its string contract', { details: { tool: name, argument: key }, recoverable: true });
      }
    } else if (rule.type === 'integer') {
      if (!Number.isSafeInteger(value) || value < (rule.minimum ?? Number.MIN_SAFE_INTEGER) || value > (rule.maximum ?? Number.MAX_SAFE_INTEGER)) {
        throw new OrixError('ORIX_MCP_ARGUMENT_RANGE', 'Tool argument ' + key + ' is outside its integer range', { details: { tool: name, argument: key, minimum: rule.minimum, maximum: rule.maximum, value }, recoverable: true });
      }
    } else if (rule.type === 'boolean' && typeof value !== 'boolean') {
      throw new OrixError('ORIX_MCP_ARGUMENT_TYPE', 'Tool argument ' + key + ' must be boolean', { details: { tool: name, argument: key }, recoverable: true });
    } else if (rule.type === 'object' && (!value || typeof value !== 'object' || Array.isArray(value))) {
      throw new OrixError('ORIX_MCP_ARGUMENT_TYPE', 'Tool argument ' + key + ' must be an object', { details: { tool: name, argument: key }, recoverable: true });
    }
  }
}

function assert_arguments(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new OrixError('ORIX_MCP_INVALID_ARGUMENTS', 'Tool arguments must be a JSON object', { recoverable: true });
}
function validate_number(value, name, minimum, maximum, fallback) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < minimum || result > maximum) throw new OrixError('ORIX_MCP_ARGUMENT_RANGE', name + ' is outside the permitted range', { details: { name, minimum, maximum, value: result }, recoverable: true });
  return result;
}
function serialize_result(value) {
  const text = JSON.stringify(value, null, 2);
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes > MAX_RESULT_BYTES) throw new OrixError('ORIX_MCP_RESULT_LIMIT', 'Tool result exceeds the 2 MiB MCP response budget', { details: { bytes, maximum: MAX_RESULT_BYTES }, recoverable: true });
  return text;
}
export function create_tool_registry(options = {}) {
  const roots = options.roots ?? configured_workspace_roots(options.environment);
  const handlers = {
    async 'orix.inspect_file'(args) {
      assert_arguments(args);
      const target = await resolve_workspace_path(args.path, roots, { kind: 'file' });
      return inspect_file(target.path);
    },
    async 'orix.scan_directory'(args) {
      assert_arguments(args);
      const target = await resolve_workspace_path(args.path, roots, { kind: 'directory' });
      return scan_directory(target.path, { limits: {
        max_scan_files: validate_number(args.max_files, 'max_files', 1, 10000, 1000),
        max_scan_depth: validate_number(args.max_depth, 'max_depth', 0, 64, 16),
        max_scan_concurrency: validate_number(args.concurrency, 'concurrency', 1, 16, 4),
      } });
    },
    async 'orix.scan_project'(args) {
      assert_arguments(args);
      const target = await resolve_workspace_path(args.path, roots, { kind: 'directory' });
      return scan_project(target.path, {
        max_files: validate_number(args.max_files, 'max_files', 1, 10000, 1000),
        max_depth: validate_number(args.max_depth, 'max_depth', 0, 64, 16),
      });
    },
    async 'orix.formats'(args) {
      assert_arguments(args);
      return { schema_version: 'orix.formats.v1', formats: list_format_capabilities() };
    },
    async 'orix.ledger.verify'(args) {
      assert_arguments(args);
      const target = await resolve_workspace_path(args.path, roots, { kind: 'file' });
      return verify_ledger(target.path);
    },
    async 'orix.ledger.list'(args) {
      assert_arguments(args);
      const target = await resolve_workspace_path(args.path, roots, { kind: 'file' });
      return list_ledger(target.path);
    },
    async 'orix.ledger.append'(args) {
      assert_arguments(args);
      const target = await resolve_workspace_output(args.path, roots);
      return append_ledger(target, { type: args.type, payload: args.payload });
    },
    async 'orix.compare_reports'(args) {
      assert_arguments(args);
      const [baseline, current] = await Promise.all([
        read_workspace_json(args.baseline_path, roots),
        read_workspace_json(args.current_path, roots),
      ]);
      return compare_reports(baseline, current);
    },
  };
  return Object.freeze({
    definitions: MCP_TOOLS,
    async call(name, args) {
      validate_tool_arguments(name, args);
      const handler = handlers[name];
      if (!handler) throw new OrixError('ORIX_MCP_UNKNOWN_TOOL', 'Unknown ORIX tool: ' + name, { recoverable: true });
      return serialize_result(await handler(args));
    },
  });
}
