// JavaScript, src/mcp/server.mjs, Node.js 20+, bounded static-analysis Model Context Protocol stdio server.

import path from 'node:path';
import { inspect_file } from '../core/inspect.mjs';
import { analyze_har_file } from '../network/har.mjs';
import { scan_directory } from '../analyzer/scan.mjs';
import { scan_project } from '../project/intelligence.mjs';
import { analyze_project_architecture } from '../project/architecture.mjs';
import { list_format_capabilities } from '../formats/index.mjs';
import { build_capability_report } from '../capabilities/registry.mjs';
import { verify_ledger, list_ledger, append_ledger } from '../evidence/ledger.mjs';
import { create_case, list_cases, get_case, verify_case, add_case_artifact, record_case_analysis, add_case_finding, change_case_finding_status, add_case_note, add_case_relationship, change_case_status, export_case_bundle, import_case_bundle } from '../cases/store.mjs';
import { compare_reports } from '../analyzer/compare.mjs';
import { analyze_rizin_imports, analyze_rizin_functions } from '../providers/rizin.mjs';
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
export const MCP_TOOL_CALLS_PER_MINUTE = 60;
export const MCP_TOOL_RATE_LIMIT_WINDOW_MS = 60 * 1000;

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
    name: 'orix.rizin_imports',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Use an explicitly selected Rizin executable to extract a bounded static import inventory. Optional Linux Bubblewrap namespace/filesystem isolation can be requested explicitly with a workspace-contained sandbox root; isolation is disabled by default. The target is never executed.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', minLength: 1 },
        executable: { type: 'string', minLength: 1, maxLength: 4096 },
        executable_args: { type: 'array', maxItems: 16, items: { type: 'string', maxLength: 32768 }, description: 'Optional literal argv prefix passed to the selected executable without shell evaluation.' },
        max_imports: integer('Maximum imported symbols retained.', 100000, 1),
        timeout_ms: integer('Total provider workflow deadline in milliseconds.', 60000, 1),
        max_output_kib: integer('Aggregate stdout/stderr capture budget in KiB.', 8192, 1),
        isolation: { type: 'string', enum: ['none', 'required'], description: 'Explicitly opt into Linux Bubblewrap isolation; defaults to none.' },
        sandbox_root: { type: 'string', minLength: 1, maxLength: 4096, description: 'Existing directory inside a configured MCP workspace root used as the Bubblewrap root filesystem.' },
        cwd: { type: 'string', minLength: 1, maxLength: 4096, description: 'Optional provider working directory inside a configured MCP workspace; defaults to sandbox_root when required isolation is selected.' },
        cwd: { type: 'string', minLength: 1, maxLength: 4096, description: 'Optional provider working directory inside a configured MCP workspace; defaults to sandbox_root when required isolation is selected.' },
      },
      required: ['path', 'executable'],
      additionalProperties: false,
    },
  },
  {
    name: 'orix.rizin_functions',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Use an explicitly selected Rizin executable to enumerate functions, disassemble a bounded instruction window and optionally request rz-ghidra pseudocode. Optional Linux Bubblewrap isolation can be requested explicitly with a workspace-contained sandbox root; isolation is disabled by default. The target is never executed; Rizin and its optional decompiler plugin must be installed separately.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', minLength: 1 },
        executable: { type: 'string', minLength: 1, maxLength: 4096 },
        executable_args: { type: 'array', maxItems: 16, items: { type: 'string', maxLength: 32768 }, description: 'Optional literal argv prefix passed to the selected executable without shell evaluation.' },
        max_functions: integer('Maximum Rizin functions retained.', 100000, 1),
        address: { type: 'string', minLength: 1, maxLength: 18, pattern: '^(?:0x[0-9a-fA-F]{1,14}|[0-9]{1,16})$' },
        max_instructions: integer('Maximum instructions in the optional disassembly window.', 1000, 1),
        decompile: { type: 'boolean', description: 'Request optional rz-ghidra pseudocode decompilation at the supplied function entry address.' },
        timeout_ms: integer('Total provider workflow deadline in milliseconds.', 60000, 1),
        max_output_kib: integer('Aggregate stdout/stderr capture budget in KiB.', 8192, 1),
        isolation: { type: 'string', enum: ['none', 'required'], description: 'Explicitly opt into Linux Bubblewrap isolation; defaults to none.' },
        sandbox_root: { type: 'string', minLength: 1, maxLength: 4096, description: 'Existing directory inside a configured MCP workspace root used as the Bubblewrap root filesystem.' },
      },
      required: ['path', 'executable'],
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
    name: 'orix.analyze_har',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Analyze a workspace-confined HAR 1.2 capture offline. Returns bounded request metadata, host/status/timing summaries and review findings; does not export request/response bodies or secret header/query values.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', minLength: 1 },
        max_entries: integer('Maximum HAR transactions analyzed.', 100000, 1),
        max_hosts: integer('Maximum distinct hosts returned.', 10000, 1),
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
    name: 'orix.capabilities',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'Return the source-backed ORIX capability inventory, including implemented, partial and planned boundaries.',
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
  {
    name: 'orix.case.create',
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    description: 'Create a persistent local investigation case with an append-only hash-chained event history. Source artifact bytes are not copied.',
    inputSchema: { type: 'object', properties: { workspace: { type: 'string', minLength: 1 }, title: { type: 'string', minLength: 1, maxLength: 200 }, description: { type: 'string', maxLength: 4000 } }, required: ['workspace','title'], additionalProperties: false },
  },
  {
    name: 'orix.case.get',
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    description: 'List, retrieve or verify local cases. Case reads reconstruct and validate the append-only event chain.',
    inputSchema: { type: 'object', properties: { workspace: { type: 'string', minLength: 1 }, action: { type: 'string', enum: ['list','show','verify'] }, case_id: { type: 'string', minLength: 36, maxLength: 36 }, max_cases: integer('Maximum cases listed.', 1000, 1) }, required: ['workspace','action'], additionalProperties: false },
  },
  {
    name: 'orix.case.mutate',
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    description: 'Append a bounded case mutation: register artifact, record analysis, add finding/note/relationship, or change case/finding lifecycle state.',
    inputSchema: { type: 'object', properties: { workspace: { type: 'string', minLength: 1 }, case_id: { type: 'string', minLength: 36, maxLength: 36 }, action: { type: 'string', enum: ['add_artifact','record_analysis','add_finding','add_note','relationship','finding_status','status'] }, path: { type: 'string', minLength: 1 }, report_path: { type: 'string', minLength: 1 }, tool: { type: 'string', maxLength: 100 }, tool_version: { type: 'string', maxLength: 100 }, rule_id: { type: 'string', maxLength: 160 }, title: { type: 'string', maxLength: 300 }, summary: { type: 'string', maxLength: 2000 }, severity: { type: 'string', enum: ['critical','high','medium','low','info','unknown'] }, confidence: { type: 'string', enum: ['observed','derived','heuristic','unknown'] }, artifact_id: { type: 'string', maxLength: 100 }, run_id: { type: 'string', minLength: 36, maxLength: 36 }, text: { type: 'string', maxLength: 5000 }, finding_id: { type: 'string', minLength: 36, maxLength: 36 }, status: { type: 'string', enum: ['open','in_review','closed','triaged','confirmed','false_positive','accepted_risk','resolved'] }, reason: { type: 'string', maxLength: 1000 }, from_type: { type: 'string', maxLength: 20 }, from_id: { type: 'string', maxLength: 200 }, to_type: { type: 'string', maxLength: 20 }, to_id: { type: 'string', maxLength: 200 }, relation: { type: 'string', maxLength: 80 } }, required: ['workspace','case_id','action'], additionalProperties: false },
  },
  {
    name: 'orix.case.exchange',
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    description: 'Export or import a portable case directory after validating member digests and the event chain. Bundles are unsigned and do not embed source samples.',
    inputSchema: { type: 'object', properties: { workspace: { type: 'string', minLength: 1 }, case_id: { type: 'string', minLength: 36, maxLength: 36 }, action: { type: 'string', enum: ['export','import'] }, path: { type: 'string', minLength: 1 } }, required: ['workspace','action','path'], additionalProperties: false },
  },
]);

function is_request_id(value) {
  return typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value));
}

function is_json_object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function consume_tool_call_budget(rate_limit) {
  if (!rate_limit) return true;
  const now = Date.now();
  if (now - rate_limit.window_started_at >= rate_limit.window_ms) {
    rate_limit.window_started_at = now;
    rate_limit.calls = 0;
  }
  if (rate_limit.calls >= rate_limit.max_calls) return false;
  rate_limit.calls += 1;
  return true;
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
    if (schema.enum && !schema.enum.includes(item)) {
      throw new TypeError(key + ' must be one of: ' + schema.enum.join(', '));
    }
    if (schema.type === 'string') {
      if (typeof item !== 'string' || item.length < (schema.minLength ?? 0) || item.length > (schema.maxLength ?? Infinity)) {
        throw new TypeError(key + ' must be a string within its declared length bounds');
      }
      if (schema.pattern && !new RegExp(schema.pattern).test(item)) throw new TypeError(key + ' does not match its required pattern');
    }
    if (schema.type === 'array') {
      if (!Array.isArray(item) || item.length > (schema.maxItems ?? Infinity)) {
        throw new TypeError(key + ' must be an array within its declared item limit');
      }
      if (schema.items?.type === 'string') {
        for (const entry of item) {
          if (typeof entry !== 'string' ||
              entry.length < (schema.items.minLength ?? 0) ||
              entry.length > (schema.items.maxLength ?? Infinity)) {
            throw new TypeError(key + ' entries must be strings within their declared length bounds');
          }
        }
      }
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
    case 'orix.case.create': {
      const workspace = await resolve_workspace_path(args.workspace, roots, { kind: 'directory' });
      return create_case(workspace.path, { title: args.title, description: args.description ?? '' });
    }
    case 'orix.case.get': {
      const workspace = await resolve_workspace_path(args.workspace, roots, { kind: 'directory' });
      if (!['list', 'show', 'verify'].includes(args.action)) throw new TypeError('Case get action must be list, show or verify');
      if (args.action === 'list') return list_cases(workspace.path, { max_cases: args.max_cases });
      if (!args.case_id) throw new TypeError('Case show and verify require case_id');
      if (args.action === 'show') return get_case(workspace.path, args.case_id);
      return verify_case(workspace.path, args.case_id);
    }
    case 'orix.case.mutate': {
      if (!['add_artifact','record_analysis','add_finding','add_note','relationship','finding_status','status'].includes(args.action)) throw new TypeError('Unsupported case mutation action');
      const workspace = await resolve_workspace_path(args.workspace, roots, { kind: 'directory' });
      if (args.action === 'add_artifact') {
        const target = await resolve_workspace_path(args.path, roots, { kind: 'file' });
        return add_case_artifact(workspace.path, args.case_id, target.path);
      }
      if (args.action === 'record_analysis') {
        const target = await resolve_workspace_path(args.report_path, roots, { kind: 'file' });
        const report = await read_workspace_json(target.path, roots, { max_bytes: 2 * 1024 * 1024 });
        return record_case_analysis(workspace.path, args.case_id, { report, tool: args.tool ?? 'orix', tool_version: args.tool_version ?? null });
      }
      if (args.action === 'add_finding') return add_case_finding(workspace.path, args.case_id, args);
      if (args.action === 'add_note') return add_case_note(workspace.path, args.case_id, args.text);
      if (args.action === 'finding_status') return change_case_finding_status(workspace.path, args.case_id, args.finding_id, args.status, args.reason ?? '');
      if (args.action === 'status') return change_case_status(workspace.path, args.case_id, args.status, args.reason ?? '');
      return add_case_relationship(workspace.path, args.case_id, args);
    }
    case 'orix.case.exchange': {
      if (!['export','import'].includes(args.action)) throw new TypeError('Case exchange action must be export or import');
      if (args.action === 'export' && !args.case_id) throw new TypeError('Case export requires case_id');
      const workspace = await resolve_workspace_path(args.workspace, roots, { kind: 'directory' });
      if (args.action === 'export') {
        const parent = await resolve_workspace_path(path.dirname(path.resolve(args.path)), roots, { kind: 'directory' });
        return export_case_bundle(workspace.path, args.case_id, path.join(parent.path, path.basename(args.path)));
      }
      const bundle = await resolve_workspace_path(args.path, roots, { kind: 'directory' });
      return import_case_bundle(workspace.path, bundle.path);
    }
    case 'orix.inspect_file': {
      const limits = {};
      if (args.max_read_mib !== undefined) limits.max_read_bytes = args.max_read_mib * 1024 * 1024;
      if (args.max_file_mib !== undefined) limits.max_file_bytes = args.max_file_mib * 1024 * 1024;
      if (args.max_strings !== undefined) limits.max_strings = args.max_strings;
      const target = await resolve_workspace_path(args.path, roots, { kind: 'file' });
      return inspect_file(target.path, { limits, extract_strings: args.extract_strings });
    }
    case 'orix.rizin_imports': {
      if (args.isolation === 'required' && args.sandbox_root === undefined) {
        throw new TypeError('sandbox_root is required when isolation is required');
      }
      const target = await resolve_workspace_path(args.path, roots, { kind: 'file' });
      const sandbox_root = args.sandbox_root === undefined
        ? undefined
        : (await resolve_workspace_path(args.sandbox_root, roots, { kind: 'directory' })).path;
      const cwd = args.cwd === undefined
        ? (args.isolation === 'required' ? sandbox_root : undefined)
        : (await resolve_workspace_path(args.cwd, roots, { kind: 'directory' })).path;
      return analyze_rizin_imports({
        input_path: target.path,
        executable: args.executable,
        executable_args: args.executable_args,
        max_imports: args.max_imports ?? 10_000,
        timeout_ms: args.timeout_ms ?? 30_000,
        max_output_bytes: (args.max_output_kib ?? 2_048) * 1024,
        isolation: args.isolation,
        sandbox_root,
        cwd,
      });
    }
    case 'orix.rizin_functions': {
      if (args.isolation === 'required' && args.sandbox_root === undefined) {
        throw new TypeError('sandbox_root is required when isolation is required');
      }
      const target = await resolve_workspace_path(args.path, roots, { kind: 'file' });
      const sandbox_root = args.sandbox_root === undefined
        ? undefined
        : (await resolve_workspace_path(args.sandbox_root, roots, { kind: 'directory' })).path;
      const cwd = args.cwd === undefined
        ? (args.isolation === 'required' ? sandbox_root : undefined)
        : (await resolve_workspace_path(args.cwd, roots, { kind: 'directory' })).path;
      return analyze_rizin_functions({
        input_path: target.path,
        executable: args.executable,
        executable_args: args.executable_args,
        max_functions: args.max_functions ?? 1000,
        address: args.address,
        max_instructions: args.max_instructions ?? 100,
        decompile: args.decompile ?? false,
        timeout_ms: args.timeout_ms ?? 30_000,
        max_output_bytes: (args.max_output_kib ?? 2_048) * 1024,
        isolation: args.isolation,
        sandbox_root,
        cwd,
      });
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
    case 'orix.analyze_har': {
      const target = await resolve_workspace_path(args.path, roots, { kind: 'file' });
      return analyze_har_file(target.path, { max_entries: args.max_entries, max_hosts: args.max_hosts });
    }
    case 'orix.formats':
      return { schema_version: 'orix.formats.v1', formats: list_format_capabilities() };
    case 'orix.capabilities':
      return build_capability_report({
        mcp_protocol_version: MCP_PROTOCOL_VERSION,
        mcp_tools: ORIX_MCP_TOOLS,
      });
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
  const session = options.session;
  if (!session) return handle_mcp_message_impl(message, options);

  // Pings are available during setup. Other requests require the full
  // initialize -> notifications/initialized handshake on this connection.
  if (Array.isArray(message)) return handle_mcp_message_impl(message, options);
  if (!is_json_object(message) || message.jsonrpc !== '2.0') {
    return handle_mcp_message_impl(message, options);
  }
  const has_id = Object.hasOwn(message, 'id');
  if (has_id && !is_request_id(message.id)) return handle_mcp_message_impl(message, options);
  if (typeof message.method !== 'string' || message.method.length === 0) {
    return handle_mcp_message_impl(message, options);
  }
  if (message.method === 'ping') return handle_mcp_message_impl(message, options);

  if (message.method === 'initialize') {
    if (!has_id) return null;
    if (session.phase !== 'new') {
      return jsonrpc_error(message.id, -32600, 'initialize may be called only once per MCP connection');
    }
    const response = await handle_mcp_message_impl(message, options);
    if (response && !response.error) session.phase = 'awaiting_initialized';
    return response;
  }

  if (message.method === 'notifications/initialized' && !has_id) {
    if (session.phase === 'awaiting_initialized') session.phase = 'initialized';
    return null;
  }

  if (!has_id) return null;
  if (session.phase !== 'initialized') {
    return jsonrpc_error(message.id, -32002, 'Server not initialized; complete initialize and notifications/initialized first');
  }
  return handle_mcp_message_impl(message, options);
}

async function handle_mcp_message_impl(message, options = {}) {
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
    if (!consume_tool_call_budget(options.rate_limit)) {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{
            type: 'text',
            text: JSON.stringify({
              code: 'ORIX_MCP_RATE_LIMITED',
              message: 'Tool-call rate limit exceeded. Retry after the current 60-second window resets.',
            }),
          }],
          isError: true,
        },
      };
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
  max_tool_calls_per_minute = MCP_TOOL_CALLS_PER_MINUTE,
} = {}) {
  if (!Number.isSafeInteger(max_tool_calls_per_minute) || max_tool_calls_per_minute < 1 || max_tool_calls_per_minute > 10000) {
    throw new RangeError('max_tool_calls_per_minute must be an integer between 1 and 10000');
  }
  const options = {
    roots,
    environment,
    session: { phase: 'new' },
    rate_limit: {
      window_started_at: Date.now(),
      window_ms: MCP_TOOL_RATE_LIMIT_WINDOW_MS,
      max_calls: max_tool_calls_per_minute,
      calls: 0,
    },
  };
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
