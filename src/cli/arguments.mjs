// JavaScript, src/cli/arguments.mjs, Node.js 20+, strict command-line argument parser.

import { OrixError } from '../core/errors.mjs';
import { DEFAULT_LIMITS } from '../core/limits.mjs';

const VALUE_OPTIONS = new Set(['--format','--out','--ledger','--max-files','--max-directories','--max-entries','--max-depth','--max-nodes','--max-edges','--max-hotspots','--max-read-mib','--max-file-mib','--concurrency','--strings-limit','--executable','--timeout-ms','--max-output-kib','--max-imports','--max-functions','--address','--max-instructions','--max-packages','--max-advisories','--max-network-mib','--max-har-entries','--max-har-hosts','--max-trace-events','--max-trace-actions','--max-trace-requests']);
const BOOLEAN_OPTIONS = new Set(['--json','--markdown','--no-strings','--osv','--decompile','--help','-h']);

function positive_integer(value, option, minimum, maximum) {
  if (!/^\d+$/.test(value)) throw new OrixError('ORIX_CLI_INVALID_NUMBER', `${option} requires a whole-number value`, { details: { value }, recoverable: true });
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new OrixError('ORIX_CLI_NUMBER_OUT_OF_RANGE', `${option} must be between ${minimum} and ${maximum}`, { details: { value, minimum, maximum }, recoverable: true });
  }
  return parsed;
}

export function parse_arguments(argv) {
  const result = { command: null, target: null, flags: {}, positionals: [] };
  const tokens = [...argv];
  while (tokens.length > 0) {
    const token = tokens.shift();
    if (token === '--') { result.positionals.push(...tokens); break; }
    if (BOOLEAN_OPTIONS.has(token)) {
      if (token === '--json') result.flags.format = 'json';
      else if (token === '--markdown') result.flags.format = 'markdown';
      else if (token === '--no-strings') result.flags.extract_strings = false;
      else if (token === '--osv') result.flags.osv_lookup = true;
      else if (token === '--decompile') result.flags.rizin_decompile = true;
      else result.flags.help = true;
      continue;
    }
    if (token === '--executable-arg') {
      const raw = tokens.shift();
      if (raw === undefined || raw.length === 0) {
        throw new OrixError('ORIX_CLI_MISSING_VALUE', '--executable-arg requires a non-empty value', { recoverable: true });
      }
      result.flags.provider_executable_args ??= [];
      if (result.flags.provider_executable_args.length >= 16) {
        throw new OrixError('ORIX_CLI_ARGUMENT_LIMIT', '--executable-arg may be supplied at most 16 times', { recoverable: true });
      }
      result.flags.provider_executable_args.push(raw);
      continue;
    }
    if (VALUE_OPTIONS.has(token)) {
      const raw = tokens.shift();
      if (raw === undefined || raw.startsWith('--')) throw new OrixError('ORIX_CLI_MISSING_VALUE', `${token} requires a value`, { recoverable: true });
      if (token === '--format') {
        if (!['json','markdown','sarif','cyclonedx','mermaid'].includes(raw)) throw new OrixError('ORIX_CLI_BAD_FORMAT', '--format must be json, markdown, sarif, cyclonedx or mermaid', { details: { value: raw }, recoverable: true });
        result.flags.format = raw;
      } else if (token === '--out') result.flags.out = raw;
      else if (token === '--ledger') result.flags.ledger = raw;
      else if (token === '--max-files') result.flags.max_scan_files = positive_integer(raw, token, 1, 1_000_000);
      else if (token === '--max-directories') result.flags.max_scan_directories = positive_integer(raw, token, 1, 1_000_000);
      else if (token === '--max-entries') result.flags.max_scan_entries = positive_integer(raw, token, 1, 10_000_000);
      else if (token === '--max-depth') result.flags.max_scan_depth = positive_integer(raw, token, 0, 256);
      else if (token === '--max-nodes') result.flags.max_architecture_nodes = positive_integer(raw, token, 1, 50_000);
      else if (token === '--max-edges') result.flags.max_architecture_edges = positive_integer(raw, token, 1, 250_000);
      else if (token === '--max-hotspots') result.flags.max_architecture_hotspots = positive_integer(raw, token, 1, 100);
      else if (token === '--max-read-mib') result.flags.max_read_bytes = positive_integer(raw, token, 1, 512) * 1024 * 1024;
      else if (token === '--max-file-mib') result.flags.max_file_bytes = positive_integer(raw, token, 1, 2_048) * 1024 * 1024;
      else if (token === '--concurrency') result.flags.max_scan_concurrency = positive_integer(raw, token, 1, 32);
      else if (token === '--strings-limit') result.flags.max_strings = positive_integer(raw, token, 0, 100_000);
      else if (token === '--executable') result.flags.provider_executable = raw;
      else if (token === '--timeout-ms') result.flags.timeout_ms = positive_integer(raw, token, 1, 60_000);
      else if (token === '--max-output-kib') result.flags.max_output_bytes = positive_integer(raw, token, 1, 8_192) * 1024;
      else if (token === '--max-imports') result.flags.max_imports = positive_integer(raw, token, 0, 1_000_000);
      else if (token === '--max-functions') result.flags.max_functions = positive_integer(raw, token, 1, 100_000);
      else if (token === '--address') result.flags.rizin_address = raw;
      else if (token === '--max-instructions') result.flags.max_instructions = positive_integer(raw, token, 1, 1000);
      else if (token === '--max-packages') result.flags.max_osv_packages = positive_integer(raw, token, 1, 10_000);
      else if (token === '--max-advisories') result.flags.max_osv_advisories = positive_integer(raw, token, 1, 2_000);
      else if (token === '--max-network-mib') result.flags.max_osv_response_bytes = positive_integer(raw, token, 1, 128) * 1024 * 1024;
      else if (token === '--max-har-entries') result.flags.max_har_entries = positive_integer(raw, token, 1, 100_000);
      else if (token === '--max-har-hosts') result.flags.max_har_hosts = positive_integer(raw, token, 1, 10_000);
      else if (token === '--max-trace-events') result.flags.max_trace_events = positive_integer(raw, token, 1, 50_000);
      else if (token === '--max-trace-actions') result.flags.max_trace_actions = positive_integer(raw, token, 1, 10_000);
      else if (token === '--max-trace-requests') result.flags.max_trace_requests = positive_integer(raw, token, 1, 20_000);
      continue;
    }
    if (token.startsWith('-')) throw new OrixError('ORIX_CLI_UNKNOWN_OPTION', `Unknown option: ${token}`, { recoverable: true });
    result.positionals.push(token);
  }
  result.command = result.positionals.shift() ?? null;
  result.target = result.positionals.shift() ?? null;
  if (result.command === 'compare') {
    result.baseline = result.target;
    result.target = result.positionals.shift() ?? null;
    if (!result.baseline || !result.target) throw new OrixError('ORIX_CLI_COMPARE_ARGUMENTS', 'compare requires baseline and current report paths', { recoverable: true });
    if (result.positionals.length > 0) throw new OrixError('ORIX_CLI_EXTRA_ARGUMENTS', 'compare accepts exactly two report paths', { recoverable: true });
  }
  if (result.command === 'providers') {
    result.provider_id = result.target ?? 'list';
    result.target = null;
    if (result.provider_id === 'list') {
      result.provider_action = 'list';
      if (result.positionals.length > 0) {
        throw new OrixError('ORIX_CLI_PROVIDER_ARGUMENTS', 'providers list accepts no positional arguments', { recoverable: true });
      }
    } else if (result.provider_id === 'rizin') {
      result.provider_action = result.positionals.shift() ?? null;
      if (result.provider_action === 'imports') {
        result.target = result.positionals.shift() ?? null;
        if (!result.target) {
          throw new OrixError('ORIX_CLI_PROVIDER_INPUT', 'providers rizin imports requires an input file path', { recoverable: true });
        }
      } else if (result.provider_action === 'functions') {
        result.target = result.positionals.shift() ?? null;
        if (!result.target) {
          throw new OrixError('ORIX_CLI_PROVIDER_INPUT', 'providers rizin functions requires an input file path', { recoverable: true });
        }
      } else if (result.provider_action === 'doctor') {
        result.target = null;
        if (result.positionals.length > 0) {
          throw new OrixError('ORIX_CLI_PROVIDER_ARGUMENTS', 'providers rizin doctor accepts no positional arguments', { recoverable: true });
        }
      } else {
        throw new OrixError('ORIX_CLI_PROVIDER_ACTION', 'providers rizin requires the doctor, imports or functions action', { recoverable: true });
      }
    } else {
      throw new OrixError('ORIX_CLI_PROVIDER_UNKNOWN', 'Unknown provider: ' + result.provider_id, { recoverable: true });
    }
  }
  if (result.command === 'case') {
    result.flags.case_operation = result.target;
    result.flags.case_args = [...result.positionals];
    result.target = null;
    result.positionals = [];
    if (!['create','list','show','verify','add-artifact','analysis','finding','finding-status','note','relationship','status','export','import'].includes(result.flags.case_operation)) throw new OrixError('ORIX_CLI_CASE_OPERATION', 'case requires create, list, show, verify, add-artifact, analysis, finding, finding-status, note, relationship, status, export or import', { recoverable: true });
  }
  if (result.command === 'ledger') {
    result.flags.ledger_operation = result.target;
    result.flags.ledger_path = result.positionals.shift() ?? null;
    result.target = null;
    if (!['verify', 'list'].includes(result.flags.ledger_operation)) throw new OrixError('ORIX_CLI_LEDGER_OPERATION', 'ledger requires verify or list', { recoverable: true });
    if (!result.flags.ledger_path) throw new OrixError('ORIX_CLI_LEDGER_PATH', 'ledger operation requires a ledger path', { recoverable: true });
  }
  if (result.positionals.length > 0) throw new OrixError('ORIX_CLI_EXTRA_ARGUMENTS', `Unexpected extra arguments: ${result.positionals.join(' ')}`, { recoverable: true });
  const effective_file_limit = result.flags.max_file_bytes ?? DEFAULT_LIMITS.max_file_bytes;
  const effective_read_limit = result.flags.max_read_bytes ?? Math.min(DEFAULT_LIMITS.max_read_bytes, effective_file_limit);
  if (effective_read_limit > effective_file_limit) {
    throw new OrixError('ORIX_CLI_LIMIT_CONFLICT', '--max-read-mib cannot exceed the effective --max-file-mib limit; set both options when increasing the read prefix', { recoverable: true });
  }
  return result;
}
