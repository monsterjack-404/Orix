// JavaScript, src/cli/arguments.mjs, Node.js 20+, strict command-line argument parser.

import { OrixError } from '../core/errors.mjs';
import { DEFAULT_LIMITS } from '../core/limits.mjs';

const VALUE_OPTIONS = new Set(['--format','--out','--ledger','--max-files','--max-directories','--max-entries','--max-depth','--max-read-mib','--max-file-mib','--concurrency','--strings-limit']);
const BOOLEAN_OPTIONS = new Set(['--json','--markdown','--no-strings','--help','-h']);

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
      else result.flags.help = true;
      continue;
    }
    if (VALUE_OPTIONS.has(token)) {
      const raw = tokens.shift();
      if (raw === undefined || raw.startsWith('--')) throw new OrixError('ORIX_CLI_MISSING_VALUE', `${token} requires a value`, { recoverable: true });
      if (token === '--format') {
        if (!['json','markdown','sarif','cyclonedx'].includes(raw)) throw new OrixError('ORIX_CLI_BAD_FORMAT', '--format must be json, markdown, sarif or cyclonedx', { details: { value: raw }, recoverable: true });
        result.flags.format = raw;
      } else if (token === '--out') result.flags.out = raw;
      else if (token === '--ledger') result.flags.ledger = raw;
      else if (token === '--max-files') result.flags.max_scan_files = positive_integer(raw, token, 1, 1_000_000);
      else if (token === '--max-directories') result.flags.max_scan_directories = positive_integer(raw, token, 1, 1_000_000);
      else if (token === '--max-entries') result.flags.max_scan_entries = positive_integer(raw, token, 1, 10_000_000);
      else if (token === '--max-depth') result.flags.max_scan_depth = positive_integer(raw, token, 0, 256);
      else if (token === '--max-read-mib') result.flags.max_read_bytes = positive_integer(raw, token, 1, 512) * 1024 * 1024;
      else if (token === '--max-file-mib') result.flags.max_file_bytes = positive_integer(raw, token, 1, 2_048) * 1024 * 1024;
      else if (token === '--concurrency') result.flags.max_scan_concurrency = positive_integer(raw, token, 1, 32);
      else if (token === '--strings-limit') result.flags.max_strings = positive_integer(raw, token, 0, 100_000);
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
