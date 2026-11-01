// JavaScript, src/cli/main.mjs, Node.js 20+, ORIX command dispatcher and report output.

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { parse_arguments } from './arguments.mjs';
import { HELP_TEXT } from './help.mjs';
import { inspect_file } from '../core/inspect.mjs';
import { scan_directory } from '../analyzer/scan.mjs';
import { list_supported_formats } from '../formats/registry.mjs';
import { render_json } from '../reports/json.mjs';
import { render_inspection_markdown, render_scan_markdown } from '../reports/markdown.mjs';
import { normalize_error } from '../core/errors.mjs';

async function write_or_print(content, output_path) {
  if (!output_path) { process.stdout.write(content.endsWith('\n') ? content : `${content}\n`); return; }
  const destination = path.resolve(output_path);
  try {
    await fs.writeFile(destination, content, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error.code === 'EEXIST') throw new Error(`Refusing to overwrite existing report: ${destination}`);
    throw error;
  }
  process.stdout.write(`Report created: ${destination}\n`);
}

function select_report(report, format, renderer) {
  return format === 'json' ? render_json(report) : renderer(report);
}

export async function main(argv = process.argv.slice(2)) {
  const parsed = parse_arguments(argv);
  if (parsed.flags.help || parsed.command === 'help' || !parsed.command) {
    process.stdout.write(HELP_TEXT);
    return 0;
  }
  if (parsed.command === 'formats') {
    if (parsed.target) throw new Error('The formats command does not accept a target');
    const content = render_json({ schema_version: 'orix.formats.v1', formats: list_supported_formats() });
    await write_or_print(content, parsed.flags.out);
    return 0;
  }
  if (!['inspect','scan'].includes(parsed.command)) throw new Error(`Unknown command: ${parsed.command}`);
  if (!parsed.target) throw new Error(`${parsed.command} requires a target path`);
  const options = { ...parsed.flags, limits: parsed.flags };
  const report = parsed.command === 'inspect'
    ? await inspect_file(parsed.target, options)
    : await scan_directory(parsed.target, options);
  const renderer = parsed.command === 'inspect' ? render_inspection_markdown : render_scan_markdown;
  await write_or_print(select_report(report, parsed.flags.format ?? 'markdown', renderer), parsed.flags.out);
  return 0;
}

export async function run_cli(argv = process.argv.slice(2)) {
  try {
    return await main(argv);
  } catch (error) {
    const normalized = normalize_error(error);
    process.stderr.write(`ORIX ${normalized.code}: ${normalized.message}\n`);
    if (normalized.details) process.stderr.write(`${JSON.stringify(normalized.details)}\n`);
    return 1;
  }
}
