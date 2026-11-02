// JavaScript, src/cli/main.mjs, Node.js 20+, ORIX command dispatcher and report output.
import { promises as fs, constants as FS_CONSTANTS } from 'node:fs';
import path from 'node:path';
import { parse_arguments } from './arguments.mjs';
import { HELP_TEXT } from './help.mjs';
import { inspect_file } from '../core/inspect.mjs';
import { scan_directory } from '../analyzer/scan.mjs';
import { scan_project, render_project_markdown } from '../project/intelligence.mjs';
import { list_format_capabilities } from '../formats/index.mjs';
import { render_json } from '../reports/json.mjs';
import { render_inspection_markdown, render_scan_markdown } from '../reports/markdown.mjs';
import { render_sarif } from '../reports/sarif.mjs';
import { normalize_error } from '../core/errors.mjs';
import { append_ledger, list_ledger, verify_ledger } from '../evidence/ledger.mjs';
import { compare_reports } from '../analyzer/compare.mjs';
import { render_comparison_markdown } from '../reports/comparison.mjs';
import { OrixError } from '../core/errors.mjs';
import { hash_buffer } from '../core/hash.mjs';
async function write_or_print(content,output_path) {
  if(!output_path){process.stdout.write(content.endsWith('\n')?content:content+'\n');return;}
  const destination=path.resolve(output_path);
  try{await fs.writeFile(destination,content,{encoding:'utf8',flag:'wx',mode:0o600});}
  catch(error){if(error.code==='EEXIST')throw new Error('Refusing to overwrite existing report: '+destination);throw error;}
  process.stdout.write('Report created: '+destination+'\n');
}

async function read_json_report(file_path) {
  const absolute = path.resolve(file_path);
  let before;
  try { before = await fs.lstat(absolute); }
  catch (error) { throw new OrixError('ORIX_COMPARE_FILE_UNAVAILABLE', 'Cannot access comparison report: ' + absolute, { cause: error, details: { system_code: error.code }, recoverable: true }); }
  if (before.isSymbolicLink() || !before.isFile()) throw new OrixError('ORIX_COMPARE_UNSAFE_FILE', 'Comparison input must be a regular non-symlink file', { details: { path: absolute }, recoverable: true });
  if (!Number.isSafeInteger(before.size) || before.size > 64 * 1024 * 1024) throw new OrixError('ORIX_COMPARE_FILE_LIMIT', 'Comparison report exceeds the 64 MiB input limit', { details: { size: before.size }, recoverable: true });
  const handle = await fs.open(absolute, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0));
  let text;
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== before.size) throw new OrixError('ORIX_COMPARE_FILE_CHANGED', 'Comparison report changed between metadata lookup and open', { recoverable: true });
    text = await handle.readFile({ encoding: 'utf8' });
  } finally { await handle.close(); }
  try { return JSON.parse(text); }
  catch (error) { throw new OrixError('ORIX_COMPARE_INVALID_JSON', 'Comparison input is not valid JSON: ' + absolute, { cause: error, details: { path: absolute }, recoverable: true }); }
}

function select_report(report,format,renderer){if(format==='json')return render_json(report);if(format==='sarif')return render_sarif(report);return renderer(report);}
export async function main(argv=process.argv.slice(2)) {
  const parsed=parse_arguments(argv);
  if(parsed.flags.help||parsed.command==='help'||!parsed.command){process.stdout.write(HELP_TEXT);return 0;}
  if(parsed.command==='ledger'){
    const result=parsed.flags.ledger_operation==='verify'
      ? await verify_ledger(parsed.flags.ledger_path)
      : await list_ledger(parsed.flags.ledger_path);
    await write_or_print(render_json(result),parsed.flags.out);
    return 0;
  }
  if(parsed.command==='compare'){
    if(parsed.flags.format==='sarif')throw new Error('SARIF output is not defined for comparison reports');
    const baseline=await read_json_report(parsed.baseline);
    const current=await read_json_report(parsed.target);
    const report=compare_reports(baseline,current);
    await write_or_print(parsed.flags.format==='json'?render_json(report):render_comparison_markdown(report),parsed.flags.out);
    return 0;
  }
  if(parsed.command==='formats'){if(parsed.target)throw new Error('The formats command does not accept a target');await write_or_print(render_json({schema_version:'orix.formats.v1',formats:list_format_capabilities()}),parsed.flags.out);return 0;}
  if(!['inspect','scan','project'].includes(parsed.command))throw new Error('Unknown command: '+parsed.command);
  if(!parsed.target)throw new Error(parsed.command+' requires a target path');
  const options={...parsed.flags,limits:parsed.flags};
  if(parsed.flags.format==='sarif'&&parsed.command==='project')throw new Error('SARIF output currently supports inspect and scan reports, not project reports');
  let report,renderer;
  if(parsed.command==='inspect'){report=await inspect_file(parsed.target,options);renderer=render_inspection_markdown;}
  else if(parsed.command==='scan'){report=await scan_directory(parsed.target,options);renderer=render_scan_markdown;}
  else {
    const project_limits={
      max_files:parsed.flags.max_scan_files,
      max_entries:parsed.flags.max_scan_entries,
      max_depth:parsed.flags.max_scan_depth,
    };
    report=await scan_project(parsed.target,project_limits);
    renderer=render_project_markdown;
  }
  if(parsed.flags.ledger){
    const payload=parsed.command==='inspect'
      ? { path:report.artifact.path, sha256:report.integrity.digest, size_bytes:report.artifact.size_bytes, format:report.detection.format, parser_status:report.parser.status, indicators:report.indicators, evidence:report.evidence }
      : parsed.command==='scan'
        ? { root:report.scan.root, files_analyzed:report.scan.files_analyzed, files_skipped:report.scan.files_skipped, total_bytes_analyzed:report.scan.total_bytes_analyzed, formats:report.scan.formats, indicator_counts:report.scan.indicator_counts, coverage:report.scan.coverage, report_sha256:hash_buffer(Buffer.from(JSON.stringify(report))), artifacts:report.artifacts.slice(0,1000).map(item=>({ path:item.artifact.path, sha256:item.integrity.digest, format:item.detection.format, indicator_rule_ids:(item.indicators??[]).map(finding=>finding.rule_id) })), artifacts_omitted:Math.max(0,report.artifacts.length-1000) }
        : { root:parsed.target, schema_version:report.schema_version, report_sha256:hash_buffer(Buffer.from(JSON.stringify(report))), file_count:report.inventory?.files?.length??report.files?.length??null };
    report.ledger_receipt=await append_ledger(parsed.flags.ledger,{type:parsed.command+'.completed',payload});
  }
  await write_or_print(select_report(report,parsed.flags.format??'markdown',renderer),parsed.flags.out);
  return 0;
}
export async function run_cli(argv=process.argv.slice(2)) {
  try{return await main(argv);}
  catch(error){const normalized=normalize_error(error);process.stderr.write('ORIX '+normalized.code+': '+normalized.message+'\n');if(normalized.details)process.stderr.write(JSON.stringify(normalized.details)+'\n');return 1;}
}
