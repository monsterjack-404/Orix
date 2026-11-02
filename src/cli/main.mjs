// JavaScript, src/cli/main.mjs, Node.js 20+, ORIX command dispatcher and report output.
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { parse_arguments } from './arguments.mjs';
import { HELP_TEXT } from './help.mjs';
import { inspect_file } from '../core/inspect.mjs';
import { scan_directory } from '../analyzer/scan.mjs';
import { scan_project, render_project_markdown } from '../project/intelligence.mjs';
import { list_format_capabilities } from '../formats/index.mjs';
import { render_json } from '../reports/json.mjs';
import { render_inspection_markdown, render_scan_markdown } from '../reports/markdown.mjs';\nimport { render_sarif } from '../reports/sarif.mjs';
import { normalize_error } from '../core/errors.mjs';
async function write_or_print(content,output_path) {
  if(!output_path){process.stdout.write(content.endsWith('\n')?content:content+'\n');return;}
  const destination=path.resolve(output_path);
  try{await fs.writeFile(destination,content,{encoding:'utf8',flag:'wx',mode:0o600});}
  catch(error){if(error.code==='EEXIST')throw new Error('Refusing to overwrite existing report: '+destination);throw error;}
  process.stdout.write('Report created: '+destination+'\n');
}
function select_report(report,format,renderer){if(format==='json')return render_json(report);if(format==='sarif')return render_sarif(report);return renderer(report);}
export async function main(argv=process.argv.slice(2)) {
  const parsed=parse_arguments(argv);
  if(parsed.flags.help||parsed.command==='help'||!parsed.command){process.stdout.write(HELP_TEXT);return 0;}
  if(parsed.command==='formats'){if(parsed.target)throw new Error('The formats command does not accept a target');await write_or_print(render_json({schema_version:'orix.formats.v1',formats:list_format_capabilities()}),parsed.flags.out);return 0;}
  if(!['inspect','scan','project'].includes(parsed.command))throw new Error('Unknown command: '+parsed.command);
  if(!parsed.target)throw new Error(parsed.command+' requires a target path');
  const options={...parsed.flags,limits:parsed.flags};\n  if(parsed.flags.format==='sarif'&&parsed.command==='project')throw new Error('SARIF output currently supports inspect and scan reports, not project reports');
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
  await write_or_print(select_report(report,parsed.flags.format??'markdown',renderer),parsed.flags.out);
  return 0;
}
export async function run_cli(argv=process.argv.slice(2)) {
  try{return await main(argv);}
  catch(error){const normalized=normalize_error(error);process.stderr.write('ORIX '+normalized.code+': '+normalized.message+'\n');if(normalized.details)process.stderr.write(JSON.stringify(normalized.details)+'\n');return 1;}
}
