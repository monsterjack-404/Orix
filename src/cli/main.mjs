// JavaScript, src/cli/main.mjs, Node.js 20+, ORIX command dispatcher and report output.
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { parse_arguments } from './arguments.mjs';
import { HELP_TEXT } from './help.mjs';
import { inspect_file } from '../core/inspect.mjs';
import { scan_directory } from '../analyzer/scan.mjs';
import { scan_project, render_project_markdown } from '../project/intelligence.mjs';
import { analyze_project_architecture } from '../project/architecture.mjs';
import { render_architecture_markdown, render_architecture_mermaid } from '../reports/architecture.mjs';
import { list_format_capabilities } from '../formats/index.mjs';
import { build_capability_report } from '../capabilities/registry.mjs';
import { MCP_PROTOCOL_VERSION, ORIX_MCP_TOOLS } from '../mcp/server.mjs';
import { render_json } from '../reports/json.mjs';
import { render_inspection_markdown, render_scan_markdown } from '../reports/markdown.mjs';
import { render_sarif } from '../reports/sarif.mjs';
import { normalize_error } from '../core/errors.mjs';
import { append_ledger, list_ledger, verify_ledger } from '../evidence/ledger.mjs';
import { compare_reports } from '../analyzer/compare.mjs';
import { render_comparison_markdown } from '../reports/comparison.mjs';
import { read_json_report } from '../core/read-report.mjs';
import { hash_buffer } from '../core/hash.mjs';
import { render_cyclonedx } from '../reports/cyclonedx.mjs';
import { analyze_har_file, render_har_markdown } from '../network/har.mjs';
import { analyze_android_package_file, render_android_package_markdown } from '../android/package.mjs';
import { RIZIN_PROVIDER_MANIFEST, analyze_rizin_imports, analyze_rizin_functions, probe_rizin } from '../providers/rizin.mjs';
import { render_rizin_imports_markdown, render_rizin_functions_markdown } from '../reports/rizin.mjs';
import { audit_project_dependencies, render_vulnerability_audit_markdown } from '../vulnerability/osv.mjs';
async function write_or_print(content,output_path) {
  if(!output_path){process.stdout.write(content.endsWith('\n')?content:content+'\n');return;}
  const destination=path.resolve(output_path);
  try{await fs.writeFile(destination,content,{encoding:'utf8',flag:'wx',mode:0o600});}
  catch(error){if(error.code==='EEXIST')throw new Error('Refusing to overwrite existing report: '+destination);throw error;}
  process.stdout.write('Report created: '+destination+'\n');
}

function select_report(report,format,renderer){if(format==='json')return render_json(report);if(format==='sarif')return render_sarif(report);return renderer(report);}
function validate_command_flags(command, flags) {
  const allowed = {
    inspect: ['format', 'out', 'ledger', 'extract_strings', 'max_strings', 'max_read_bytes', 'max_file_bytes'],
    scan: ['format', 'out', 'ledger', 'extract_strings', 'max_strings', 'max_scan_files', 'max_scan_directories', 'max_scan_entries', 'max_scan_depth', 'max_read_bytes', 'max_file_bytes', 'max_scan_concurrency'],
    project: ['format', 'out', 'ledger', 'max_scan_files', 'max_scan_entries', 'max_scan_depth'],
    architecture: ['format', 'out', 'max_scan_files', 'max_scan_entries', 'max_scan_depth', 'max_architecture_nodes', 'max_architecture_edges', 'max_architecture_hotspots'],
    compare: ['format', 'out'],
    formats: ['format', 'out'],
    capabilities: ['format', 'out'],
    ledger: ['format', 'out', 'ledger_operation', 'ledger_path'],
    providers: ['format', 'out', 'provider_executable', 'timeout_ms', 'max_output_bytes', 'max_imports', 'max_functions', 'rizin_address', 'max_instructions', 'rizin_decompile'],
    audit: ['format', 'out', 'max_scan_files', 'max_scan_entries', 'max_scan_depth', 'osv_lookup', 'max_osv_packages', 'max_osv_advisories', 'max_osv_response_bytes', 'timeout_ms'],
    har: ['format', 'out', 'max_har_entries', 'max_har_hosts'],
    android: ['format', 'out', 'max_file_bytes', 'max_scan_entries'],
  }[command];
  if (!allowed) return;
  const unsupported = Object.keys(flags).filter(key => !allowed.includes(key));
  if (unsupported.length) throw new Error(command + ' does not support option(s): ' + unsupported.join(', '));
}
export async function main(argv=process.argv.slice(2), dependencies = {}) {
  const parsed=parse_arguments(argv);
  if(parsed.flags.help||parsed.command==='help'||!parsed.command){process.stdout.write(HELP_TEXT);return 0;}
  validate_command_flags(parsed.command, parsed.flags);
  if(parsed.flags.format==='mermaid'&&parsed.command!=='architecture')throw new Error('Mermaid output is only supported by the architecture command');
  if(parsed.command==='ledger'&&parsed.flags.format&&parsed.flags.format!=='json')throw new Error('ledger output currently supports JSON only');
  if(parsed.command==='providers'&&parsed.provider_action==='list'&&parsed.flags.format&&parsed.flags.format!=='json')throw new Error('providers list output currently supports JSON only');
  if(parsed.command==='providers'&&parsed.provider_action==='imports'&&parsed.flags.format&&!['json','markdown'].includes(parsed.flags.format))throw new Error('provider import output supports JSON or Markdown only');
  if(parsed.command==='providers'&&parsed.provider_action==='functions'&&parsed.flags.format&&!['json','markdown'].includes(parsed.flags.format))throw new Error('provider function output supports JSON or Markdown only');
  if(parsed.command==='providers'&&parsed.provider_action==='doctor'&&parsed.flags.format&&parsed.flags.format!=='json')throw new Error('provider doctor output currently supports JSON only');
  if(parsed.command==='compare'&&parsed.flags.format&&!['json','markdown'].includes(parsed.flags.format))throw new Error('compare output supports JSON or Markdown only');
  if(parsed.command==='formats'&&parsed.flags.format&&parsed.flags.format!=='json')throw new Error('formats output currently supports JSON only');
  if(parsed.command==='capabilities'&&parsed.flags.format&&parsed.flags.format!=='json')throw new Error('capabilities output currently supports JSON only');
  if(parsed.command==='providers'){
    if(parsed.provider_action==='list'){
      const report={
        schema_version:'orix.providers.v1',
        providers:[{
          id:RIZIN_PROVIDER_MANIFEST.id,
          name:RIZIN_PROVIDER_MANIFEST.name,
          version:RIZIN_PROVIDER_MANIFEST.version,
          capabilities:RIZIN_PROVIDER_MANIFEST.capabilities,
          supported_platforms:RIZIN_PROVIDER_MANIFEST.supported_platforms,
          input_formats:RIZIN_PROVIDER_MANIFEST.input_formats,
          execution:RIZIN_PROVIDER_MANIFEST.execution,
          license:RIZIN_PROVIDER_MANIFEST.license,
          availability:'external-install-not-probed',
        }],
      };
      await write_or_print(render_json(report),parsed.flags.out);
      return 0;
    }
    if(parsed.provider_action==='doctor'){
      if(!parsed.flags.provider_executable){
        throw new Error('providers rizin doctor requires --executable <absolute-path>');
      }
      const report=await probe_rizin({
        executable:parsed.flags.provider_executable,
        timeout_ms:parsed.flags.timeout_ms,
        max_output_bytes:parsed.flags.max_output_bytes,
      });
      await write_or_print(render_json(report),parsed.flags.out);
      return 0;
    }
    if(parsed.provider_action==='functions'){
      if(!parsed.flags.provider_executable){
        throw new Error('providers rizin functions requires --executable <absolute-path>');
      }
      const report=await analyze_rizin_functions({
        executable:parsed.flags.provider_executable,
        input_path:parsed.target,
        timeout_ms:parsed.flags.timeout_ms,
        max_output_bytes:parsed.flags.max_output_bytes,
        max_functions:parsed.flags.max_functions,
        address:parsed.flags.rizin_address,
        max_instructions:parsed.flags.max_instructions,
        decompile:parsed.flags.rizin_decompile,
      });
      const output=parsed.flags.format==='json'
        ? render_json(report)
        : render_rizin_functions_markdown(report);
      await write_or_print(output,parsed.flags.out);
      return 0;
    }
    if(parsed.provider_action==='imports'){
      if(!parsed.flags.provider_executable){
        throw new Error('providers rizin imports requires --executable <absolute-path>');
      }
      const report=await analyze_rizin_imports({
        executable:parsed.flags.provider_executable,
        input_path:parsed.target,
        timeout_ms:parsed.flags.timeout_ms,
        max_output_bytes:parsed.flags.max_output_bytes,
        max_imports:parsed.flags.max_imports,
      });
      const output=parsed.flags.format==='json'
        ? render_json(report)
        : render_rizin_imports_markdown(report);
      await write_or_print(output,parsed.flags.out);
      return 0;
    }
  }
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
  if(parsed.command==='capabilities'){
    if(parsed.target)throw new Error('The capabilities command does not accept a target');
    const report=build_capability_report({mcp_protocol_version:MCP_PROTOCOL_VERSION,mcp_tools:ORIX_MCP_TOOLS});
    await write_or_print(render_json(report),parsed.flags.out);
    return 0;
  }
  if(parsed.command==='audit'){
    if(!parsed.target)throw new Error('audit requires a project directory');
    if(!parsed.flags.osv_lookup)throw new Error('Dependency audit is network-enabled and opt-in; pass --osv to query OSV.dev. No network request was made.');
    if(parsed.flags.format&&!['json','markdown'].includes(parsed.flags.format))throw new Error('audit output supports JSON or Markdown only');
    const project=await scan_project(parsed.target,{
      max_files:parsed.flags.max_scan_files,
      max_entries:parsed.flags.max_scan_entries,
      max_depth:parsed.flags.max_scan_depth,
    });
    const report=await audit_project_dependencies(project,{
      fetch_impl:dependencies.fetch_impl,
      timeout_ms:parsed.flags.timeout_ms,
      max_packages:parsed.flags.max_osv_packages,
      max_advisories:parsed.flags.max_osv_advisories,
      max_total_response_bytes:parsed.flags.max_osv_response_bytes,
    });
    const output=parsed.flags.format==='json'
      ? render_json(report)
      : render_vulnerability_audit_markdown(report);
    await write_or_print(output,parsed.flags.out);
    return 0;
  }
  if(parsed.command==='har'){
    if(!parsed.target)throw new Error('har requires a .har capture file');
    if(parsed.flags.format&&!['json','markdown'].includes(parsed.flags.format))throw new Error('har output supports JSON or Markdown only');
    const report=await analyze_har_file(parsed.target,{max_entries:parsed.flags.max_har_entries,max_hosts:parsed.flags.max_har_hosts});
    const output=parsed.flags.format==='json'?render_json(report):render_har_markdown(report);
    await write_or_print(output,parsed.flags.out);
    return 0;
  }
  if(parsed.command==='android'){
    if(!parsed.target)throw new Error('android requires an APK or AAB file path');
    if(parsed.flags.format&&!['json','markdown'].includes(parsed.flags.format))throw new Error('android output supports JSON or Markdown only');
    if(parsed.flags.max_file_bytes!==undefined&&parsed.flags.max_file_bytes>1_073_741_824)throw new Error('android --max-file-mib cannot exceed 1024 MiB');
    if(parsed.flags.max_scan_entries!==undefined&&parsed.flags.max_scan_entries>1_000_000)throw new Error('android --max-entries cannot exceed 1000000');
    const report=await analyze_android_package_file(parsed.target,{
      max_file_bytes:parsed.flags.max_file_bytes,
      zip:{max_entries:parsed.flags.max_scan_entries},
    });
    const output=parsed.flags.format==='json'?render_json(report):render_android_package_markdown(report);
    await write_or_print(output,parsed.flags.out);
    return 0;
  }
  if(parsed.command==='architecture'){
    if(!parsed.target)throw new Error('architecture requires a target directory');
    if(parsed.flags.format&&!['json','markdown','mermaid'].includes(parsed.flags.format))throw new Error('architecture output supports JSON, Markdown or Mermaid');
    const project=await scan_project(parsed.target,{max_files:parsed.flags.max_scan_files,max_entries:parsed.flags.max_scan_entries,max_depth:parsed.flags.max_scan_depth});
    const report=analyze_project_architecture(project, {
      max_nodes: parsed.flags.max_architecture_nodes,
      max_edges: parsed.flags.max_architecture_edges,
      max_hotspots: parsed.flags.max_architecture_hotspots,
    });
    const format=parsed.flags.format??'markdown';
    const output=format==='json'?render_json(report):format==='mermaid'?render_architecture_mermaid(report):render_architecture_markdown(report);
    await write_or_print(output,parsed.flags.out);
    return 0;
  }
  if(!['inspect','scan','project'].includes(parsed.command))throw new Error('Unknown command: '+parsed.command);
  if(!parsed.target)throw new Error(parsed.command+' requires a target path');
  const options={...parsed.flags,limits:parsed.flags};
  if(parsed.flags.format==='cyclonedx'&&parsed.command!=='project')throw new Error('CycloneDX output requires the project command');
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
    renderer=parsed.flags.format==='cyclonedx'?render_cyclonedx:render_project_markdown;
  }
  if(parsed.flags.ledger){
    const payload=parsed.command==='inspect'
      ? { path:report.artifact.path, sha256:report.integrity.digest, size_bytes:report.artifact.size_bytes, format:report.detection.format, parser_status:report.parser.status, indicators:report.indicators, evidence:report.evidence }
      : parsed.command==='scan'
        ? { root:report.scan.root, files_analyzed:report.scan.files_analyzed, files_skipped:report.scan.files_skipped, total_bytes_analyzed:report.scan.total_bytes_analyzed, formats:report.scan.formats, indicator_counts:report.scan.indicator_counts, coverage:report.scan.coverage, report_sha256:hash_buffer(Buffer.from(JSON.stringify(report))), artifacts:report.artifacts.slice(0,128).map(item=>({ path:item.artifact.path, sha256:item.integrity.digest, format:item.detection.format, indicator_rule_ids:(item.indicators??[]).slice(0,10).map(finding=>finding.rule_id), indicators_omitted:Math.max(0,(item.indicators??[]).length-10) })), artifacts_omitted:Math.max(0,report.artifacts.length-128) }
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
