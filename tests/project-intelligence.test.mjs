// JavaScript, tests/project-intelligence.test.mjs, Node.js 20+, project analyzer regression tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,mkdir,rm,symlink,writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { scan_project,render_project_markdown } from '../src/project/intelligence.mjs';
async function with_project(callback){const root=await mkdtemp(path.join(os.tmpdir(),'orix-project-'));try{await callback(root);}finally{await rm(root,{recursive:true,force:true});}}
test('indexes languages, manifests, dependencies, symbols and local imports',async()=>with_project(async root=>{
 await mkdir(path.join(root,'src'),{recursive:true});
 await writeFile(path.join(root,'package.json'),JSON.stringify({name:'fixture-app',version:'1.2.3',dependencies:{'tiny-lib':'^2.0.0'},devDependencies:{'test-runner':'^1.0.0'},scripts:{postinstall:'echo must-not-run'}}));
 await writeFile(path.join(root,'src','index.ts'),"import { run } from './worker';\nexport function main() { return run(); }\n");
 await writeFile(path.join(root,'src','worker.ts'),"export function run() { return 42; }\n");
 await mkdir(path.join(root,'tests'));await writeFile(path.join(root,'tests','sample.test.ts'),'export const testValue = 1;\n');
 const report=await scan_project(root);
 assert.equal(report.schema_version,'orix.project.v1');assert.equal(report.summary.files_analyzed,4);
 assert.equal(report.summary.declared_dependencies,2);assert.ok(report.detection.package_managers.includes('npm-compatible'));
 assert.equal(report.detection.has_tests,true);assert.ok(report.summary.source_symbols>=3);assert.equal(report.graph.edges.length,1);
 assert.equal(report.manifests[0].scripts[0].name,'postinstall');assert.equal(report.coverage.complete,true);
}));
test('credential-shaped content is redacted from findings',async()=>with_project(async root=>{
 await writeFile(path.join(root,'config.js'),"const api_key = 'super-secret-value-123456';\n");
 const report=await scan_project(root);assert.equal(report.findings.length,1);assert.equal(report.findings[0].severity,'high');
 assert.equal(JSON.stringify(report.findings).includes('super-secret-value-123456'),false);assert.equal(report.findings[0].line,1);
}));
test('symbolic links are skipped without traversal',async()=>with_project(async root=>{
 const outside=path.join(root,'outside'),inside=path.join(root,'project');await mkdir(outside);await mkdir(inside);
 await writeFile(path.join(outside,'secret.js'),'export const outsideValue = 1;');await symlink(outside,path.join(inside,'linked'));
 const report=await scan_project(inside);assert.equal(report.files.length,0);
 assert.ok(report.coverage.skipped_entries.some(item=>item.reason==='symbolic-link'));
}));
test('file limit produces incomplete coverage',async()=>with_project(async root=>{
 await writeFile(path.join(root,'a.js'),'export const a = 1;');await writeFile(path.join(root,'b.js'),'export const b = 2;');
 const report=await scan_project(root,{max_files:1});assert.equal(report.summary.files_analyzed,1);
 assert.equal(report.coverage.truncated,true);assert.equal(report.coverage.complete,false);
}));
test('invalid manifest remains a warning and markdown renders',async()=>with_project(async root=>{
 await writeFile(path.join(root,'package.json'),'{ broken json');const report=await scan_project(root);
 assert.equal(report.manifests.length,1);assert.equal(report.manifests[0].warnings.length,1);
 assert.match(render_project_markdown(report),/ORIX Project Intelligence Report/);
}));
