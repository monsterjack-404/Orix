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

test('project CLI emits the versioned JSON report without executing scripts',async()=>with_project(async root=>{
 await writeFile(path.join(root,'package.json'),JSON.stringify({name:'cli-fixture',scripts:{postinstall:'throw new Error("must not execute")'}}));
 const {spawnSync}=await import('node:child_process');
 const result=spawnSync(process.execPath,['src/cli.mjs','project',root,'--json'],{cwd:path.resolve(path.dirname(new URL(import.meta.url).pathname),'..'),encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);
 const report=JSON.parse(result.stdout);
 assert.equal(report.schema_version,'orix.project.v1');
 assert.equal(report.manifests[0].scripts[0].name,'postinstall');
}));


test('project intelligence indexes npm lockfile packages without executing install hooks', async () => with_project(async root => {
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'locked-fixture', dependencies: { alpha: '^1.0.0' }, scripts: { postinstall: 'throw new Error("must not run")' } }));
  await writeFile(path.join(root, 'package-lock.json'), JSON.stringify({
    name: 'locked-fixture',
    lockfileVersion: 3,
    packages: {
      '': { name: 'locked-fixture', dependencies: { alpha: '^1.0.0' } },
      'node_modules/alpha': { version: '1.2.0', dependencies: { beta: '^2.0.0' }, integrity: 'sha512-YQ==' },
      'node_modules/alpha/node_modules/beta': { version: '2.3.0' },
    },
  }));
  const report = await scan_project(root);
  assert.equal(report.lockfiles.length, 1);
  assert.equal(report.summary.locked_packages, 2);
  assert.equal(report.summary.lockfile_edges, 1);
  assert.equal(report.lockfiles[0].root_edges[0].name, 'alpha');
  assert.equal(report.lockfiles[0].edges[0].resolved_version, '2.3.0');
  assert.equal(report.manifests[0].scripts[0].name, 'postinstall');
}));


test('project intelligence inventories Git metadata without traversing .git objects', async () => with_project(async root => {
  const git = path.join(root, '.git');
  await mkdir(path.join(git, 'refs', 'heads'), { recursive: true });
  await writeFile(path.join(git, 'HEAD'), 'ref: refs/heads/main\n');
  await writeFile(path.join(git, 'refs', 'heads', 'main'), 'a'.repeat(40) + '\n');
  await writeFile(path.join(git, 'config'), '[core]\n repositoryformatversion = 0\n[remote "origin"]\n url = git@github.com:monsterjack-404/Orix.git\n');
  await writeFile(path.join(root, 'src.js'), 'export const value = 1;\n');
  const report = await scan_project(root);
  assert.equal(report.git.present, true);
  assert.equal(report.git.branch, 'main');
  assert.equal(report.git.head_oid, 'a'.repeat(40));
  assert.equal(report.git.remotes[0].host, 'github.com');
  assert.equal(report.summary.git_present, true);
  assert.equal(report.files.some(file => file.path.startsWith('.git/')), false);
}));


test('project Markdown includes lockfile graph status and resolved package provenance', async () => with_project(async root => {
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'markdown-fixture', dependencies: { alpha: '^1.0.0' } }));
  await writeFile(path.join(root, 'package-lock.json'), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'markdown-fixture', dependencies: { alpha: '^1.0.0' } },
      'node_modules/alpha': { version: '1.2.0', integrity: 'sha512-YQ==' },
    },
  }));
  const report = await scan_project(root);
  const markdown = render_project_markdown(report);
  assert.match(markdown, /## Lockfile inventory/);
  assert.match(markdown, /npm-package-lock/);
  assert.match(markdown, /## Resolved package sample/);
  assert.match(markdown, /alpha/);
  assert.doesNotMatch(markdown, /\\\n/);
}));


test('project intelligence indexes pnpm lockfile package graph', async () => with_project(async root => {
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'pnpm-fixture', dependencies: { alpha: '^1.0.0' } }));
  await writeFile(path.join(root, 'pnpm-lock.yaml'), [
    "lockfileVersion: '9.0'",
    'importers:',
    '  .:',
    '    dependencies:',
    '      alpha:',
    '        specifier: ^1.0.0',
    '        version: 1.2.0',
    'packages:',
    '  alpha@1.2.0:',
    '    resolution:',
    '      integrity: sha512-alpha',
    '  beta@2.3.0:',
    '    resolution: {integrity: sha512-beta}',
    'snapshots:',
    '  alpha@1.2.0:',
    '    dependencies:',
    '      beta: 2.3.0',
    '  beta@2.3.0: {}',
  ].join('\n'));
  const report = await scan_project(root);
  assert.equal(report.lockfiles.length, 1);
  assert.equal(report.lockfiles[0].format, 'pnpm-lock');
  assert.equal(report.summary.locked_packages, 2);
  assert.equal(report.summary.lockfile_edges, 1);
  assert.equal(report.lockfiles[0].root_edges[0].name, 'alpha');
}));


test('project intelligence integrates Composer lockfile graph with manifest roots', async () => with_project(async root => {
  await writeFile(path.join(root, 'composer.json'), JSON.stringify({ name: 'vendor/root', require: { 'vendor/app': '^1.0' }, 'require-dev': { 'phpunit/phpunit': '^10.0' } }));
  await writeFile(path.join(root, 'composer.lock'), JSON.stringify({
    packages: [{ name: 'vendor/app', version: '1.4.0', require: { 'vendor/lib': '^2.0' } }, { name: 'vendor/lib', version: '2.3.0', require: {} }],
    'packages-dev': [{ name: 'phpunit/phpunit', version: '10.2.0', require: {} }],
  }));
  const report = await scan_project(root);
  assert.equal(report.lockfiles.length, 1);
  assert.equal(report.lockfiles[0].format, 'composer-lock');
  assert.equal(report.summary.locked_packages, 3);
  assert.equal(report.lockfiles[0].root_edges.length, 2);
  assert.equal(report.lockfiles[0].edges.length, 1);
}));


test('project intelligence matches go.sum checksums to go.mod direct dependencies', async () => with_project(async root => {
  await writeFile(path.join(root, 'go.mod'), 'module example.invalid/root\n\nrequire github.com/acme/direct v1.2.3\n');
  await writeFile(path.join(root, 'go.sum'), [
    'github.com/acme/direct v1.2.3 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    'github.com/acme/direct v1.2.3/go.mod h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
    'github.com/acme/transitive v0.9.0 h1:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
  ].join('\n'));
  const report = await scan_project(root);
  assert.equal(report.lockfiles.length, 1);
  assert.equal(report.lockfiles[0].format, 'go-sum');
  assert.equal(report.summary.locked_packages, 2);
  assert.equal(report.lockfiles[0].root_edges.length, 1);
  assert.equal(report.lockfiles[0].root_edges[0].name, 'github.com/acme/direct');
}));


test('project intelligence resolves Poetry lock packages and dependency groups', async () => with_project(async root => {
  await writeFile(path.join(root, 'pyproject.toml'), [
    '[tool.poetry]',
    'name = "poetry-fixture"',
    'version = "1.0.0"',
    '[tool.poetry.dependencies]',
    'python = "^3.11"',
    'requests = "^2.31.0"',
    '[tool.poetry.group.dev.dependencies]',
    'pytest = "^7.0"',
  ].join('\n'));
  await writeFile(path.join(root, 'poetry.lock'), [
    '[[package]]',
    'name = "requests"',
    'version = "2.31.0"',
    'groups = ["main"]',
    '[package.dependencies]',
    'urllib3 = ">=1.21.1,<3"',
    '',
    '[[package]]',
    'name = "urllib3"',
    'version = "2.0.7"',
    'groups = ["main"]',
    '',
    '[[package]]',
    'name = "pytest"',
    'version = "7.4.0"',
    'groups = ["dev"]',
    '',
    '[metadata]',
    'lock-version = "2.0"',
  ].join('\n'));
  const report = await scan_project(root);
  assert.equal(report.lockfiles[0].format, 'poetry-lock');
  assert.equal(report.summary.locked_packages, 3);
  assert.equal(report.lockfiles[0].root_edges.length, 2);
  assert.equal(report.lockfiles[0].edges.length, 1);
  assert.equal(report.dependencies.find(item => item.name === 'pytest').dependency_type, 'dev');
}));

test('project intelligence integrates Pipfile.lock with declared runtime and development packages', async () => with_project(async root => {
  await writeFile(path.join(root, 'Pipfile'), [
    '[packages]',
    'requests = "==2.31.0"',
    '[dev-packages]',
    'pytest = "==7.4.0"',
  ].join('\n'));
  await writeFile(path.join(root, 'Pipfile.lock'), JSON.stringify({
    _meta: { pipfile_spec: 6 },
    default: { requests: { version: '==2.31.0', hashes: [] } },
    develop: { pytest: { version: '==7.4.0', hashes: [] } },
  }));
  const report = await scan_project(root);
  assert.equal(report.lockfiles[0].format, 'pipfile-lock');
  assert.equal(report.summary.locked_packages, 2);
  assert.equal(report.lockfiles[0].root_edges.length, 2);
  assert.equal(report.lockfiles[0].complete, false);
}));


test('project intelligence integrates NuGet and Gradle lock inventories', async () => with_project(async root => {
  await writeFile(path.join(root, 'packages.lock.json'), JSON.stringify({
    version: 1,
    dependencies: {
      'net8.0': {
        'Newtonsoft.Json': { type: 'Direct', requested: '[13.0.3, )', resolved: '13.0.3', contentHash: 'sha512-hash', dependencies: {} },
      },
    },
  }));
  await writeFile(path.join(root, 'gradle.lockfile'), 'com.google.guava:guava:32.1.2-jre=compileClasspath,runtimeClasspath\\n');
  const report = await scan_project(root);
  assert.equal(report.lockfiles.length, 2);
  assert.ok(report.lockfiles.some(item => item.format === 'nuget-packages-lock'));
  assert.ok(report.lockfiles.some(item => item.format === 'gradle-lock'));
  assert.equal(report.summary.locked_packages, 2);
}));
